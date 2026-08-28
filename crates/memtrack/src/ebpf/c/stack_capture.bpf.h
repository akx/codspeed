#ifndef __STACK_CAPTURE_BPF_H__
#define __STACK_CAPTURE_BPF_H__

#include "event.h"
#include "utils/map_helpers.h"
#include "utils/process_tracking.h"

/* Raw user-stack bytes and registers are emitted once per hash for offline
 * DWARF unwinding. Allocation events carry the hash; bpf_get_stackid() supplies
 * the frame-pointer fallback.
 *
 * Stack data changes may give one call path multiple hashes.
 */

const volatile __u8 capture_stacks_enabled = 0;

#define STACK_TRACE_MAX_DEPTH 127
/* Captured lengths are rounded down to this granularity. */
#define STACK_COPY_CHUNK 512
#define FNV64_OFFSET 0xcbf29ce484222325ULL
#define FNV64_PRIME 0x00000100000001b3ULL

/* Frame-pointer fallback keyed by bpf_get_stackid(). */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __uint(value_size, STACK_TRACE_MAX_DEPTH * sizeof(__u64));
} stack_traces SEC(".maps");

/* A separate ring keeps allocation events fixed-size. */
BPF_RINGBUF(stacks, 64 * 1024 * 1024);
BPF_HASH_MAP(seen_stack_hashes, __u64, __u8, 65536);
BPF_HASH_MAP(pending_stack_hash, __u64, __u64, 10000);
BPF_ARRAY_MAP(stack_counters, __u64, MEMTRACK_STACK_COUNTER_COUNT);

/* The union permits word-wise hashing before emitting a variable-length record. */
struct stack_scratch_buf {
    struct stack_header header;
    union {
        __u8 bytes[MEMTRACK_MAX_STACK_COPY];
        __u64 words[MEMTRACK_MAX_STACK_COPY / 8];
    };
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stack_scratch_buf);
} stack_scratch SEC(".maps");

/* Older clang BPF backends cannot lower a 32-bit atomic compare-and-swap. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} stack_busy SEC(".maps");

static __always_inline void bump_stack_counter(__u32 index) {
    __u64* slot = bpf_map_lookup_elem(&stack_counters, &index);
    if (slot) {
        __sync_fetch_and_add(slot, 1);
    }
}

/* FNV-1a over one STACK_COPY_CHUNK worth of 8-byte words. Fixed-size, unrolled
 * so the verifier sees a bounded loop. */
static __always_inline __u64 fnv64_hash_chunk(__u64 hash, const __u64* words) {
#pragma unroll
    for (__u32 word = 0; word < STACK_COPY_CHUNK / 8; word++) {
        hash = (hash ^ words[word]) * FNV64_PRIME;
    }
    return hash;
}

#if defined(__TARGET_ARCH_x86)
static __always_inline void fill_stack_regs(struct stack_regs* out, struct pt_regs* ctx) {
    out->reg[0] = ctx->ax;
    out->reg[1] = ctx->dx;
    out->reg[2] = ctx->cx;
    out->reg[3] = ctx->bx;
    out->reg[4] = ctx->si;
    out->reg[5] = ctx->di;
    out->reg[6] = ctx->bp;
    out->reg[7] = ctx->sp;
    out->reg[8] = ctx->r8;
    out->reg[9] = ctx->r9;
    out->reg[10] = ctx->r10;
    out->reg[11] = ctx->r11;
    out->reg[12] = ctx->r12;
    out->reg[13] = ctx->r13;
    out->reg[14] = ctx->r14;
    out->reg[15] = ctx->r15;
    out->reg[16] = ctx->ip;
}
#elif defined(__TARGET_ARCH_arm64)
static __always_inline void fill_stack_regs(struct stack_regs* out, struct pt_regs* ctx) {
    struct user_pt_regs* uregs = (struct user_pt_regs*)ctx;
#pragma unroll
    for (int i = 0; i < 31; i++) {
        out->reg[i] = uregs->regs[i];
    }
    out->reg[31] = uregs->sp;
    out->reg[32] = uregs->pc;
}
#else
#error "stack capture needs a DWARF register mapping for this architecture"
#endif

static __always_inline __u64 capture_stack_inner(struct pt_regs* ctx, struct task_ids ids) {
    __u32 zero = 0;
    struct stack_scratch_buf* scratch = bpf_map_lookup_elem(&stack_scratch, &zero);
    if (!scratch) {
        return 0;
    }

    __u64 sp = PT_REGS_SP(ctx);
    const __u32 want = 8192;

    /* Chunked reads stop at the first unreadable stack region. */
    __u64 hash = FNV64_OFFSET;
    __u32 got = 0;
#pragma clang loop unroll(disable)
    for (__u32 off = 0; off + STACK_COPY_CHUNK <= MEMTRACK_MAX_STACK_COPY;
         off += STACK_COPY_CHUNK) {
        if (off >= want) {
            break;
        }
        if (bpf_probe_read_user(&scratch->bytes[off], STACK_COPY_CHUNK, (void*)(sp + off)) != 0) {
            break;
        }

        hash = fnv64_hash_chunk(hash, &scratch->words[off >> 3]);
        got = off + STACK_COPY_CHUNK;
    }

    if (got == 0) {
        bump_stack_counter(MEMTRACK_STACK_COUNTER_COPY_FAILED);
        return 0;
    }

    __u8 truncated = got >= want;
    if (truncated) {
        bump_stack_counter(MEMTRACK_STACK_COUNTER_TRUNCATED);
    }

    /* Length distinguishes a full copy from the same bytes as a truncated prefix.
     * Zero is reserved for allocation events without a stack. */
    hash = (hash ^ got) * FNV64_PRIME;
    if (hash == 0) {
        hash = FNV64_OFFSET;
    }

    __u8 marker = 1;
    long gate_result = bpf_map_update_elem(&seen_stack_hashes, &hash, &marker, BPF_NOEXIST);
    if (gate_result == -17) { /* -EEXIST */
        return hash;
    }
    if (gate_result != 0) {
        /* Re-emit when deduplication is full so the hash remains resolvable. */
        bump_stack_counter(MEMTRACK_STACK_COUNTER_HASH_MAP_FULL);
    }

    __s64 stackid = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    if (stackid < 0) {
        bump_stack_counter(MEMTRACK_STACK_COUNTER_STACKID_FAILED);
    }

    scratch->header.hash = hash;
    scratch->header.timestamp = bpf_ktime_get_ns();
    scratch->header.stackid = stackid;
    scratch->header.sp = sp;
    scratch->header.pid = ids.tgid;
    scratch->header.tid = ids.tid;
    scratch->header.copy_len = got;
    scratch->header.truncated = truncated;
    scratch->header._pad[0] = 0;
    scratch->header._pad[1] = 0;
    scratch->header._pad[2] = 0;
    fill_stack_regs(&scratch->header.regs, ctx);

    if (bpf_ringbuf_output(&stacks, scratch, sizeof(struct stack_header) + got, 0) != 0) {
        bump_stack_counter(MEMTRACK_STACK_COUNTER_RING_FULL);
        bpf_map_delete_elem(&seen_stack_hashes, &hash);
    }

    return hash;
}

static __always_inline __u64 capture_stack(struct pt_regs* ctx) {
    if (!capture_stacks_enabled || !is_enabled()) {
        return 0;
    }

    struct task_ids ids = current_task_ids();
    if (!is_tracked(ids.tgid)) {
        return 0;
    }

    __u32 zero = 0;
    __u64* busy = bpf_map_lookup_elem(&stack_busy, &zero);
    if (!busy) {
        return 0;
    }
    /* Uprobe programs run in preemptible task context without the
     * bpf_prog_active recursion guard, so a task preempting this one on the
     * same CPU can re-enter and reuse the per-CPU scratch buffer. */
    if (__sync_val_compare_and_swap(busy, 0, 1) != 0) {
        bump_stack_counter(MEMTRACK_STACK_COUNTER_PREEMPTED);
        return 0;
    }

    __u64 hash = capture_stack_inner(ctx, ids);

    /* A same-CPU contender runs only after a context switch, which orders this
     * plain store before scratch-buffer reuse. */
    *busy = 0;
    return hash;
}

static __always_inline void stash_stack_hash(__u64 hash) {
    if (hash == 0) {
        return;
    }

    __u64 tid = current_tid();
    bpf_map_update_elem(&pending_stack_hash, &tid, &hash, BPF_ANY);
}

static __always_inline __u64 take_stack_hash(void) {
    if (!capture_stacks_enabled) {
        return 0;
    }

    __u64 tid = current_tid();
    __u64* hash = bpf_map_lookup_elem(&pending_stack_hash, &tid);
    if (!hash) {
        return 0;
    }

    __u64 value = *hash;
    bpf_map_delete_elem(&pending_stack_hash, &tid);
    return value;
}

#endif /* __STACK_CAPTURE_BPF_H__ */
