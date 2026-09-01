#[macro_use]
mod shared;

use itertools::Itertools;
use memtrack::TrackerOptions;
use rstest::rstest;
use runner_shared::artifacts::{MemtrackEvent, MemtrackEventKind};
use std::mem::discriminant;
use std::process::Command;
use tempfile::TempDir;

fn describe_allocator_event(kind: &MemtrackEventKind) -> Option<String> {
    let description = match kind {
        MemtrackEventKind::Malloc { size, stack_hash } => {
            format!("Malloc {{ size: {size}, has_stack: {} }}", *stack_hash != 0)
        }
        MemtrackEventKind::Calloc { size, stack_hash } => {
            format!("Calloc {{ size: {size}, has_stack: {} }}", *stack_hash != 0)
        }
        MemtrackEventKind::AlignedAlloc { size, stack_hash } => format!(
            "AlignedAlloc {{ size: {size}, has_stack: {} }}",
            *stack_hash != 0
        ),
        MemtrackEventKind::Realloc {
            size, stack_hash, ..
        } => {
            format!(
                "Realloc {{ size: {size}, has_stack: {} }}",
                *stack_hash != 0
            )
        }
        MemtrackEventKind::Free { stack_hash } => {
            format!("Free {{ has_stack: {} }}", *stack_hash != 0)
        }
        _ => return None,
    };

    Some(description)
}

fn format_events(events: &[MemtrackEvent]) -> Vec<String> {
    const MARKER: u64 = 0xC0D5_9EED;
    let has_markers = events.iter().any(|e| {
        matches!(
            e.kind,
            MemtrackEventKind::Malloc { size, .. } if size == MARKER
        )
    });

    let filtered_events = if has_markers {
        shared::between_markers(events)
    } else {
        events
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    MemtrackEventKind::Malloc { .. }
                        | MemtrackEventKind::Free { .. }
                        | MemtrackEventKind::Calloc { .. }
                        | MemtrackEventKind::Realloc { .. }
                        | MemtrackEventKind::AlignedAlloc { .. }
                )
            })
            .sorted_by_key(|e| e.timestamp)
            .dedup_by(|a, b| a.addr == b.addr && discriminant(&a.kind) == discriminant(&b.kind))
            .cloned()
            .collect()
    };

    filtered_events
        .iter()
        .filter_map(|e| describe_allocator_event(&e.kind))
        .collect()
}

#[test_with::env(GITHUB_ACTIONS)]
#[rstest]
#[case::stack_paths(include_str!("../testdata/stack_paths.c"), "stack_paths", true)]
#[case::nested_doubling(
    include_str!("../testdata/nested_doubling.c"),
    "nested_doubling",
    true
)]
#[case::nested_doubling_shared_free(
    include_str!("../testdata/nested_doubling_shared_free.c"),
    "nested_doubling_shared_free",
    true
)]
#[case::stack_capture_disabled(
    include_str!("../testdata/stack_paths.c"),
    "stack_capture_disabled",
    false
)]
#[test_log::test]
fn test_stack_capture(
    #[case] source: &str,
    #[case] name: &str,
    #[case] stack_capture: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let binary = shared::compile_c_source(source, name, temp_dir.path())?;
    let options = TrackerOptions::builder()
        .stack_capture(stack_capture)
        .build();
    let (events, thread_handle) = shared::track_command(Command::new(binary), options)?;

    insta::assert_debug_snapshot!(name, format_events(&events));

    thread_handle
        .join()
        .expect("tracker teardown thread panicked");
    Ok(())
}
