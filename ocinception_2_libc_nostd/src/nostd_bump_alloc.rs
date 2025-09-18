//! Implement a bump allocator to handle Rust allocations.
//!
//! This was inspired by Solana SDK:
//! https://github.com/anza-xyz/solana-sdk/blob/program-entrypoint%40v2.3.0/program-entrypoint/src/lib.rs#L342-L364
#[cfg(feature = "with-debug")]
use super::panic::my_panic;
use core::alloc::{GlobalAlloc, Layout};

pub struct BumpAlloc;

#[global_allocator]
static GLOBAL_ALLOCATOR: BumpAlloc = BumpAlloc;

const HEAP_SIZE: usize = 50 * 1024 * 1024;
static mut BUMP_ALLOCATOR_HEAP: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];
static mut BUMP_ALLOCATOR_OFFSET: usize = 0;

unsafe impl GlobalAlloc for BumpAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut heap_offset = unsafe { BUMP_ALLOCATOR_OFFSET };
        // Reserve enough space to align
        heap_offset += layout.align();

        #[allow(static_mut_refs)]
        let allocation_ptr = (unsafe { BUMP_ALLOCATOR_HEAP.as_mut_ptr() as usize } + heap_offset)
            & !(layout.align().wrapping_sub(1));

        // Reserve the requested space
        heap_offset += layout.size();

        #[cfg(feature = "with-debug")]
        if heap_offset >= HEAP_SIZE {
            my_panic("too much heap space has been used");
        }

        unsafe { BUMP_ALLOCATOR_OFFSET = heap_offset };
        allocation_ptr as *mut u8
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // All allocations are guaranteed to only contain nul bytes
        unsafe { self.alloc(layout) }
    }

    #[inline]
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}
