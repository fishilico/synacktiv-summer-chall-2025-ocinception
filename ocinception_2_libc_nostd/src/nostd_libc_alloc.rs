use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;

#[link(name = "c")]
unsafe extern "C" {
    pub fn free(p: *mut c_void);

    pub fn memalign(align: usize, size: usize) -> *mut c_void;
}

pub struct LibcAlloc;

#[global_allocator]
static GLOBAL_ALLOCATOR: LibcAlloc = LibcAlloc;

unsafe impl GlobalAlloc for LibcAlloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        /*
        #[cfg(feature = "with-debug")]
        {
            // Show some statistics
            static mut TOTAL_ALLOCATED: usize = 0;
            unsafe { TOTAL_ALLOCATED += layout.size() };
            core::fmt::write(
                &mut super::panic::StdErrWriter {},
                format_args!("alloc {} bytes, total {}\n", layout.size(), unsafe {
                    TOTAL_ALLOCATED
                }),
            )
            .unwrap();
        }
        */
        let align = layout.align().max(core::mem::size_of::<usize>());
        unsafe { memalign(align, layout.size()) as *mut u8 }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { self.alloc(layout) };
        if !ptr.is_null() {
            unsafe { core::ptr::write_bytes(ptr, 0, layout.size()) };
        }
        ptr
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe { free(ptr as *mut c_void) };
    }
}
