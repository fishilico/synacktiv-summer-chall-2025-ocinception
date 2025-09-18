//! Define custom panic handlers
#[cfg(any(feature = "with-debug", not(any(feature = "std", test))))]
use super::linux_syscalls::syscall_exit;
#[cfg(feature = "with-debug")]
use super::linux_syscalls::syscall_write_all;

/// Enable writing formatted strings to stderr
#[cfg(feature = "with-debug")]
#[allow(dead_code)]
pub struct StdErrWriter;

#[cfg(feature = "with-debug")]
impl core::fmt::Write for StdErrWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        unsafe { syscall_write_all(2, s.as_ptr(), s.len() as u32) };
        Ok(())
    }
}

/// Panic ourselves
#[cfg(feature = "with-debug")]
pub fn my_panic(msg: &str) -> ! {
    unsafe {
        syscall_write_all(2, msg.as_ptr(), msg.len() as u32);
        syscall_write_all(2, b"\n".as_ptr(), 1);
    }
    syscall_exit(1);
}

#[cfg(not(any(feature = "std", test)))]
#[panic_handler]
#[cfg_attr(not(feature = "with-debug"), allow(unused_variables))]
fn panic(info: &core::panic::PanicInfo) -> ! {
    #[cfg(feature = "with-debug")]
    {
        if core::fmt::write(
            &mut StdErrWriter {},
            format_args!("Rust triggered a panic: {}\n", info),
        )
        .is_err()
        {
            my_panic("Rust triggered a panic");
        }
    }
    syscall_exit(1);
}
