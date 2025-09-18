//! Linux system calls ("syscalls") list and functions
//!
//! glibc syscall implementation for x86_64:
//! https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/x86_64/syscall.S;h=b211a0baab40d40e25c682c7745da26111752d83;hb=d2097651cc57834dbfcaa102ddfacae0d86cfb66
//! Implementation on x86 is a bit more complex:
//! https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/i386/syscall.S;h=99d2f70432156dbb09918383e6d45cec904974da;hb=d2097651cc57834dbfcaa102ddfacae0d86cfb66
//! https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/i386/sysdep.h;h=87806a7a978a9c25062cd5d20b3ee46a2d9b97dc;hb=d2097651cc57834dbfcaa102ddfacae0d86cfb66#l125
#[cfg(feature = "with-debug")]
use super::panic::my_panic;

#[cfg(target_arch = "x86")]
mod numbers {
    pub const NR_EXIT: u32 = 1;
    pub const NR_READ: u32 = 3;
    pub const NR_WRITE: u32 = 4;
    pub const NR_OPEN: u32 = 5;
    pub const NR_SOCKET: u32 = 359;
    pub const NR_BIND: u32 = 361;
    pub const NR_ACCEPT4: u32 = 364;
}

#[cfg(target_arch = "x86_64")]
mod numbers {
    pub const NR_READ: u32 = 0;
    pub const NR_WRITE: u32 = 1;
    pub const NR_OPEN: u32 = 2;
    pub const NR_SOCKET: u32 = 41;
    pub const NR_ACCEPT: u32 = 43;
    pub const NR_BIND: u32 = 49;
    pub const NR_EXIT: u32 = 60;
}
pub use numbers::*;

#[cfg(feature = "with-debug")]
pub const MIN_ERRNO: usize = 0xfffff001;

/// Perform a system call to exit with a code and do not return
#[inline]
pub fn syscall_exit(code: u32) -> ! {
    unsafe {
        #[cfg(target_arch = "x86")]
        core::arch::asm!(
            "int 0x80",
            in("eax") NR_EXIT,
            in("ebx") code,
            options(nomem, noreturn, nostack, preserves_flags)
        );
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "syscall",
            in("rax") NR_EXIT as u64,
            in("rdi") code as u64,
            options(nomem, noreturn, nostack, preserves_flags)
        );
    }
}

/// Perform a system call with 2 arguments
#[inline]
#[must_use]
pub unsafe fn syscall2(number: u32, arg0: usize, arg1: usize) -> usize {
    let mut ret: usize;
    unsafe {
        #[cfg(target_arch = "x86")]
        core::arch::asm!(
            "int 0x80",
            inlateout("eax") number => ret,
            in("ebx") arg0,
            in("ecx") arg1,
            options(nostack, preserves_flags)
        );
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "syscall",
            inlateout("rax") number as u64 => ret,
            in("rdi") arg0,
            in("rsi") arg1,
            out("rcx") _,
            out("r11") _,
            options(nostack, preserves_flags)
        );
    }
    ret
}

/// Perform a system call with 3 arguments
#[inline]
#[must_use]
pub unsafe fn syscall3(number: u32, arg0: usize, arg1: usize, arg2: usize) -> usize {
    let mut ret: usize;
    unsafe {
        #[cfg(target_arch = "x86")]
        core::arch::asm!(
            "int 0x80",
            inlateout("eax") number => ret,
            in("ebx") arg0,
            in("ecx") arg1,
            in("edx") arg2,
            options(nostack, preserves_flags)
        );
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "syscall",

            inlateout("rax") number as u64 => ret,
            in("rdi") arg0,
            in("rsi") arg1,
            in("rdx") arg2,
            out("rcx") _,
            out("r11") _,
            options(nostack, preserves_flags)
        );
    }
    ret
}

/// Perform a system call with 4 arguments
#[cfg_attr(target_arch = "x86_64", allow(dead_code))]
#[inline]
#[must_use]
pub unsafe fn syscall4(number: u32, arg0: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
    let mut ret: usize;
    unsafe {
        #[cfg(target_arch = "x86")]
        core::arch::asm!(
            "xchg esi, {arg3}",
            "int 0x80",
            "xchg esi, {arg3}",
            // Using esi is not allowed with LLVM. The compiler reports:
            // error: cannot use register `si`: esi is used internally by LLVM and cannot be used as an operand for inline asm
            // Also https://practice.course.rs/unsafe/inline-asm.html#explicit-register-operands
            // says: Note: [...] Also, they [explicit register operands] must appear at the end of the operand list after all other operand types.
            arg3 = in(reg) arg3,
            inlateout("eax") number => ret,
            in("ebx") arg0,
            in("ecx") arg1,
            in("edx") arg2,
            options(nostack, preserves_flags)
        );
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "syscall",

            inlateout("rax") number as u64 => ret,
            in("rdi") arg0,
            in("rsi") arg1,
            in("rdx") arg2,
            in("r10") arg3,
            out("rcx") _,
            out("r11") _,
            options(nostack, preserves_flags)
        );
    }
    ret
}

/// Invoke syscall read, returning an unsigned size
#[must_use]
pub unsafe fn syscall_read(fd: u32, buffer: *mut u8, count: usize) -> usize {
    let ret = unsafe { syscall3(NR_READ, fd as usize, buffer as usize, count) };
    // Handle errors only with builds without "no-debug"
    #[cfg(feature = "with-debug")]
    if ret >= MIN_ERRNO {
        my_panic("syscall read failed");
    }
    ret
}

/// Invoke syscall write, returning an unsigned size
#[must_use]
pub unsafe fn syscall_write(fd: u32, buffer: *const u8, count: u32) -> usize {
    let ret = unsafe { syscall3(NR_WRITE, fd as usize, buffer as usize, count as usize) };
    // Handle errors only with builds without "no-debug"
    #[cfg(feature = "with-debug")]
    if ret >= MIN_ERRNO {
        my_panic("syscall write failed");
    }
    ret
}

/// Invoke syscall write, ensuring everything was read
pub unsafe fn syscall_write_all(fd: u32, buffer: *const u8, count: u32) {
    #[cfg_attr(not(feature = "with-debug"), allow(unused_variables))]
    let ret = unsafe { syscall_write(fd, buffer, count) };
    // Handle errors only with builds without "no-debug"
    #[cfg(feature = "with-debug")]
    if ret != count as usize {
        my_panic("syscall write was truncated");
    }
}

#[must_use]
pub unsafe fn syscall_open(pathname: *const u8, flags: u32) -> u32 {
    let ret = unsafe { syscall2(NR_OPEN, pathname as usize, flags as usize) };
    #[cfg(feature = "with-debug")]
    if ret >= MIN_ERRNO || ret > u32::MAX as usize {
        my_panic("syscall open failed");
    }
    ret as u32
}

#[must_use]
pub fn syscall_socket(domain: u32, ty: u32, protocol: u32) -> u32 {
    #[cfg_attr(not(feature = "with-debug"), allow(unused_variables))]
    let ret = unsafe { syscall3(NR_SOCKET, domain as usize, ty as usize, protocol as usize) };
    #[cfg(feature = "with-debug")]
    if ret >= MIN_ERRNO || ret > u32::MAX as usize {
        my_panic("syscall socket failed");
    }
    ret as u32
}

pub unsafe fn syscall_bind(sockfd: u32, addr: *const u8, addrlen: usize) {
    #[cfg_attr(not(feature = "with-debug"), allow(unused_variables))]
    let ret = unsafe { syscall3(NR_BIND, sockfd as usize, addr as usize, addrlen) };
    #[cfg(feature = "with-debug")]
    if ret >= MIN_ERRNO {
        my_panic("syscall bind failed");
    }
}

/// Invoke syscall accept or accept4, ignoring the peer address
#[must_use]
pub fn syscall_accept1(sockfd: u32) -> u32 {
    #[cfg_attr(not(feature = "with-debug"), allow(unused_variables))]
    let ret: usize;
    unsafe {
        #[cfg(target_arch = "x86")]
        {
            ret = syscall4(NR_ACCEPT4, sockfd as usize, 0, 0, 0);
        }
        #[cfg(target_arch = "x86_64")]
        {
            ret = syscall3(NR_ACCEPT, sockfd as usize, 0, 0);
        }
    };
    #[cfg(feature = "with-debug")]
    if ret >= MIN_ERRNO || ret > u32::MAX as usize {
        my_panic("syscall socket failed");
    }
    ret as u32
}
