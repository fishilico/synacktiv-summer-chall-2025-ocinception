//! Implement some memory operations in assembly

/// Compute the length of a string
///
/// # Safety
/// `s` must target a valid C string
#[inline]
pub unsafe fn asm_strlen(s: *const u8) -> u32 {
    let mut ret: u32;
    unsafe {
        #[cfg(target_arch = "x86")]
        core::arch::asm!(
            "not ecx",
            "repne scasb al, byte ptr es:[edi]",
            "not ecx",
            "dec ecx",
            in("eax") 0,
            inout("ecx") 0 => ret,
            inout("edi") s => _,
            options(nostack, readonly)
        );
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "not ecx",
            "xor eax, eax",
            "repne scasb al, byte ptr es:[rdi]",
            "not ecx", // Optimization: assume strings are shorter than 4 GB
            "dec ecx",
            in("rax") 0,
            inout("rcx") 0 => ret,
            inout("rdi") s => _,
            options(nostack, readonly)
        );
    }
    ret
}

/// Copy a byte to a pointer, like memset
///
/// Return the end of the dst.
///
/// # Safety
/// - `dst` must have enough space to hold `size` bytes.
#[cfg_attr(not(test), allow(dead_code))]
#[inline]
pub unsafe fn asm_memset(mut dst: *mut u8, c: u8, size: usize) -> *mut u8 {
    unsafe {
        #[cfg(target_arch = "x86")]
        core::arch::asm!(
            "rep stosb byte ptr [edi], al",
            in("al") c,
            inout("edi") dst,
            inout("ecx") size => _,
            options(nostack, preserves_flags)
        );
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "rep stosb byte ptr [rdi], al",
            in("al") c,
            inout("rdi") dst,
            inout("ecx") size as u32 => _,  // Optimization: use 32-bit register assignation
            options(nostack, preserves_flags)
        );
    }
    dst
}

#[cfg(not(test))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut u8, c: u8, size: usize) -> *mut u8 {
    unsafe { asm_memset(dst, c, size) };
    // Return the start of dst
    dst
}

/// memset with a constant small size and character
#[inline]
pub unsafe fn asm_memset_const<const CHAR: u8, const SIZE: usize>(mut dst: *mut u8) -> *mut u8 {
    assert!(SIZE < 256);
    // Optimize the assembly code to let the compiler known ecx = 0
    unsafe {
        #[cfg(target_arch = "x86")]
        core::arch::asm!(
            "mov cl, {SIZE}",
            "rep stosb byte ptr [edi], al",
            SIZE = const SIZE,
            in("al") CHAR,
            in("ecx") 0,
            inout("edi") dst,
            options(nostack, preserves_flags)
        );
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "mov cl, {SIZE}",
            "rep stosb byte ptr [rdi], al",
            SIZE = const SIZE,
            in("al") CHAR,
            in("ecx") 0,
            inout("rdi") dst,
            options(nostack, preserves_flags)
        );
    }
    dst
}

/// Copy bytes to a pointer, like memcpy
///
/// Return the end of the dst.
///
/// # Safety
/// - `dst` must have enough space to hold `size` bytes.
/// - `dst` and `src` must not overlap
#[cfg_attr(not(test), allow(dead_code))]
#[inline]
pub unsafe fn asm_memcpy(mut dst: *mut u8, src: *const u8, size: u32) -> *mut u8 {
    unsafe {
        #[cfg(target_arch = "x86")]
        core::arch::asm!(
            "xchg esi, {src}",
            "rep movsb byte ptr es:[edi], byte ptr [esi]",
            "mov esi, {src}",
            src = inout(reg) src => _,  // esi is used internally by LLVM
            inout("edi") dst,
            inout("ecx") size => _,
            options(nostack, preserves_flags)
        );
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "rep movsb byte ptr es:[rdi], byte ptr [rsi]",
            inlateout("rdi") dst,
            inlateout("rsi") src => _,
            inlateout("ecx") size => _,  // Optimization: use 32-bit register assignation
            options(nostack, preserves_flags)
        );
    }
    dst
}

#[cfg(not(test))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, size: u32) -> *mut u8 {
    unsafe {
        asm_memcpy(dst, src, size);
    }
    // Return the start of dst
    dst
}

/// memcpy with a constant small size
#[inline]
pub unsafe fn asm_memcpy_const<const SIZE: usize>(mut dst: *mut u8, src: *const u8) -> *mut u8 {
    assert!(SIZE < 256);
    // Optimize the assembly code to let the compiler known ecx = 0
    unsafe {
        #[cfg(target_arch = "x86")]
        core::arch::asm!(
            "xchg esi, {src}",
            "mov cl, {SIZE}",
            "rep movsb byte ptr es:[edi], byte ptr [esi]",
            "mov esi, {src}",
            SIZE = const SIZE,
            src = inout(reg) src => _,  // esi is used internally by LLVM
            inout("edi") dst,
            in("ecx") 0,
            options(nostack, preserves_flags)
        );
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "mov cl, {SIZE}",
            "rep movsb byte ptr es:[rdi], byte ptr [rsi]",
            SIZE = const SIZE,
            in("rcx") 0,
            inlateout("rdi") dst,
            inlateout("rsi") src => _,
            options(nostack, preserves_flags)
        );
    }
    dst
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strlen() {
        unsafe {
            assert_eq!(asm_strlen(b"\0".as_ptr()), 0);
            assert_eq!(asm_strlen(b"hello\0".as_ptr()), 5);
        }
    }

    #[test]
    fn memcpy() {
        unsafe {
            let mut buffer = [0u8; 5];
            let end = asm_memcpy(buffer.as_mut_ptr(), b"hello".as_ptr(), 5);
            assert_eq!(buffer, *b"hello");
            assert_eq!(end, buffer.as_mut_ptr().add(5));

            let end = asm_memcpy(buffer.as_mut_ptr().add(1), b"i ".as_ptr(), 2);
            assert_eq!(buffer, *b"hi lo");
            assert_eq!(end, buffer.as_mut_ptr().add(3));

            let end = asm_memcpy_const::<2>(buffer.as_mut_ptr(), b"HI".as_ptr());
            assert_eq!(buffer, *b"HI lo");
            assert_eq!(end, buffer.as_mut_ptr().add(2));
        }
    }

    #[test]
    fn memset() {
        unsafe {
            let mut buffer = [0u8; 5];
            let end = asm_memset(buffer.as_mut_ptr(), b'a', 5);
            assert_eq!(buffer, *b"aaaaa");
            assert_eq!(end, buffer.as_mut_ptr().add(5));

            let end = asm_memset(buffer.as_mut_ptr().add(1), b'b', 3);
            assert_eq!(buffer, *b"abbba");
            assert_eq!(end, buffer.as_mut_ptr().add(4));

            let end = asm_memset_const::<b'C', 2>(buffer.as_mut_ptr());
            assert_eq!(buffer, *b"CCbba");
            assert_eq!(end, buffer.as_mut_ptr().add(2));
        }
    }
}
