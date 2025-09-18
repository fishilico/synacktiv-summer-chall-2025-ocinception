use super::{
    copy_str,
    linux_syscalls::{syscall_accept1, syscall_bind, syscall_read, syscall_socket, syscall_write},
};

/// Create a socket to compute SHA256 hashes using Linux crypto userspace API
/// https://www.kernel.org/doc/html/v6.16/crypto/userspace-if.html
#[must_use]
pub fn open_linux_sha256() -> u32 {
    const AF_ALG: u32 = 38;
    const SOCK_SEQPACKET: u32 = 5;

    let mut addr_buffer = [0u8; 88]; // struct sockaddr_alg
    addr_buffer[0] = AF_ALG as u8; // salg_family
    // addr_buffer[2..6].copy_from_slice(b"hash"); // salg_type
    // addr_buffer[24..30].copy_from_slice(b"sha256"); // salg_name
    unsafe {
        copy_str!(addr_buffer.as_mut_ptr().add(2), "hash");
        copy_str!(addr_buffer.as_mut_ptr().add(24), "sha256");
    }

    // Create a transformation socket
    let tfmfd = syscall_socket(AF_ALG, SOCK_SEQPACKET, 0);

    // Bind the socket to SHA256
    unsafe { syscall_bind(tfmfd, addr_buffer.as_ptr(), addr_buffer.len()) };

    // Get the operation socket
    syscall_accept1(tfmfd)
}

/// Compute a SHA256 hash using Linux crypto userspace API
/// https://www.kernel.org/doc/html/v6.16/crypto/userspace-if.html
#[cfg_attr(target_arch = "x86", allow(dead_code))]
pub unsafe fn linux_sha256(sha256_opfd: u32, data: *const u8, size: u32, digest: &mut [u8; 32]) {
    #[cfg_attr(not(feature = "with-debug"), allow(unused_variables))]
    let written = unsafe { syscall_write(sha256_opfd, data, size) };
    #[cfg(feature = "with-debug")]
    if written != size as usize {
        panic!("sha256 write error");
    }

    #[cfg_attr(not(feature = "with-debug"), allow(unused_variables))]
    let read = unsafe { syscall_read(sha256_opfd, digest.as_mut_ptr(), digest.len()) };
    #[cfg(feature = "with-debug")]
    if read != 32 {
        panic!("sha256 read error");
    }
}

/// Compute a SHA256 and format it in hexadecimal at the given pointer
/// This function is optimized for x86 fastcall (args in ecx, edx and stack)
#[inline(never)]
pub unsafe fn sha256_hex(data: *const u8, size: u32, sha256_opfd: u32, hex_digest_ptr: *mut u8) {
    #[cfg(target_arch = "x86")]
    unsafe {
        // Use a static buffer as there is no thread in this program
        static mut SHA256_DIGEST: [u8; 32] = [0; 32];

        core::arch::asm!(
            "push esi",

            // Write the data: ebx = opfd, ecx = data, edx = size
            "xor eax, eax",
            "mov al, {NR_WRITE}",
            "int 0x80",

            // Read the data: ebx = opfd, ecx = buffer, edx = size
            "mov ecx, OFFSET {SHA256_DIGEST}",
            "xor edx, edx",
            "mov dl, 0x20",
            "xor eax, eax",
            "mov al, {NR_READ}",
            "int 0x80",

            // Convert to hexadecimal using the poem from
            // https://www.xorpd.net/pages/xchg_rax/snip_1e.html
            "mov esi, ecx",
            "mov ecx, edx",
            "2:",
            "lodsb al, byte ptr [esi]",
            "ror eax, 4",
            // Introduce a skip instruction (test al, imm8) to decrement edx when jumping
            ".byte 0xa8",
            "3:",
            "dec edx", // 0x4a (1 byte)
            "cmp al, 0x0a",
            "sbb al, 0x69",
            "das",
            "or al, 0x20",
            "stosb byte ptr es:[edi], al",

            // Convert the next nibble:
            // - For high significant nibbles, edx = ecx. edx gets decremented.
            // - For low significant nibbles, edx = ecx - 1, loop to the next source byte or return.
            "shr eax, 28",
            "cmp ecx, edx",
            "je 3b",

            "loop 2b",

            "pop esi",
            SHA256_DIGEST = sym SHA256_DIGEST,
            NR_WRITE = const super::linux_syscalls::NR_WRITE,
            NR_READ = const super::linux_syscalls::NR_READ,
            out("eax") _,
            inout("ebx") sha256_opfd => _,
            inout("ecx") data => _,
            inout("edx") size => _,
            inout("edi") hex_digest_ptr => _,
            options(nostack)
        )
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let mut digest = [0; 32];
        unsafe { linux_sha256(sha256_opfd, data, size, &mut digest) };

        // Group hexdigits by pairs
        let hex_digest = unsafe { core::slice::from_raw_parts_mut(hex_digest_ptr, 64) };
        for (hexdigits, byte) in hex_digest.chunks_mut(2).zip(digest) {
            hexdigits[0] = (byte >> 4) + if byte >= 0xa0 { b'a' - 10 } else { b'0' };
            let low_nibble = byte & 0xf;
            hexdigits[1] = low_nibble + if low_nibble >= 10 { b'a' - 10 } else { b'0' };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256() {
        super::super::global_strings::decompress_strings();
        let sha256_opfd = open_linux_sha256();
        let mut hex_digest = [0u8; 64];

        unsafe { sha256_hex(b"".as_ptr(), 0, sha256_opfd, hex_digest.as_mut_ptr()) };
        assert_eq!(
            hex_digest,
            *b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        unsafe { sha256_hex(b"hello".as_ptr(), 5, sha256_opfd, hex_digest.as_mut_ptr()) };
        assert_eq!(
            hex_digest,
            *b"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
