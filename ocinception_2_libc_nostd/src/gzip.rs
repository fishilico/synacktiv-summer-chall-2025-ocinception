#[cfg(not(test))]
use super::{
    IMAGE_TAR_BYTES, MAX_IMAGE_SIZE,
    linux_syscalls::{syscall_exit, syscall_write_all},
};

/// Compute the CRC32 used in gzip
/// crc32fast contains a speed-optimised version in
/// https://github.com/srijs/rust-crc32fast/blob/v1.5.0/src/specialized/pclmulqdq.rs
/// but we are only interested in having a minimal set of instructions
fn gzip_crc32(data: &[u8]) -> u32 {
    #[cfg(target_arch = "x86")]
    {
        let mut value: u32;
        unsafe {
            core::arch::asm!(
                "xor eax, eax",
                "dec eax", // let mut value = 0xffffffff;
                out("eax") value,
                options(nostack, nomem, pure)
            );
        };
        for x in data {
            unsafe {
                core::arch::asm!(
                    "xor al, byte ptr [{x}]",
                    "push 8",
                    "pop ecx",
                    "2:",
                    "shr eax, 1",
                    "jnc 3f",
                    "xor eax, 0xedb88320",
                    "3:",
                    "loop 2b",
                    x = in(reg) x,
                    inout("eax") value,
                    out("ecx") _,
                    options(nostack)
                );
            };
        }
        !value
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let mut value = 0xffffffff;
        for x in data {
            value ^= *x as u32;
            for _ in 0..8 {
                if (value & 1) != 0 {
                    value = (value >> 1) ^ 0xedb88320; // reversed polynom 0x04c11db7
                } else {
                    value = value >> 1;
                }
            }
        }
        !value
    }
}

/// Compress the image using gzip DEFLATE
/// https://datatracker.ietf.org/doc/html/rfc1952 GZIP file format specification version 4.3
/// https://datatracker.ietf.org/doc/html/rfc1951 DEFLATE Compressed Data Format Specification version 1.3
#[cfg(not(test))]
#[allow(static_mut_refs)]
pub fn write_image_gzip(image_tar_size: u32) -> ! {
    let data = unsafe { &IMAGE_TAR_BYTES[..image_tar_size as usize] };
    static mut IMAGE_COMPRESSED: [u8; MAX_IMAGE_SIZE] = [0; MAX_IMAGE_SIZE];
    let compressed = unsafe { &mut IMAGE_COMPRESSED };

    let flags = miniz_oxide::deflate::core::create_comp_flags_from_zip_params(
        // Compression level: https://github.com/Frommi/miniz_oxide/blob/0.8.8/miniz_oxide/src/deflate/mod.rs#L18
        10,
        // Window bits (positive for zlib:
        // https://github.com/Frommi/miniz_oxide/blob/0.8.8/miniz_oxide/src/deflate/core.rs#L2351-L2353)
        0,
        // Strategies: https://github.com/Frommi/miniz_oxide/blob/0.8.8/miniz_oxide/src/deflate/core.rs#L197
        miniz_oxide::deflate::core::CompressionStrategy::Default as i32,
    );
    let mut compressor = miniz_oxide::deflate::core::CompressorOxide::new(flags);
    #[cfg_attr(not(feature = "with-debug"), allow(unused_variables))]
    let (status, bytes_in, bytes_out) = miniz_oxide::deflate::core::compress(
        &mut compressor,
        data,
        &mut compressed[10..],
        miniz_oxide::deflate::core::TDEFLFlush::Finish,
    );
    #[cfg(feature = "with-debug")]
    {
        if status != miniz_oxide::deflate::core::TDEFLStatus::Done {
            panic!("gzip compression not complete");
        }
        if bytes_in != data.len() {
            panic!("gzip compression did not consume all input");
        }
    }

    // Add gzip header and footer
    compressed[0] = 0x1f;
    compressed[1] = 0x8b;
    compressed[2] = 8;
    unsafe {
        let footer_ptr = compressed.as_mut_ptr().add(10 + bytes_out);
        footer_ptr.cast::<u32>().write_unaligned(gzip_crc32(data));
        footer_ptr
            .add(4)
            .cast::<u32>()
            .write_unaligned(data.len() as u32);
    }
    unsafe { syscall_write_all(1, compressed.as_ptr(), 18 + bytes_out as u32) };
    syscall_exit(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test GZip CRC
    #[test]
    fn gzip_crc() {
        assert_eq!(gzip_crc32(b"\0"), 0xd202ef8d);
        assert_eq!(gzip_crc32(b"\xff"), 0xff000000);
        assert_eq!(gzip_crc32(b"hello world"), 0xd4a1185);
    }
}
