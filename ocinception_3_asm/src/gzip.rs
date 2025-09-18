/// Compress the image using gzip DEFLATE
/// https://datatracker.ietf.org/doc/html/rfc1952 GZIP file format specification version 4.3
/// https://datatracker.ietf.org/doc/html/rfc1951 DEFLATE Compressed Data Format Specification version 1.3
//#[cfg(all(not(test), feature = "gzip"))]
#[allow(static_mut_refs)]
#[unsafe(link_section = ".text.compress_image")]
#[unsafe(no_mangle)]
#[rustc_align(1)]
pub extern "C" fn compress_gzip() -> ! {
    let image_ptr = unsafe { super::IMAGE_TAR_BYTES.as_ptr() };
    let file_size = unsafe { super::SYMBOL_FILE_SIZE.as_ptr() as usize };
    let image_size = 7 * 512 + file_size;
    #[cfg(feature = "with-debug")]
    {
        let image_end_ptr = unsafe { super::IMAGE_TAR_BYTES_END.as_ptr() };
        let image_size = image_end_ptr as usize - image_ptr as usize;
        assert_eq!(image_size, image_end_ptr as usize - image_ptr as usize);
    }

    let data = unsafe { core::slice::from_raw_parts(image_ptr, image_size) };
    let deflate_compressed = unsafe {
        core::slice::from_raw_parts_mut(
            super::IMAGE_COMPRESSED.as_mut_ptr().add(10),
            image_size - 10,
        )
    };

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
    let (status, bytes_in, deflate_size) = miniz_oxide::deflate::core::compress(
        &mut compressor,
        data,
        deflate_compressed,
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

    unsafe {
        core::arch::asm!(
            // Compte the GZip CRC32
            "xor eax, eax",
            "dec eax", // set CRC value to 0xffffffff
            "mov edi, OFFSET {IMAGE_TAR_BYTES}",
            "2:",
            "xor al, byte ptr [edi]",
            "push 8",
            "pop ecx",
            "3:",
            "shr eax, 1",
            "jnc 4f",
            "xor eax, 0xedb88320",
            "4:",
            "loop 3b",
            "inc edi",
            "cmp edi, OFFSET {IMAGE_COMPRESSED}", // Stop loop at IMAGE_TAR_BYTES_END = IMAGE_COMPRESSED
            "jnz 2b",
            "not eax",
            // Write GZip header
            // "mov edi, OFFSET {IMAGE_COMPRESSED}",
            "push edi",
            "mov dword ptr [edi], {GZIP_HEADER}",
            // Write GZip footer
            "add edi, 10",
            "add edi, edx",
            "stosd dword ptr es:[edi], eax", // Store the CRC32
            "mov dword ptr [edi], OFFSET {SYMBOL_FILE_SIZE} + {DIFF_IMAGE_SIZE_FILE_SIZE}", // Store the initial size
            // Syscall write
            "pop ecx", // buffer = compressed
            "add edx, 18", // size = deflate_size + 18
            "push {NR_WRITE}",
            "pop eax",
            "push 1",
            "pop ebx", // fd = 1
            "int 0x80",
            // Exit
            "mov eax, ebx", // NR_exit = 1
            "dec ebx",      // exit_code = 0
            "int 0x80",
            IMAGE_TAR_BYTES = sym super::IMAGE_TAR_BYTES,
            IMAGE_COMPRESSED = sym super::IMAGE_COMPRESSED,
            SYMBOL_FILE_SIZE = sym super::SYMBOL_FILE_SIZE,
            NR_WRITE = const super::linux_syscalls::NR_WRITE,
            GZIP_HEADER = const u32::from_ne_bytes(*b"\x1f\x8b\x08\0"),
            DIFF_IMAGE_SIZE_FILE_SIZE = const 7 * 512, // 7 tar blocks
            in("edx") deflate_size,
            options(noreturn, nostack)
        );
    }
}

/// Provide an optimized version of memcpy
#[cfg(not(test))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, size: u32) -> *mut u8 {
    unsafe {
        core::arch::asm!(
            "xchg esi, {src}",
            "rep movsb byte ptr es:[edi], byte ptr [esi]",
            "mov esi, {src}",
            src = inout(reg) src => _,  // esi is used internally by LLVM
            inout("edi") dst => _,
            inout("ecx") size => _,
            options(nostack, preserves_flags)
        );
    }
    dst
}

/// Provide an optimized version of memset
#[cfg(not(test))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut u8, c: u8, size: usize) -> *mut u8 {
    unsafe {
        core::arch::asm!(
            "rep stosb byte ptr [edi], al",
            in("al") c,
            inout("edi") dst => _,
            inout("ecx") size => _,
            options(nostack, preserves_flags)
        );
    }
    dst
}
