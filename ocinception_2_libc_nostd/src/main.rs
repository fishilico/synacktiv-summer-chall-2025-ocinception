#![allow(static_mut_refs)]
//#![feature(concat_bytes)] // https://github.com/rust-lang/rust/issues/87555
//#![feature(fn_align)] // https://github.com/rust-lang/rust/issues/82232
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(not(feature = "std"))]
use core::assert;

mod global_strings;
#[cfg(any(test, feature = "gzip"))]
mod gzip;
mod linux_syscalls;
mod mem_ops;
#[cfg(all(
    not(feature = "std"),
    feature = "use-alloc",
    not(feature = "use-libc-alloc")
))]
mod nostd_bump_alloc;
#[cfg(all(
    not(feature = "std"),
    feature = "use-alloc",
    feature = "use-libc-alloc"
))]
mod nostd_libc_alloc;
mod panic;
mod sha256;
#[cfg(feature = "zstd")]
mod zstd;

use self::global_strings::{
    CONFIG_AND_INDEX_JSON_LEN, MANIFEST_LEN, STR_BLOBS_SHA256, STR_CONFIG_1, STR_CONFIG_2,
    STR_CONFIG_3, STR_DIGEST_SHA256, STR_MANIFEST_1, STR_MANIFEST_2,
};
use self::linux_syscalls::{syscall_open, syscall_read};
use self::mem_ops::{asm_memcpy_const, asm_memset_const, asm_strlen};
#[cfg(not(any(feature = "gzip", feature = "zstd")))]
use linux_syscalls::{syscall_exit, syscall_write_all};

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
core::compile_error!("unsupported CPU architecture");

// Offsets in the generated OCI image
const IMAGE_OFFSET_INDEX_HEADER: usize = 0;
const IMAGE_OFFSET_INDEX_CONTENT: usize = IMAGE_OFFSET_INDEX_HEADER + 512;
const IMAGE_OFFSET_CONFIG_LINK_HEADER: usize = IMAGE_OFFSET_INDEX_CONTENT + 512;
const IMAGE_OFFSET_MANIFEST_HEADER: usize = IMAGE_OFFSET_CONFIG_LINK_HEADER + 512;
const IMAGE_OFFSET_MANIFEST_CONTENT: usize = IMAGE_OFFSET_MANIFEST_HEADER + 512;
const IMAGE_OFFSET_LAYER_HEADER: usize = IMAGE_OFFSET_MANIFEST_CONTENT + 512;
const IMAGE_OFFSET_LAYER_CONTENT: usize = IMAGE_OFFSET_LAYER_HEADER + 512;

const _: () = assert!(IMAGE_OFFSET_LAYER_CONTENT == 3072);

const IMAGE_OFFSET_SHA256_CONFIG: usize = IMAGE_OFFSET_MANIFEST_CONTENT + 101;
const IMAGE_OFFSET_SHA256_LAYER: usize = IMAGE_OFFSET_MANIFEST_CONTENT + 206;

const MAX_PROGRAM_SIZE: usize = 5 * 1024 * 1024;
const MAX_IMAGE_SIZE: usize = IMAGE_OFFSET_LAYER_CONTENT + 512 + MAX_PROGRAM_SIZE;

pub static mut IMAGE_TAR_BYTES: [u8; MAX_IMAGE_SIZE] = [0; MAX_IMAGE_SIZE];
const IMAGE_TAR_BYTES_PTR: *mut u8 = unsafe { IMAGE_TAR_BYTES.as_mut_ptr() };

/// Fill field size and compute the tar header checksum.
/// Grouping these functions together enables inlining the contents here.
#[inline(never)]
unsafe fn set_tar_header_size_cksum(tar_header: *mut u8, size: u32) {
    // Set the size field of the tar header
    // Use tar_header[124..136] is base-256 mode (big endian, high bit set)
    //
    // Compute the checksum considering it currently holds 8 \x20.
    // Do not modify the field and offset the sum by 8 * 0x20 = 0x100.
    // This enables keeping all nul bytes including the ending \0 too.
    //
    // Moreover, compute the checksum only on the first 256 bytes, as the 256 other ones are never set.
    unsafe {
        #[cfg(target_arch = "x86")]
        {
            core::arch::asm!(
                "push esi",
                "add ecx, 124",
                "mov byte ptr [ecx], 0x80",
                "bswap edx",
                "mov dword ptr [ecx + 8], edx",
                "lea esi, [ecx - 124]",
                "xor edx, edx",
                "xor ecx, ecx",

                // Compute the checksum
                "xor eax, eax",
                "mov dh, 1", // cksum = 0x100
                "mov ch, 1", // count ecx = 256
                "3:",
                "lodsb al, byte ptr [esi]",
                "add edx, eax",
                "loop 3b",

                // Write the checksum in octal to
                // [148..156] char chksum[8];
                // In practice, the checksum cannot be larger than 5 octal digits
                "mov cl, 5",
                "4:",
                "mov eax, edx",
                "and al, 7",
                "or al, 0x30",
                // Write the octal checksum at tar_header + rcx + 147
                // esi is currently tar_header + 256, so subtract by 109.
                "mov byte ptr [esi + ecx - 109], al",
                "shr edx, 3",
                "loop 4b",
                "pop esi",
                inout("ecx") tar_header=> _,
                inout("edx") size => _,
                out("eax") _,
            )
        }
        #[cfg(target_arch = "x86_64")]
        {
            core::arch::asm!(
                "mov cl, 11",
                "2:",
                "mov eax, edx",
                "and al, 7",
                "or al, 0x30",
                "mov byte ptr [rsi + rcx + 123], al",
                "shr edx, 3",
                "loop 2b",
                // Compute the checksum
                "xor eax, eax",
                "mov dh, 1", // cksum = 0x100
                "mov ch, 1", // count ecx = 256
                "3:",
                "lodsb al, byte ptr [rsi]",
                "add edx, eax",
                "loop 3b",
                "mov cl, 5",
                "4:",
                "mov eax, edx",
                "and al, 7",
                "or al, 0x30",
                // "mov byte ptr [{tar_header} + rcx + 147], al",
                // ... with esi = tar_header + 256
                "mov byte ptr [rsi + rcx - 109], al",
                "shr edx, 3",
                "loop 4b",
                inout("rsi") tar_header => _,
                inout("edx") size => _,
                out("rax") _,
                inout("rcx") 0 => _,
                options(nostack)
            )
        }
    }
}

/// Provide a start function when compiling with "none" environment
#[cfg(all(not(test), target_env = ""))]
mod start {
    #[unsafe(naked)]
    #[unsafe(no_mangle)]
    pub extern "C" fn _start() -> ! {
        #[cfg(target_arch = "x86")]
        {
            core::arch::naked_asm!(
                // rsp contains [argc, argv[0], argv[1]...]
                "jmp {main_argv01}",
                main_argv01 = sym super::main_argv01,
            );
        }
        #[cfg(target_arch = "x86_64")]
        {
            core::arch::naked_asm!(
                // rsp contains [argc, argv[0], argv[1]...], pop the arguments
                "pop rax",
                "pop rdi",
                "pop rsi",
                // The stack stays correctly aligned on 16 bytes :)
                "jmp {main_argv01}",
                main_argv01 = sym super::main_argv01,
            );
        }
    }
}

/// Link with a C library which provides a CRT with _start which calls main
/// Do not provide a main when running tests
#[cfg(all(not(test), not(target_env = "")))]
mod with_crt {
    #[link(name = "c")]
    unsafe extern "C" {}

    #[unsafe(no_mangle)]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub extern "C" fn main(_argc: isize, argv: *const *const u8) -> isize {
        let argv0_ptr = unsafe { *argv };
        let argv1_ptr = unsafe { *argv.add(1) };
        super::main_argv01(argv0_ptr, argv1_ptr)
    }
}

/// main function with extracted argv[0] and argv[1]
#[cfg_attr(test, allow(dead_code))]
#[allow(clippy::manual_c_str_literals)]
extern "C" fn main_argv01(argv0_ptr: *const u8, argv1_ptr: *const u8) -> ! {
    global_strings::decompress_strings();

    /*
    if argv1_ptr.is_null() {
        // Use an argument of 64 bytes which abuses JSON format, by default
        argv1_ptr =
            b"latest\",  \n\"Hello\": \"https://www.youtube.com/watch?v=vzKyGv_Pv4s\0".as_ptr();
    }
    */

    if cfg!(feature = "with-debug") {
        if argv1_ptr.is_null() {
            panic!("Missing argument (string of 64 characters)");
        }
        if unsafe { asm_strlen(argv1_ptr) } != 64 {
            panic!("Unexpected argument length");
        }
    }

    let sha256_opfd = sha256::open_linux_sha256();
    if cfg!(feature = "with-debug") && sha256_opfd != 4 {
        panic!("Unexpected SHA256 operation fd!");
    }

    // Create a filesystem layer archive, reading the file directly
    // Use the location in the final archive directly if there is no compression
    let layer_tar_bytes = unsafe { &mut IMAGE_TAR_BYTES[IMAGE_OFFSET_LAYER_CONTENT..] };

    let exe_fd = unsafe { syscall_open(argv0_ptr, 0) };
    if cfg!(feature = "with-debug") && exe_fd != 5 {
        panic!("Unexpected file fd!");
    }

    let program_size = unsafe {
        syscall_read(
            exe_fd,
            layer_tar_bytes.as_mut_ptr().add(512),
            MAX_PROGRAM_SIZE,
        ) as u32
    };
    if cfg!(feature = "with-debug") && program_size as usize == MAX_PROGRAM_SIZE {
        panic!("The program file is too big!");
    }

    // Create a filesystem layer archive
    layer_tar_bytes[0] = b's';
    // Set mode to rx (Read+Execute)
    layer_tar_bytes[100] = b'5';
    unsafe {
        set_tar_header_size_cksum(layer_tar_bytes.as_mut_ptr(), program_size);
    }

    let layer_tar_bytes_size: u32 = 512 + program_size;

    unsafe {
        // [tar layer] Compute the SHA256 of the filesystem layer archive
        sha256::sha256_hex(
            layer_tar_bytes.as_ptr(),
            layer_tar_bytes_size,
            sha256_opfd,
            IMAGE_TAR_BYTES_PTR.add(IMAGE_OFFSET_SHA256_LAYER),
        );

        // [tar layer header] Define the path, the size and compute the checksum
        let end = copy_str!(
            IMAGE_TAR_BYTES_PTR.add(IMAGE_OFFSET_LAYER_HEADER),
            STR_BLOBS_SHA256
        );
        asm_memcpy_const::<64>(end, IMAGE_TAR_BYTES_PTR.add(IMAGE_OFFSET_SHA256_LAYER));
        set_tar_header_size_cksum(
            IMAGE_TAR_BYTES_PTR.add(IMAGE_OFFSET_LAYER_HEADER),
            layer_tar_bytes_size,
        );

        // [config and index.json] Fill the content
        let end = copy_str!(
            IMAGE_TAR_BYTES_PTR.add(IMAGE_OFFSET_INDEX_CONTENT),
            STR_CONFIG_1
        );
        let end = copy_str!(end, STR_DIGEST_SHA256);
        let end = asm_memset_const::<b'1', 64>(end);
        let end = copy_str!(end, STR_CONFIG_2);
        let end = asm_memcpy_const::<64>(end, argv1_ptr);
        copy_str!(end, STR_CONFIG_3);

        // [config and index.json] Compute the SHA256
        sha256::sha256_hex(
            IMAGE_TAR_BYTES_PTR.add(IMAGE_OFFSET_INDEX_CONTENT),
            CONFIG_AND_INDEX_JSON_LEN,
            sha256_opfd,
            IMAGE_TAR_BYTES_PTR.add(IMAGE_OFFSET_SHA256_CONFIG),
        );

        // [tar index.json header] Define the path, the size and compute the checksum
        copy_str!(
            IMAGE_TAR_BYTES_PTR.add(IMAGE_OFFSET_INDEX_HEADER),
            "index.json"
        );
        set_tar_header_size_cksum(
            IMAGE_TAR_BYTES_PTR.add(IMAGE_OFFSET_INDEX_HEADER),
            CONFIG_AND_INDEX_JSON_LEN,
        );

        // [tar config header] Define the path and link to index.json
        let end = copy_str!(
            IMAGE_TAR_BYTES_PTR.add(IMAGE_OFFSET_CONFIG_LINK_HEADER),
            STR_BLOBS_SHA256
        );
        asm_memcpy_const::<64>(end, IMAGE_TAR_BYTES_PTR.add(IMAGE_OFFSET_SHA256_CONFIG));
        // Set typeflag = LNKTYPE = '1 and fill char linkname[100]
        copy_str!(
            IMAGE_TAR_BYTES_PTR.add(IMAGE_OFFSET_CONFIG_LINK_HEADER + 156),
            "1index.json"
        );
        set_tar_header_size_cksum(IMAGE_TAR_BYTES_PTR.add(IMAGE_OFFSET_CONFIG_LINK_HEADER), 0);

        // [manifest] Fill the content
        let end = copy_str!(
            IMAGE_TAR_BYTES_PTR.add(IMAGE_OFFSET_MANIFEST_CONTENT),
            STR_MANIFEST_1
        );
        let end = copy_str!(end, STR_DIGEST_SHA256);
        let end = copy_str!(end.add(64), STR_MANIFEST_2);
        *end.add(64).cast::<u32>() = u32::from_ne_bytes(*b"\"}]}");

        // [tar manifest header] Define the path, the size and compute the checksum
        let end = copy_str!(
            IMAGE_TAR_BYTES_PTR.add(IMAGE_OFFSET_MANIFEST_HEADER),
            STR_BLOBS_SHA256
        );
        asm_memset_const::<b'1', 64>(end);
        set_tar_header_size_cksum(
            IMAGE_TAR_BYTES_PTR.add(IMAGE_OFFSET_MANIFEST_HEADER),
            MANIFEST_LEN,
        );
    }

    let image_tar_size = IMAGE_OFFSET_LAYER_CONTENT as u32 + layer_tar_bytes_size;
    #[cfg(feature = "with-debug")]
    if image_tar_size as u64 > MAX_IMAGE_SIZE as u64 {
        panic!("MAX_IMAGE_SIZE is too small");
    }

    #[cfg(feature = "gzip")]
    {
        gzip::write_image_gzip(image_tar_size)
    }

    #[cfg(feature = "zstd")]
    {
        zstd::write_image_zstd(image_tar_size)
    }

    #[cfg(not(any(feature = "gzip", feature = "zstd")))]
    {
        unsafe { syscall_write_all(1, IMAGE_TAR_BYTES_PTR, image_tar_size) };
        syscall_exit(0)
    }
}
