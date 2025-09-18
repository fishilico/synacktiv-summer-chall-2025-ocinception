#![allow(unexpected_cfgs)] // Allow using #[cfg(target_env = "optim")]
#![feature(concat_bytes)] // https://github.com/rust-lang/rust/issues/87555
#![feature(fn_align)] // https://github.com/rust-lang/rust/issues/82232
#![no_std]
#![cfg_attr(not(test), no_main)]
use core::{assert, concat_bytes};

#[cfg(feature = "gzip")]
mod gzip;
#[cfg(feature = "use-alloc")]
mod nostd_bump_alloc;

#[cfg(not(target_arch = "x86"))]
core::compile_error!("requires --target i686-... (x86 arch)");

#[cfg(not(any(test, target_env = "", target_env = "optim")))]
core::compile_error!("requires --target i686-unknown-none.json or i686-unknown-optim.json");

const IMAGE_OFFSET_INDEX_HEADER: usize = 0;
const IMAGE_OFFSET_INDEX_CONTENT: usize = IMAGE_OFFSET_INDEX_HEADER + 512;
const IMAGE_OFFSET_CONFIG_LINK_HEADER: usize = IMAGE_OFFSET_INDEX_CONTENT + 512;
const IMAGE_OFFSET_MANIFEST_HEADER: usize = IMAGE_OFFSET_CONFIG_LINK_HEADER + 512;
const IMAGE_OFFSET_MANIFEST_CONTENT: usize = IMAGE_OFFSET_MANIFEST_HEADER + 512;
const IMAGE_OFFSET_LAYER_HEADER: usize = IMAGE_OFFSET_MANIFEST_CONTENT + 512;
const IMAGE_OFFSET_LAYER_CONTENT: usize = IMAGE_OFFSET_LAYER_HEADER + 512;

const _: () = assert!(IMAGE_OFFSET_LAYER_CONTENT == 3072);

const SHA256_OPFD: u32 = 4;

const IMAGE_OFFSET_SHA256_CONFIG: usize = IMAGE_OFFSET_MANIFEST_CONTENT + 101;
const IMAGE_OFFSET_SHA256_LAYER: usize = IMAGE_OFFSET_MANIFEST_CONTENT + 206;

const STRINGS: [u8; 13 + 11 + 84 + 24 + 17 + 5 + 46 + 59 + 5] = *concat_bytes!(
    // Path in OCI images
    b"blobs/sha256/",
    // Set tar header typeflag = LNKTYPE = '1 and fill char linkname[100]
    b"1index.json",
    // Craft an image manifest file
    // https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md
    b"{\"schemaversion\":2,\"config\":{\"mediatype\":\"application/vnd.oci.image.config.v1+json\",",
    b"\",\"size\":-1},\"layers\":[{",
    // Reuse '"digest": "sha256:' in several places
    b"\"digest\":\"sha256:",
    // AF_ALG = 38 = '&' and constant for sockaddr_alg
    b"&hash",
    // Craft an image configuration file mixed with index.json
    // https://github.com/opencontainers/image-spec/blob/v1.1.1/config.md
    // https://github.com/opencontainers/image-spec/blob/v1.1.1/image-layout.md#indexjson-file
    b"{\"config\":{\"entrypoint\":[\"/s\"]},\"manifests\":[{",
    b"\",\"annotations\":{\"io.containerd.image.name\":\"ocinception_3:",
    b"\"}}]}",
);

const MANIFEST_END: u32 = u32::from_ne_bytes(*b"\"}]}");
const MANIFEST_LEN: usize = 274;
const CONFIG_AND_INDEX_JSON_LEN: u32 = 269 - 14;
const STRING_OFFSET_BLOBS_SHA256: usize = 0;
const STRING_OFFSET_1INDEX_JSON: usize = STRING_OFFSET_BLOBS_SHA256 + 13;
const STRING_OFFSET_MANIFEST_1: usize = STRING_OFFSET_1INDEX_JSON + 11;
const STRING_OFFSET_MANIFEST_2: usize = STRING_OFFSET_MANIFEST_1 + 84;
const STRING_OFFSET_DIGEST_SHA256: usize = STRING_OFFSET_MANIFEST_2 + 24;
const STRING_OFFSET_ALG_SOCKET: usize = STRING_OFFSET_DIGEST_SHA256 + 17;
const STRING_OFFSET_CONFIG_1: usize = STRING_OFFSET_ALG_SOCKET + 5;
const STRING_OFFSET_CONFIG_2: usize = STRING_OFFSET_CONFIG_1 + 46;
const STRING_OFFSET_CONFIG_3: usize = STRING_OFFSET_CONFIG_2 + 59;
const _: () = assert!(STRING_OFFSET_CONFIG_3 + 5 == STRINGS.len());

const STRING_OFFSET_INDEX_JSON: usize = STRING_OFFSET_1INDEX_JSON + 1;
const STRING_OFFSET_SHA256: usize = STRING_OFFSET_DIGEST_SHA256 + 10;

/// Compress the strings using a custom base64 alphabet
const fn compress_strings() -> [u8; 198] {
    const ALPHABET: [u8; 61] = *b"!\"#$%&\'()*+,-./0123456789:[\\]^_`abcdefghijklmnopqrstuvwxyz{|}";

    /// Decompress a 6-bit symbol
    const fn decompress_symbol(sym: u8) -> u8 {
        if sym < 0x1a { sym + 0x21 } else { sym + 0x41 }
    }

    /// Compress an 8-bit character to a 6-bit symbol
    const fn compress_char(c: u8) -> u8 {
        if c < b'[' { c - b'!' } else { c - b'[' + 0x1a }
    }

    // Check the alphabet
    let mut sym = 0u8;
    while sym < 61 {
        let c = decompress_symbol(sym);
        assert!(ALPHABET[sym as usize] == c, "mismatched alphabet");
        assert!(compress_char(c) == sym, "invalid compressor helper");
        sym += 1;
    }

    // Compress 4 characters into 4 6-bit symbols, packed into 3 bytes
    // The last symbol is 0, and it is actually aligned.
    // (and packs are not truncated.)
    let mut compressed = [0u8; 198];
    assert!(
        STRINGS.len().div_ceil(4) * 3 == compressed.len(),
        "mismatched lengths"
    );
    let mut pos = 0usize;
    while pos < STRINGS.len() / 4 {
        let sym0 = compress_char(STRINGS[4 * pos]);
        let sym1 = compress_char(STRINGS[4 * pos + 1]);
        let sym2 = compress_char(STRINGS[4 * pos + 2]);
        let sym3 = compress_char(STRINGS[4 * pos + 3]);
        // Swap the bytes to make the decompressor shorter
        compressed[3 * pos] = sym3 | (sym2 << 6);
        compressed[3 * pos + 1] = (sym2 >> 2) | (sym1 << 4);
        compressed[3 * pos + 2] = (sym1 >> 4) | (sym0 << 2);
        pos += 1;
    }

    // No character remains to be compressed, and some zero symbols are added in .bss
    assert!(4 * pos == STRINGS.len(), "unexpected STRINGS length");
    assert!(3 * pos == compressed.len(), "unexpected compressed length");
    compressed
}

#[unsafe(no_mangle)]
static COMPRESSED_STRINGS: [u8; 198] = compress_strings();

// Import symbols
unsafe extern "C" {
    //#[link_name = "__executable_start"]
    //static SYMBOL_EXECUTABLE_START: [u8; 0];
    #[link_name = "file_size"]
    static SYMBOL_FILE_SIZE: [u8; 0];
    #[link_name = "offset_set_tar_header_size_cksum"]
    static SYMBOL_OFFSET_SET_TAR_HEADER_SIZE_CKSUM: [u8; 0];
    #[link_name = "decompressed_strings"]
    static DECOMPRESSED_STRINGS: [u8; 278];
    #[link_name = "buffer_image_tar_bytes"]
    static mut IMAGE_TAR_BYTES: [u8; 0];
    #[cfg(not(all(feature = "gzip", not(feature = "with-debug"))))]
    #[link_name = "buffer_image_tar_bytes_end"]
    static mut IMAGE_TAR_BYTES_END: [u8; 0];
    #[link_name = "buffer_image_compressed"]
    static mut IMAGE_COMPRESSED: [u8; 0];
    #[cfg(not(feature = "gzip"))]
    #[link_name = "zstd_last_raw_block_header"]
    static ZSTD_LAST_RAW_BLOCK_HEADER: [u8; 0];
}

/// System call numbers used on Linux x86 32-bit architecture
mod linux_syscalls {
    #[cfg(not(test))]
    pub const NR_EXIT: u32 = 1;
    pub const NR_READ: u32 = 3;
    pub const NR_WRITE: u32 = 4;
    pub const NR_SOCKET: u32 = 359;
    pub const NR_BIND: u32 = 361;
    pub const NR_ACCEPT4: u32 = 364;
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") linux_syscalls::NR_EXIT,
            in("ebx") 1,
            options(nomem, noreturn, nostack, preserves_flags)
        );
    }
}

// ELF headers
// The ELF header (Ehdr) and the program header (Phdr) are interleaved in a way similar as
// https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html
#[cfg(target_env = "optim")]
core::arch::global_asm!(
    ".pushsection .headers, \"ax\"",
    ".align 0",
    "ELF_ehdr:",
    ".int 0x464c457f",           // Elf32_Ehdr.e_ident[EI_MAG0..3] = ELF magic
    /*
    ".byte 0",                   // Elf32_Ehdr.e_ident[EI_CLASS] = 0, should be ELFCLASS32=1
    ".byte 0",                   // Elf32_Ehdr.e_ident[EI_DATA] = 0, should be ELFDATA2LSB=1
    ".byte 0",                   // Elf32_Ehdr.e_ident[EI_VERSION] = 0, should be 1
    ".byte 0",                   // Elf32_Ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE
    ".byte 0",                   // Elf32_Ehdr.e_ident[EI_ABIVERSION] = 0, should be 1
    ".byte 0, 0, 0, 0, 0, 0, 0", // Elf32_Ehdr padding (7 bytes)
    */
    "_start:",
    "mov esi, OFFSET {COMPRESSED_STRINGS}",
    "mov edi, OFFSET {STRINGS}",
    ".byte 0xeb, {real_start} - . - 1", // jmp {real_start}
    ".short 2",                  // Elf32_Ehdr.e_type = ET_EXEC
    ".short 3",                  // Elf32_Ehdr.e_machine = EM_386
    ".int 1",                    // Elf32_Ehdr.e_version = 1
    ".int _start",               // Elf32_Ehdr.e_entry
    ".int ELF_phdr - ELF_ehdr",  // Elf32_Ehdr.e_phoff
    ".int 0",                    // Elf32_Ehdr.e_shoff
    ".int 0",                    // Elf32_Ehdr.e_flags
    ".short ELF_ehdr_size",      // Elf32_Ehdr.e_ehsize
    ".short ELF_phdr_size",      // Elf32_Ehdr.e_phentsize
    "ELF_phdr:",
    ".short 1", // Elf32_Ehdr.e_phnum = 1, Elf32_Phdr.p_type = PT_LOAD
    ".short 0", // Elf32_Ehdr.e_shentsize
    ".short 0", // Elf32_Ehdr.e_shnum, Elf32_Phdr.p_offset = 0
    ".short 0", // Elf32_Ehdr.e_shstrndx
    "ELF_ehdr_size = . - ELF_ehdr", // -- end of Elf32_Ehdr --
    ".int __executable_start", // Elf32_Phdr.p_vaddr
    ".int __executable_start", // Elf32_Phdr.p_paddr
    ".int file_size", // Elf32_Phdr.p_filesz
    ".int file_memory_size", // Elf32_Phdr.p_memsz
    //".int 7",   // Elf32_Phdr.p_flags = PF_R | PR_W | PF_X
    //".int 1",   // Elf32_Phdr.p_align = 1
    ".byte 7",
    //".byte 0, 0, 0, 0, 0, 0", // Skip unneeded zeros
    "ELF_phdr_size = . - ELF_phdr + 7",
    ".popsection",
    COMPRESSED_STRINGS = sym COMPRESSED_STRINGS,
    STRINGS = sym DECOMPRESSED_STRINGS,
    real_start = sym real_start,
);

#[cfg(target_env = "")]
core::arch::global_asm!(
    // Extract the code present in the custom ELF header
    ".pushsection .text.start, \"ax\"",
    ".global _start",
    "_start:",
    "mov esi, OFFSET {COMPRESSED_STRINGS}",
    "mov edi, OFFSET {STRINGS}",
    //"jmp {real_start}", // Fall through _start
    ".size _start, . - _start",
    ".popsection",
    COMPRESSED_STRINGS = sym COMPRESSED_STRINGS,
    STRINGS = sym DECOMPRESSED_STRINGS,
    //real_start = sym real_start,
);

// Constants to compute the size of the ZSTD data, from the file size (computed in the linker script)
#[cfg(all(not(test), not(feature = "gzip"), target_env = "optim"))]
const DIFF_ZSTD_SIZE_FILE_SIZE: u32 = 0x368 - 15;
#[cfg(all(not(test), not(feature = "gzip"), target_env = ""))]
const DIFF_ZSTD_SIZE_FILE_SIZE: u32 = 0x35c - 15; // More fields in ELF header get compressed
#[cfg(all(test, not(feature = "gzip")))]
const DIFF_ZSTD_SIZE_FILE_SIZE: u32 = 0; // Use an invalid field for test

/// Fill field size and compute the tar header checksum.
/// Grouping these functions together enables inlining the contents here.
///
/// Calling convention:
/// - esi = tar_header
/// - eax = size
/// - ecx = 0
///
/// Return:
/// - eax contains a byte (eax <= 0xff)
/// - ecx = 0
/// - edx = 0
/// - esi contains trash (tar_header + 256)
#[unsafe(link_section = ".text.set_tar_header_size_cksum")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[rustc_align(1)]
unsafe extern "fastcall" fn set_tar_header_size_cksum(tar_header: *mut u8, size: u32) {
    // Set the size field of the tar header
    // Use tar_header[124..136] in base-256 mode (big endian, high bit set)
    //
    // Compute the checksum considering it currently holds 8 \x20.
    // Do not modify the field and offset the sum by 8 * 0x20 = 0x100.
    // This enables keeping all nul bytes including the ending \0 too.
    //
    // Moreover, compute the checksum only on the first 256 bytes, as the 256 other ones are never set.
    // And as the checksum never exceeds 0o77777, use only 5 octal characters.
    core::arch::naked_asm!(
        // Write the size at tar_header[124..136]
        "push esi",
        "add esi, 124",
        "mov byte ptr [esi], 0x80",
        "bswap eax",
        "mov dword ptr [esi + 8], eax",
        "pop esi",
        // Define a shortcut
        ".global set_tar_header_cksum_nosize",
        "set_tar_header_cksum_nosize:",
        // Compute the checksum
        //"xor ecx, ecx", // ecx is supposed to be 0 when calling this function
        "mul ecx", // Set eax = edx = 0
        "inc dh",  // Set cksum: edx = 0x100
        "inc ch",  // Set count: ecx = 256
        "3:",
        "lodsb al, byte ptr [esi]",
        "add edx, eax",
        "loop 3b",
        // Write the checksum in octal to
        // [148..156] char chksum[8]
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
        "ret",
    )
}

/// Compute a SHA256 hash using Linux crypto userspace API
/// https://www.kernel.org/doc/html/v6.16/crypto/userspace-if.html
/// And format it in hexadecimal at the given pointer
/// This function is optimized for x86 fastcall (args in ecx, edx and stack)
///
/// Calling convention:
/// - ecx = data
/// - edx = size
/// - edi = hex_digest_ptr (should be [esp + 4] but abuse asm call)
///
/// Return:
/// - eax = 0
/// - ebx contains a 8-bit value (ebx = SHA256_OPFD = 4)
/// - ecx = 0
/// - edx = 0
/// - esi contains trash (end of SHA256_DIGEST)
/// - edi contains trash (end of hex_digest_ptr)
#[unsafe(link_section = ".text.sha256_hex")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[rustc_align(1)]
unsafe extern "fastcall" fn sha256_hex(data: *const u8, size: u32, hex_digest_ptr: *mut u8) {
    const _: () = assert!(linux_syscalls::NR_WRITE == SHA256_OPFD);
    core::arch::naked_asm!(
        // Write the data: ebx = opfd, ecx = data, edx = size
        "push {NR_WRITE}",
        "pop eax",
        "mov ebx, eax", // The SHA256 operation fd is 4, which is NR_write
        "int 0x80",

        // Read the data: ebx = opfd, ecx = buffer, edx = size
        "push {NR_READ}",
        "pop eax",
        "lea ecx, [esp - 0x20]",
        "push 0x20",
        "pop edx",
        "int 0x80",

        // Convert to hexadecimal
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
        "ret",
        //SHA256_OPFD = const SHA256_OPFD,
        NR_WRITE = const linux_syscalls::NR_WRITE,
        NR_READ = const linux_syscalls::NR_READ,
    )
}

#[unsafe(link_section = ".text.real_start")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[rustc_align(1)]
pub extern "C" fn real_start() -> ! {
    core::arch::naked_asm!(
        // Decompress the strings using an algorithm similar as base64-encode
        // https://codegolf.stackexchange.com/questions/26584/convert-a-bytes-array-to-base64/158039#158039
        //"mov esi, OFFSET {COMPRESSED_STRINGS}", // moved to _start
        //"mov edi, OFFSET {STRINGS}",
        "2:",
        // Load 3 bytes from the compressed strings
        "dec esi",
        "lodsd eax, dword ptr [esi]",
        // Decode symbols
        "mov cl, 4",
        "3:",
        "rol eax, 6",
        "and al, 0x3f",
        "jz 4f", // symbol 0 encodes the end of stream
        "cmp al, 0x1a",
        "jc 5f",
        "add al, 0x20",
        "5:",
        "add al, 0x21",
        "stosb byte ptr es:[edi], al",
        "loop 3b",
        // Go to the next 3 bytes
        "jmp 2b",
        "4:",

        // Here:
        // - eax contains garbage (last decompressed characters) with al = 0
        // - ecx <= 4 (counter)
        // - esi = end of COMPRESSED_STRINGS in .rodata (start of .bss)
        // - edi = end of STRINGS in .bss
        // - ebx = edx = ebp = 0 (initial values)

        // Create a socket to compute SHA256 hashes using Linux crypto userspace API
        // https://www.kernel.org/doc/html/v6.16/crypto/userspace-if.html
        // Set sockaddr_alg.salg_name = "sha256"
        "connect_crypto_sha256:",
        "lea edi, [esp - {SOCKADDR_ALG_LEN} + 24]",
        "mov esi, OFFSET {STRINGS} + {STRING_OFFSET_SHA256}",
        "movsd dword ptr es:[edi], dword ptr [esi]",
        "movsw word ptr es:[edi], word ptr [esi]",
        // Set sockaddr_alg.sa_family = AF_ALG
        "inc esi",
        "sub edi, 30",
        "movsb byte ptr es:[edi], byte ptr [esi]",
        // Set sockaddr_alg.salg_type = "hash"
        "inc edi",
        "movsd dword ptr es:[edi], dword ptr [esi]",

        // Create a transformation socket to AF_ALF
        "mov eax, {NR_SOCKET}",
        //"xor ebx, ebx", // ebx is zero when the program starts
        "mov bl, {AF_ALG}",
        "mov cl, {SOCK_SEQPACKET}", // ecx is zero when the program starts
        //"xor edx, edx", // edx is zero when the program starts
        "int 0x80", // eax = tfmfd
        // Bind the socket to SHA256
        "mov ebx, eax", // ebx = tfmfd
        "lea ecx, [edi - 6]", // ecx = &sockaddr_alg
        "push {SOCKADDR_ALG_LEN}",
        "pop edx", // edx = sizeof(sockaddr_alg)
        "mov ax, {NR_BIND}",
        "int 0x80",
        // Get the operation socket: accept(ebx=tfmfd, ecx=0, edx=0, esi=0)
        "xor ecx, ecx",
        "xor esi, esi",
        "mul ecx", // eax = edx = 0
        "mov ax, {NR_ACCEPT4}",
        "int 0x80",

        // Save a pointer to set_tar_header_size_cksum in ebp
        "create_filesystem:",
        "mov ebp, OFFSET {set_tar_header_size_cksum}",

        // Craft a tar header for the filesystem layer
        // cf. tar header specification: https://www.gnu.org/software/tar/manual/html_node/Standard.html
        "mov esi, OFFSET {IMAGE_TAR_BYTES} + {IMAGE_OFFSET_LAYER_CONTENT}",
        "push esi", // Save for SHA256
        "mov byte ptr [esi], {CHAR_s}", // File name 's'
        "mov byte ptr [esi + 100], {CHAR_5}", // Permissions '5' (read|execute)
        "mov ax, OFFSET {FILE_SIZE}", // Optimization: eax was 4, file_size fits 16 bits
        "call ebp", // Call set_tar_header_size_cksum

        // Copy the program to the layer tar content
        //"mov esi, OFFSET {SYMBOL_EXECUTABLE_START}",
        //"lea esi, [ebp - {OFFSET_SET_TAR_HEADER_SIZE_CKSUM}]", // LLVM linker bug: - gets converter to +
        // Work around this bug by directly encoding "8d 75 8c lea esi,[ebp-0x74]"
        ".byte 0x8d, 0x75, {OFFSET_SET_TAR_HEADER_SIZE_CKSUM}",
        "mov edi, OFFSET {IMAGE_TAR_BYTES} + {IMAGE_OFFSET_LAYER_CONTENT} + 512",
        "mov cx, OFFSET {FILE_SIZE}", // Optimization: ecx was 0, file_size fits 16 bits
        "rep movsb byte ptr es:[edi], byte ptr [esi]",

        // [tar layer] Compute the SHA256 of the filesystem layer archive
        "pop ecx", // Restore {IMAGE_TAR_BYTES} + {IMAGE_OFFSET_LAYER_CONTENT}
        "mov dx, OFFSET {FILE_SIZE} + 512", // Optimization: edx was 0, file_size fits 16 bits
        "push edx", // Save for checksum
        "mov edi, OFFSET {IMAGE_TAR_BYTES} + {IMAGE_OFFSET_SHA256_LAYER}",
        "push edi", // Save for path
        "call {sha256_hex}",

        // [tar layer header] Define the path
        "create_image:",
        "mov edi, OFFSET {IMAGE_TAR_BYTES} + {IMAGE_OFFSET_LAYER_HEADER}",
        //"add di, {IMAGE_OFFSET_LAYER_HEADER} - ({IMAGE_OFFSET_SHA256_LAYER} + 64)", // This possible optimization also gets encoded as 5 bytes (66 81 c7 f2 00)
        "push edi", // Save for checksum
        "mov esi, OFFSET {STRINGS} + {STRING_OFFSET_BLOBS_SHA256}",
        "mov cl, 13",
        "rep movsb byte ptr es:[edi], byte ptr [esi]",
        "pop eax", // (keep value pushed for checksum)
        "pop esi", // Restore {IMAGE_TAR_BYTES} + {IMAGE_OFFSET_SHA256_LAYER}
        "push eax",
        "mov cl, 64",
        "rep movsb byte ptr es:[edi], byte ptr [esi]",

        // [tar layer header] Define the size and compute the checksum
        "pop esi", // Restore {IMAGE_TAR_BYTES} + {IMAGE_OFFSET_LAYER_HEADER}
        "pop eax", // Restore {SYMBOL_FILE_SIZE} + 512
        "call ebp", // Call set_tar_header_size_cksum

        // [index.json] Fill the content
        "mov edi, OFFSET {IMAGE_TAR_BYTES} + {IMAGE_OFFSET_INDEX_CONTENT}",
        "push edi", // Save for SHA256
        "mov esi, OFFSET {STRINGS} + {STRING_OFFSET_CONFIG_1}",
        "mov cl, 46",
        "rep movsb byte ptr es:[edi], byte ptr [esi]",
        // Copy "\"digest\":\"sha256:"
        "push esi",
        "add esi, {STRING_OFFSET_DIGEST_SHA256} - {STRING_OFFSET_CONFIG_2}",
        "mov cl, 17",
        "rep movsb byte ptr es:[edi], byte ptr [esi]",
        "pop esi",
        // Copy the manifest digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        "mov al, 0x61", // 'a'
        "mov cl, 64",
        "rep stosb byte ptr es:[edi], al",
        // Continue the JSON
        "mov cl, 59",
        "rep movsb byte ptr es:[edi], byte ptr [esi]",
        // Copy the tag from argv[1]
        "push esi",
        "mov esi, dword ptr [esp + 0x10]",
        "mov cl, 64",
        "rep movsb byte ptr es:[edi], byte ptr [esi]",
        "pop esi",
        // End the JSON
        "movsd dword ptr es:[edi], dword ptr [esi]",
        "movsb byte ptr es:[edi], byte ptr [esi]",

        // [index.json] Compute SHA256
        "pop ecx", // Restore the pointer to index.json content
        "mov edi, OFFSET {IMAGE_TAR_BYTES} + {IMAGE_OFFSET_SHA256_CONFIG}",
        "push edi", // Save for tar config header
        "mov dx, {CONFIG_AND_INDEX_JSON_LEN}", // edx was 0 since a previous call to sha256_hex
        "push edx", // Save for checksum
        "call {sha256_hex}",

        // [tar index.json header] Define the path
        //"mov edi, OFFSET {IMAGE_TAR_BYTES} + {IMAGE_OFFSET_INDEX_HEADER}",
        "xor di, di", // Optimization: IMAGE_TAR_BYTES is aligned on 0x10000
        "push edi", // Save for checksum
        "mov esi, OFFSET {STRINGS} + {STRING_OFFSET_INDEX_JSON}",
        "mov cl, 10",
        "rep movsb byte ptr es:[edi], byte ptr [esi]",

        // [tar index.json header] Define the size and compute the checksum
        "pop esi", // Restore {IMAGE_TAR_BYTES} + {IMAGE_OFFSET_INDEX_HEADER}
        "pop eax", // Restore {CONFIG_AND_INDEX_JSON_LEN}"
        "call ebp", // Call set_tar_header_size_cksum

        // [tar config header] Define the path and link
        "mov edi, OFFSET {IMAGE_TAR_BYTES} + {IMAGE_OFFSET_CONFIG_LINK_HEADER}",
        "mov ebx, edi", // Save for checksum
        "mov esi, OFFSET {STRINGS} + {STRING_OFFSET_BLOBS_SHA256}",
        "mov cl, 13",
        "rep movsb byte ptr es:[edi], byte ptr [esi]",
        "pop esi", // Restore {IMAGE_TAR_BYTES} + {IMAGE_OFFSET_SHA256_CONFIG}
        "mov cl, 64",
        "rep movsb byte ptr es:[edi], byte ptr [esi]",
        "add edi, 79", // go to tar header offset 156
        "mov esi, OFFSET {STRINGS} + {STRING_OFFSET_1INDEX_JSON}",
        "mov cl, 11",
        "rep movsb byte ptr es:[edi], byte ptr [esi]",

        // [tar config header] Compute the checksum
        // Adjust the pointer to set_tar_header_cksum_nosize to skip defining the size
        "mov esi, ebx", // Restore {IMAGE_TAR_BYTES} + {IMAGE_OFFSET_CONFIG_LINK_HEADER}
        "call set_tar_header_cksum_nosize", // Call the shortcut

        // [manifest] Fill the content
        "mov edi, OFFSET {IMAGE_TAR_BYTES} + {IMAGE_OFFSET_MANIFEST_CONTENT}",
        "mov esi, OFFSET {STRINGS} + {STRING_OFFSET_MANIFEST_1}",
        "mov cl, 84",
        "rep movsb byte ptr es:[edi], byte ptr [esi]",
        "push esi",
        "add esi, {STRING_OFFSET_DIGEST_SHA256} - {STRING_OFFSET_MANIFEST_2}",
        "mov cl, 17",
        "rep movsb byte ptr es:[edi], byte ptr [esi]",
        "pop esi",

        // Skip the config digest and continue copying the template
        "add edi, 64",
        "mov cl, 41",
        "rep movsb byte ptr es:[edi], byte ptr [esi]",
        "mov dword ptr [edi + 64], {MANIFEST_END}",

        // [tar manifest header] Define the path as "blobs/sha256/aaaaa..."
        "mov edi, OFFSET {IMAGE_TAR_BYTES} + {IMAGE_OFFSET_MANIFEST_HEADER}",
        "push edi", // Save for checksum
        "mov esi, OFFSET {STRINGS} + {STRING_OFFSET_BLOBS_SHA256}",
        "mov cl, 13",
        "rep movsb byte ptr es:[edi], byte ptr [esi]",
        "mov al, {CHAR_a}",
        "mov cl, 64",
        "rep stosb byte ptr es:[edi], al",

        // [tar manifest header] Define the size and compute the checksum
        "pop esi", // Restore {IMAGE_TAR_BYTES} + {IMAGE_OFFSET_MANIFEST_HEADER}
        "mov ax, {MANIFEST_LEN}", // eax contained a byte before
        "call ebp", // Call set_tar_header_size_cksum

        // Falls through compression function

        //COMPRESSED_STRINGS = sym COMPRESSED_STRINGS,
        IMAGE_TAR_BYTES = sym IMAGE_TAR_BYTES,
        STRINGS = sym DECOMPRESSED_STRINGS,
        //SYMBOL_EXECUTABLE_START = sym SYMBOL_EXECUTABLE_START,
        OFFSET_SET_TAR_HEADER_SIZE_CKSUM = sym SYMBOL_OFFSET_SET_TAR_HEADER_SIZE_CKSUM,
        FILE_SIZE = sym SYMBOL_FILE_SIZE,
        set_tar_header_size_cksum = sym set_tar_header_size_cksum,
        sha256_hex = sym sha256_hex,

        // IMAGE_OFFSET_INDEX_HEADER = const IMAGE_OFFSET_INDEX_HEADER,
        IMAGE_OFFSET_INDEX_CONTENT = const IMAGE_OFFSET_INDEX_CONTENT,
        IMAGE_OFFSET_CONFIG_LINK_HEADER = const IMAGE_OFFSET_CONFIG_LINK_HEADER,
        IMAGE_OFFSET_MANIFEST_HEADER = const IMAGE_OFFSET_MANIFEST_HEADER,
        IMAGE_OFFSET_MANIFEST_CONTENT = const IMAGE_OFFSET_MANIFEST_CONTENT,
        IMAGE_OFFSET_LAYER_HEADER = const IMAGE_OFFSET_LAYER_HEADER,
        IMAGE_OFFSET_LAYER_CONTENT = const IMAGE_OFFSET_LAYER_CONTENT,
        IMAGE_OFFSET_SHA256_CONFIG = const IMAGE_OFFSET_SHA256_CONFIG,
        IMAGE_OFFSET_SHA256_LAYER = const IMAGE_OFFSET_SHA256_LAYER,
        CONFIG_AND_INDEX_JSON_LEN = const CONFIG_AND_INDEX_JSON_LEN,
        STRING_OFFSET_BLOBS_SHA256 = const STRING_OFFSET_BLOBS_SHA256,
        STRING_OFFSET_1INDEX_JSON = const STRING_OFFSET_1INDEX_JSON,
        STRING_OFFSET_MANIFEST_1 = const STRING_OFFSET_MANIFEST_1,
        STRING_OFFSET_MANIFEST_2 = const STRING_OFFSET_MANIFEST_2,
        STRING_OFFSET_DIGEST_SHA256 = const STRING_OFFSET_DIGEST_SHA256,
        STRING_OFFSET_CONFIG_1 = const STRING_OFFSET_CONFIG_1,
        STRING_OFFSET_CONFIG_2 = const STRING_OFFSET_CONFIG_2,
        STRING_OFFSET_INDEX_JSON = const STRING_OFFSET_INDEX_JSON,
        STRING_OFFSET_SHA256 = const STRING_OFFSET_SHA256,

        AF_ALG = const 38,
        NR_ACCEPT4 = const linux_syscalls::NR_ACCEPT4,
        NR_BIND = const linux_syscalls::NR_BIND,
        NR_SOCKET = const linux_syscalls::NR_SOCKET,
        SOCK_SEQPACKET = const 5,
        SOCKADDR_ALG_LEN = const 88,
        MANIFEST_END = const MANIFEST_END,
        MANIFEST_LEN = const MANIFEST_LEN,

        CHAR_5 = const b'5',
        CHAR_a = const b'a',
        CHAR_s = const b's',
    )
}

/// Compress the image using Zstandard Compression, https://datatracker.ietf.org/doc/html/rfc8878
/// Use only Run-Length Encoding (RLE) blocks to compress repeated bytes.
///
/// Registers input:
/// - eax contains a byte (eax <= 0xff)
/// - ebx = {IMAGE_TAR_BYTES} + {IMAGE_OFFSET_CONFIG_LINK_HEADER}
/// - ecx = 0
/// - edx = 0
/// - esi is a pointer in the tar header of the manifest file (+256)
/// - edi is a pointer in the tar header of the manifest file (end of path)
/// - ebp is a pointer to function set_tar_header_size_cksum
///
/// Registers allocation:
/// - edi is a pointer to the source data to be compressed
/// - eax contains the current source bytes
/// - ecx is a counter used in RLE
/// - esi is a pointer to the 3-byte header of a RAW block in the output compressed stream
/// - ebp counts the number of bytes in the current RAW block
/// - edx counted the size of the compressed output, but is now zero
#[cfg(not(feature = "gzip"))]
#[unsafe(link_section = ".text.compress_image")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[rustc_align(1)]
pub extern "C" fn compress_zstd() -> ! {
    core::arch::naked_asm!(
        //"mov edi, OFFSET {IMAGE_TAR_BYTES}",
        "xor di, di", // Optimization: clean 16 low bits, because IMAGE_TAR_BYTES is aligned
        "mov esi, OFFSET {IMAGE_COMPRESSED} + 6", // Skip 6-byte ZSTD header
        "xor ebp, ebp",
        //"push 9",
        //"pop edx",

        // [zstd] Detect 8 repeated bytes to trigger RLE compression
        "2:",
        "mov eax, dword ptr [edi]",
        "inc edi", // Proactively increment edi
        "cmp eax, dword ptr [edi]",
        "jne 3f",
        // Optimization: there is no sequence of 6, 7, 8 bytes, so detecting 5 bytes is enough
        //"cmp eax, dword ptr [edi + 3]",
        //"jne 3f",

        // [zstd] Write the header of the previous RAW block: 3 bytes (block_size << 3)
        // Assume the most significant byte is zero (no large raw regions)
        "mov ecx, ebp", // Save size of current RAW block
        "shl ebp, 3",
        "je 4f",
        "add dword ptr [esi], ebp", // Do not mov as this would overwrite RAW data
        "add esi, ecx", // Use saved size
        "xor ebp, ebp",
        "4:",

        // [zstd] Compute the number of times the byte is repeated
        "xor ecx, ecx",
        "dec ecx",
        "repe scasb al, byte ptr es:[edi]",
        "dec edi",
        // Here, ecx = -2 - (repeat_count - 1), because edi was proactively incremented
        "not ecx", // ecx = repeat_count

        // [zstd] Create a header for the RLE block: 3 bytes + repeated byte
        // 32-bit header value is (repeat_count << 3) | 2 | (byte << 24)
        "shl eax, 24",
        "lea eax, [eax + 8 * ecx + 2]",
        "mov dword ptr [esi + 3], eax",
        "add esi, 7", // Target the next RAW block
        //"add edx, 7", // Increment the total size of compressed data
        "jmp 2b",

        "3:",

        // [zstd] Store a raw (uncompressed) byte
        "mov byte ptr [esi + ebp + 3], al",
        "inc ebp", // Increment the size of the current RAW block
        //"inc edx", // Increment the total size of compressed data

        // [zstd] Exit if the end was reached
        "cmp edi, OFFSET {IMAGE_TAR_BYTES_END}",
        "jne 2b",

        // [zstd] Write the last RAW header: 3 bytes (block_size << 3) | 1
        // Assume the most significant byte is zero (no large raw regions)
        "xor ebx, ebx",
        //"lea eax, [ebx + 8 * ebp + 1]",
        //"add dword ptr [esi], eax",
        "mov word ptr [esi], OFFSET {ZSTD_LAST_RAW_BLOCK_HEADER}", // Compute the header in the linker script

        // [zstd] Write frame header, which is right after the IMAGE_TAR_BYTES buffer
        // Frame Header Descriptor: no option set (0)
        // Window Descriptor: 0
        // This works because here, edi = IMAGE_TAR_BYTES_END = IMAGE_COMPRESSED
        "mov dword ptr [edi], {ZSTD_MAGIC}",

        // [zstd] Write the compressed archive (ecx = pointer, edx = size)
        "mov ecx, edi", // In the end, edi (end of uncompressed data) reached the start of the compressed buffer
        "mov dx, OFFSET {FILE_SIZE} + {DIFF_ZSTD_SIZE_FILE_SIZE}",
        "push {NR_WRITE}",
        "pop eax",
        "inc ebx", // fd = 1
        "int 0x80",

        // Exit
        "mov eax, ebx", // NR_exit = 1
        "dec ebx",      // exit_code = 0
        "int 0x80",

        IMAGE_COMPRESSED = sym IMAGE_COMPRESSED,
        IMAGE_TAR_BYTES_END = sym IMAGE_TAR_BYTES_END,
        FILE_SIZE = sym SYMBOL_FILE_SIZE,
        ZSTD_LAST_RAW_BLOCK_HEADER = sym ZSTD_LAST_RAW_BLOCK_HEADER,

        DIFF_ZSTD_SIZE_FILE_SIZE = const DIFF_ZSTD_SIZE_FILE_SIZE,

        NR_WRITE = const linux_syscalls::NR_WRITE,

        // ZSTD_MAGICNUMBER from https://github.com/facebook/zstd/blob/e128976193546dceb24249206a02ff8f444f7120/lib/zstd.h#L142
        ZSTD_MAGIC = const u32::from_ne_bytes(*b"\x28\xb5\x2f\xfd"),
    );
}
