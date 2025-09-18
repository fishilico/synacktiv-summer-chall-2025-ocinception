//! Group strings used by the program together and compress them
use super::mem_ops::asm_memcpy_const;

/// Path in OCI images
pub const STR_BLOBS_SHA256: &str = "blobs/sha256/";

/// Set tar header typeflag = LNKTYPE = '1 and fill char linkname[100]
pub const STR_1INDEX_JSON: &str = "1index.json";

/// Craft an image manifest file
/// https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md
pub const STR_MANIFEST_1: &str =
    r#"{"schemaversion":2,"config":{"mediatype":"application/vnd.oci.image.config.v1+json","#;
pub const STR_MANIFEST_2: &str = r#"","size":-1},"layers":[{"digest":"sha256:"#;

pub const MANIFEST_LEN: u32 =
    (STR_MANIFEST_1.len() + STR_DIGEST_SHA256.len() + 64 + STR_MANIFEST_2.len() + 64 + 4) as u32;

/// AF_ALG = 38 = '&' and constant for sockaddr_alg
pub const STR_ALG_SOCKET: &str = "&hash";

/// Craft an image configuration file mixed with index.json
/// https://github.com/opencontainers/image-spec/blob/v1.1.1/config.md
/// https://github.com/opencontainers/image-spec/blob/v1.1.1/image-layout.md#indexjson-file
pub const STR_CONFIG_1: &str = r#"{"config":{"entrypoint":["/s"]},"manifests":[{"#;
pub const STR_CONFIG_2: &str = r#"","annotations":{"io.containerd.image.name":"ocinception_2:"#;
pub const STR_CONFIG_3: &str = r#""}}]}"#;

pub const CONFIG_AND_INDEX_JSON_LEN: u32 = (STR_CONFIG_1.len()
    + STR_DIGEST_SHA256.len()
    + 64
    + STR_CONFIG_2.len()
    + 64
    + STR_CONFIG_3.len()) as u32;

// Reuse '"digest": "sha256:' in several places, without including it directly
pub const STR_DIGEST_SHA256: &str = r#""digest":"sha256:"#;

const ALL_STRING_LENGTHS: usize = STR_BLOBS_SHA256.len()
    + STR_1INDEX_JSON.len()
    + STR_MANIFEST_1.len()
    + STR_MANIFEST_2.len()
    + STR_ALG_SOCKET.len()
    + STR_CONFIG_1.len()
    + STR_CONFIG_2.len()
    + STR_CONFIG_3.len();

/// Strings used by the program
const fn concatenate_strings() -> [u8; ALL_STRING_LENGTHS] {
    let mut strings: [u8; ALL_STRING_LENGTHS] = [0; ALL_STRING_LENGTHS];
    // Split the string into (current, remaining) parts
    let (cur, rem) = strings.split_at_mut(STR_BLOBS_SHA256.len());
    cur.copy_from_slice(STR_BLOBS_SHA256.as_bytes());
    let (cur, rem) = rem.split_at_mut(STR_1INDEX_JSON.len());
    cur.copy_from_slice(STR_1INDEX_JSON.as_bytes());
    let (cur, rem) = rem.split_at_mut(STR_MANIFEST_1.len());
    cur.copy_from_slice(STR_MANIFEST_1.as_bytes());
    let (cur, rem) = rem.split_at_mut(STR_MANIFEST_2.len());
    cur.copy_from_slice(STR_MANIFEST_2.as_bytes());
    let (cur, rem) = rem.split_at_mut(STR_ALG_SOCKET.len());
    cur.copy_from_slice(STR_ALG_SOCKET.as_bytes());
    let (cur, rem) = rem.split_at_mut(STR_CONFIG_1.len());
    cur.copy_from_slice(STR_CONFIG_1.as_bytes());
    let (cur, rem) = rem.split_at_mut(STR_CONFIG_2.len());
    cur.copy_from_slice(STR_CONFIG_2.as_bytes());
    let (cur, rem) = rem.split_at_mut(STR_CONFIG_3.len());
    cur.copy_from_slice(STR_CONFIG_3.as_bytes());
    assert!(rem.is_empty());
    strings
}
const STRINGS: [u8; ALL_STRING_LENGTHS] = concatenate_strings();

/// Identify the offset of a string (given as bytes) in STRINGS
pub const fn strb_offset(s: &[u8]) -> usize {
    assert!(s.len() > 0);
    let mut pos = 0;
    while pos + s.len() <= STRINGS.len() {
        let mut subpos = 0;
        while STRINGS[pos + subpos] == s[subpos] {
            subpos += 1;
            if subpos == s.len() {
                return pos;
            }
        }
        pos += 1;
    }
    panic!("String not found");
}

/// Identify the offset of a string in STRINGS
pub const fn str_offset(s: &str) -> usize {
    strb_offset(s.as_bytes())
}

/// Decompress a 6-bit symbol
const fn decompress_symbol(sym: u8) -> u8 {
    if sym < 0x1a { sym + 0x21 } else { sym + 0x41 }
}

/// Compress an 8-bit character to a 6-bit symbol
const fn compress_char(c: u8) -> u8 {
    if c < b'[' { c - b'!' } else { c - b'[' + 0x1a }
}

/// Compress the strings using a custom base64 alphabet
const fn compress_strings() -> [u8; 201] {
    const ALPHABET: [u8; 61] = *b"!\"#$%&\'()*+,-./0123456789:[\\]^_`abcdefghijklmnopqrstuvwxyz{|}";

    // Check the alphabet
    let mut sym = 0u8;
    while sym < 61 {
        let c = decompress_symbol(sym);
        assert!(ALPHABET[sym as usize] == c, "mismatched alphabet");
        assert!(compress_char(c) == sym, "invalid compressor helper");
        sym += 1;
    }

    // Compress 4 characters into 4 6-bit symbols, packed into 3 bytes
    // The last symbol is 0 and packs are not truncated.
    let mut compressed = [0u8; 201];
    assert!(
        (STRINGS.len() + 1).div_ceil(4) * 3 == compressed.len(),
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

    // No character remains to be compressed, and some zero symbols are added
    assert!(4 * pos == STRINGS.len(), "unexpected STRINGS length");
    assert!(
        3 * pos + 3 == compressed.len(),
        "unexpected compressed length"
    );
    compressed
}

static COMPRESSED_STRINGS: [u8; 201] = compress_strings();

// Define content of section .bss (globals initialized to zero)
pub static mut DECOMPRESSED_STRINGS: [u8; 264] = [0; 264];
const _: () = assert!(unsafe { DECOMPRESSED_STRINGS.len() } == STRINGS.len());

#[inline]
pub unsafe fn copy_string_by_offset<const OFFSET: usize, const SIZE: usize>(
    dst: *mut u8,
) -> *mut u8 {
    unsafe { asm_memcpy_const::<SIZE>(dst, DECOMPRESSED_STRINGS.as_ptr().add(OFFSET)) }
}

/// Copy the given decompressed string to the pointer and return dst + str.len()
#[macro_export]
macro_rules! copy_str {
    ($dst:expr, $str:expr) => {{
        const STR_OFFSET: usize = crate::global_strings::str_offset($str);
        const STR_LEN: usize = $str.len();
        crate::global_strings::copy_string_by_offset::<STR_OFFSET, STR_LEN>($dst)
    }};
}

/// Decompress the strings using an algorithm similar as base64-encode
/// https://codegolf.stackexchange.com/questions/26584/convert-a-bytes-array-to-base64/158039#158039
pub fn decompress_strings() {
    #[cfg(target_arch = "x86")]
    unsafe {
        core::arch::asm!(
            "push esi",
            "mov esi, OFFSET {COMPRESSED_STRINGS}",
            "2:",
            // Load 3 bytes from the compressed strings
            "dec esi",
            "lodsd eax, dword ptr [esi]",
            // Decode symbols
            "push 4",
            "pop ecx",
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
            "pop esi",
            COMPRESSED_STRINGS = sym COMPRESSED_STRINGS,
            inout("edi") DECOMPRESSED_STRINGS.as_mut_ptr() => _,
            out("eax") _,
            out("ecx") _,
            options(nostack),
        );
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let mut src = unsafe { COMPRESSED_STRINGS.as_ptr().sub(1) };
        let mut dst = unsafe { DECOMPRESSED_STRINGS.as_mut_ptr() };
        loop {
            // Read 3 bytes in a u32, ignoring the least significant byte in practice
            let mut chars: u32 = unsafe { src.cast::<u32>().read_unaligned() };
            for _ in 0..4 {
                chars = chars.rotate_left(6);
                let sym = (chars & 0x3f) as u8;
                if sym == 0 {
                    return;
                }
                let c = if sym < 0x1a { sym + 0x21 } else { sym + 0x41 };
                unsafe { *dst = c };
                dst = unsafe { dst.add(1) };
            }
            src = unsafe { src.add(3) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ensure strings decompression works
    #[test]
    fn constant_strings() {
        decompress_strings();
        assert_eq!(unsafe { DECOMPRESSED_STRINGS }, STRINGS);
    }

    #[test]
    fn offsets() {
        const STRING_OFFSET_BLOBS_SHA256: usize = str_offset("blobs/sha256/");

        const STRING_OFFSET_1INDEX_JSON: usize = str_offset("1index.json");
        const STRING_OFFSET_INDEX_JSON: usize = str_offset("index.json");
        const STRING_OFFSET_DIGEST_SHA256: usize = str_offset("\"digest\":\"sha256:");
        const STRING_OFFSET_ALG_SOCKET: usize = str_offset("&hash");
        decompress_strings();
        assert_eq!(
            unsafe {
                &DECOMPRESSED_STRINGS[STRING_OFFSET_BLOBS_SHA256..STRING_OFFSET_BLOBS_SHA256 + 13]
            },
            b"blobs/sha256/"
        );
        assert_eq!(
            unsafe {
                &DECOMPRESSED_STRINGS[STRING_OFFSET_1INDEX_JSON..STRING_OFFSET_1INDEX_JSON + 11]
            },
            b"1index.json"
        );
        assert_eq!(
            unsafe {
                &DECOMPRESSED_STRINGS[STRING_OFFSET_INDEX_JSON..STRING_OFFSET_INDEX_JSON + 10]
            },
            b"index.json"
        );
        assert_eq!(STRING_OFFSET_1INDEX_JSON + 1, STRING_OFFSET_INDEX_JSON);
        assert_eq!(
            unsafe {
                &DECOMPRESSED_STRINGS[STRING_OFFSET_DIGEST_SHA256..STRING_OFFSET_DIGEST_SHA256 + 17]
            },
            b"\"digest\":\"sha256:"
        );
        assert_eq!(
            unsafe {
                &DECOMPRESSED_STRINGS[STRING_OFFSET_ALG_SOCKET..STRING_OFFSET_ALG_SOCKET + 5]
            },
            b"&hash"
        );
    }
}
