OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(_start)

SECTIONS {
    __executable_start = 0x01000000;
    . = __executable_start + SIZEOF_HEADERS;

    /* ZSTD compresses zeros at the end of the program header */
    zstd_last_raw_block_offset = ABSOLUTE(. - __executable_start);

    .text : {
        KEEP(*(.text.set_tar_header_size_cksum))
        KEEP(*(.text.start))
        KEEP(*(.text.real_start))
        KEEP(*(.text.compress_image))
        KEEP(*(.text.sha256_hex))
        *(.text*)
    }
    .rodata : {
        *(.rodata*)
    }
    .data : {
        *(.data*)
    }
    file_size = ABSOLUTE(. - __executable_start);

    .ensure_no_headers : {
        KEEP(*(.headers))
        ASSERT(SIZEOF(.ensure_no_headers) == 0, "The code defines section .headers!")
    }

    .bss : {
        INCLUDE linker_script_common_bss.inc.ld;
    }

    /DISCARD/ : {
        *(.comment)
    }
}