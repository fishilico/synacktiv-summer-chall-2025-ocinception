OUTPUT_FORMAT("binary")
OUTPUT_ARCH(i386)

SECTIONS {
    __executable_start = 0x01000000;
    . = __executable_start;

    /* ZSTD compresses zeros until offset of Elf32_Phdr.p_vaddr + 3 */
    zstd_last_raw_block_offset = 0x37;

    .data : {
        KEEP(*(.headers))
        KEEP(*(.text.set_tar_header_size_cksum))
        KEEP(*(.text.start))
        KEEP(*(.text.real_start))
        KEEP(*(.text.compress_image))
        KEEP(*(.text.sha256_hex))
        KEEP(*(.text*))
        KEEP(*(.rodata*))
        KEEP(*(.data*))
    }
    file_size = ABSOLUTE(. - __executable_start);
    .bss : {
        INCLUDE linker_script_common_bss.inc.ld;
    }
    file_memory_size = ABSOLUTE(. - __executable_start);
    /DISCARD/ : {
        *(.comment)
    }
}