/* Add 3 zero bytes to make the compressed string end with a zero symbol */
. += 3;

/* Include the usual content in .bss... which should be empty */
bss_start = .;
*(.bss*)
/* ASSERT(. == bss_start, "Section .bss was not empty"); */

decompressed_strings = .;
. += 378;

. = ALIGN(0x10000);

buffer_image_tar_bytes = .;
. += 3072 + 512 + file_size;
buffer_image_tar_bytes_end = .;

/* The compressed buffer is located right after the uncompressed one */
buffer_image_compressed = .;
. += 3072 + 512 + file_size;

/* Ensure the shortcut is at an expected location */
ASSERT(set_tar_header_cksum_nosize == set_tar_header_size_cksum + 0xd, "Unexpected set_tar_header_size_cksum shortcut position");

/* Compute function offset to get the image base from set_tar_header_size_cksum
 * Work around a LLVM linker issue when the relocation of "lea esi, [ebp - offset...]" is applied as "[ebp + offset]"
 */
/*
offset_set_tar_header_size_cksum = ABSOLUTE(set_tar_header_size_cksum - __executable_start);
*/
offset_set_tar_header_size_cksum = ABSOLUTE(__executable_start - set_tar_header_size_cksum);
ASSERT(-offset_set_tar_header_size_cksum > 0, "unexpected sign of offset_set_tar_header_size_cksum");
ASSERT(-offset_set_tar_header_size_cksum <= 0x80, "unexpected large value of offset_set_tar_header_size_cksum");

/* Compute the header of the last RAW block in ZSTD */
zstd_last_raw_block_header = ABSOLUTE((file_size - zstd_last_raw_block_offset) * 8 + 1);
/* ASSERT(zstd_last_raw_block_header < 0x10000, "unexpected large value of zstd_last_raw_block_header"); */
