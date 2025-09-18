use super::{
    IMAGE_TAR_BYTES, MAX_IMAGE_SIZE,
    linux_syscalls::{syscall_exit, syscall_write_all},
};

/// Compress the image using Zstandard RLE mode
/// https://datatracker.ietf.org/doc/html/rfc8878
#[allow(static_mut_refs)]
pub fn write_image_zstd(image_tar_size: u32) -> ! {
    let mut data_ptr = unsafe { IMAGE_TAR_BYTES.as_ptr() };
    let data_end_ptr = unsafe { data_ptr.add(image_tar_size as usize) };
    static mut IMAGE_COMPRESSED: [u8; MAX_IMAGE_SIZE] = [0; MAX_IMAGE_SIZE];
    let compressed = unsafe { &mut IMAGE_COMPRESSED };

    // Write the frame header
    unsafe {
        *compressed.as_mut_ptr().cast::<u32>() = u32::from_ne_bytes(*b"\x28\xb5\x2f\xfd");
    }
    if true {
        // Small programs can use the minimal Window size of 1 KB (Window_Descriptor = 0)
        // Larger programs require a larger Window size. Use 2 MB:
        // size = 1 << ((Window_Descriptor >> 3) + 10)
        compressed[5] = 0x58;
    }

    // Detect RLE sequences in the data
    let mut current_raw_block_size = 0u32;
    let mut compressed_raw_header_offset = 6;
    let mut compressed_offset = 9;
    while data_ptr != data_end_ptr {
        let data_u32 = unsafe { data_ptr.cast::<u32>().read_unaligned() };
        let data_plus1_u32 = unsafe { data_ptr.add(1).cast::<u32>().read_unaligned() };
        if unsafe { data_end_ptr.offset_from_unsigned(data_ptr) } >= 8 && data_u32 == data_plus1_u32
        {
            let data_plus4_u32 = unsafe { data_ptr.add(4).cast::<u32>().read_unaligned() };
            if data_u32 == data_plus4_u32 {
                // There is at least 8 repetitions; do RLE
                // Create a header for the previous block in RAW mode
                if current_raw_block_size > 0 {
                    let block_header = current_raw_block_size << 3;
                    // Write 3 bytes without changing the 4th, using += instead of =
                    unsafe {
                        let ptr = compressed
                            .as_mut_ptr()
                            .add(compressed_raw_header_offset)
                            .cast::<u32>();
                        ptr.write_unaligned(ptr.read_unaligned() + block_header);
                    }
                }
                let repeated_byte = (data_u32 & 0xff) as u8;
                let mut repeat_count = 1u32;
                unsafe {
                    data_ptr = data_ptr.add(1);
                    while data_ptr != data_end_ptr && *data_ptr == repeated_byte {
                        repeat_count += 1;
                        data_ptr = data_ptr.add(1);
                    }
                }

                #[cfg(feature = "with-debug")]
                let _ = core::fmt::write(
                    &mut super::panic::StdErrWriter {},
                    format_args!(
                        "Identified RLE at {:#06x} [{:3}] for {}\n",
                        unsafe { data_ptr.offset_from_unsigned(IMAGE_TAR_BYTES.as_ptr()) },
                        repeat_count,
                        repeated_byte
                    ),
                );

                // Create a header for the RLE block
                let block_header = (repeat_count << 3) | 2 | (data_u32 << 24);
                unsafe {
                    compressed
                        .as_mut_ptr()
                        .add(compressed_offset)
                        .cast::<u32>()
                        .write_unaligned(block_header);
                }
                current_raw_block_size = 0;
                compressed_raw_header_offset = compressed_offset + 4;
                compressed_offset += 7;
                continue;
            }
        }
        // Store the raw byte
        unsafe {
            *compressed.as_mut_ptr().add(compressed_offset) = (data_u32 & 0xff) as u8;
            data_ptr = data_ptr.add(1);
        }
        current_raw_block_size += 1;
        compressed_offset += 1;
    }
    // Write the last RAW header
    if current_raw_block_size > 0 {
        let block_header = (current_raw_block_size << 3) | 1;
        unsafe {
            let ptr = compressed
                .as_mut_ptr()
                .add(compressed_raw_header_offset)
                .cast::<u32>();
            ptr.write_unaligned(ptr.read_unaligned() + block_header);
        }
    } else {
        // Add an empty raw block to mark the last one
        unsafe { *compressed.as_mut_ptr().add(compressed_offset) = 1 };
        compressed_offset += 3;
    }

    unsafe { syscall_write_all(1, compressed.as_ptr(), compressed_offset as u32) };
    syscall_exit(0)
}
