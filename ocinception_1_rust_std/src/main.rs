use sha2::Digest;
use std::io::{IsTerminal, Write};

const NICKNAME: &str = "1";
const PROGRAM_NAME: &str = "s";

/// Fill field size and compute the tar header checksum.
fn set_tar_header_size_cksum(tar_header: &mut [u8], size: usize) {
    if size != 0 {
        if cfg!(feature = "tar-binary-size") {
            // Write the size in tar_header[124..136] in base-256 mode (big endian, high bit set)
            tar_header[124] = 0x80;
            tar_header[128..136].copy_from_slice(&u64::to_be_bytes(size as u64));
        } else {
            // Write the size in octal in tar_header[124..136]
            let octal_size = format!("{size:o}").into_bytes();
            assert!(octal_size.len() <= 12);
            tar_header[124..][..octal_size.len()].copy_from_slice(&octal_size);
        }
    }

    // Compute the checksum by considering it holds spaces
    let cksum = tar_header[0..148]
        .iter()
        .chain(b"        ")
        .chain(&tar_header[156..])
        .fold(0, |a, b| a + (*b as u32));
    let octal_cksum = format!("{cksum:o}").into_bytes();
    tar_header[148..][..octal_cksum.len()].copy_from_slice(&octal_cksum);
}

/// Add padding to align the size to 512 bytes
fn add_tar_padding(tar_file: &mut Vec<u8>) {
    let aligned_len = tar_file.len().div_ceil(512) * 512;
    tar_file.resize(aligned_len, 0);
}

/// Compute the checksum for GZip files
#[cfg(any(feature = "gz", test))]
fn gzip_crc32(data: &[u8]) -> u32 {
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

/// Compress the image using gzip DEFLATE
/// https://datatracker.ietf.org/doc/html/rfc1952 GZIP file format specification version 4.3
/// https://datatracker.ietf.org/doc/html/rfc1951 DEFLATE Compressed Data Format Specification version 1.3
#[cfg(feature = "gz")]
fn compress_gzip(data: &[u8]) -> Vec<u8> {
    /*
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        encoder
            .write_all(&image_tar_bytes)
            .expect("gz compress write");
        compressed = encoder.finish().expect("gz compress finish");
    */

    // Compress with better than best compression level
    // https://docs.rs/miniz_oxide/latest/miniz_oxide/deflate/enum.CompressionLevel.html#variant.UberCompression
    let compressed_deflate = miniz_oxide::deflate::compress_to_vec(
        &data,
        miniz_oxide::deflate::CompressionLevel::UberCompression as u8,
    );

    // Craft a GZIP file header and footer
    let mut compressed = Vec::with_capacity(18 + compressed_deflate.len());
    compressed.extend([0x1f, 0x8b, 8]);
    compressed.resize(10, 0);
    compressed.extend(compressed_deflate);
    compressed.extend(gzip_crc32(data).to_le_bytes());
    compressed.extend((data.len() as u32).to_le_bytes());
    compressed
}

/// Compress using Zstandard
/// https://datatracker.ietf.org/doc/html/rfc8878
#[cfg(feature = "zstd")]
fn compress_zstd(data: &[u8]) -> Vec<u8> {
    // Ruzstd does not support best compression level yet
    // ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)

    let mut compressed = Vec::<u8>::new();
    let mut encoder =
        zstd::stream::write::Encoder::new(&mut compressed, 22).expect("zstd encoder new");
    encoder
        .set_pledged_src_size(Some(data.len() as u64))
        .expect("zstd set_pledged_src_size");
    encoder
        .include_checksum(false)
        .expect("zstd include_checksum");

    // Do not set Frame_Content_Size_Flag
    encoder
        .include_contentsize(false)
        .expect("zstd include_contentsize");

    encoder.write_all(data).expect("zstd write");
    encoder.do_finish().expect("zstd finish");
    compressed
}

fn main() {
    // The argument is the tag to use
    let mut args = std::env::args();
    let program_name = args.next().unwrap();
    let arg_tag = args.next().unwrap_or_else(|| "latest".to_string());

    // Create a filesystem layer archive
    let program_file = std::fs::read(program_name).expect("read program");
    let mut filesystem_tar_header = [0u8; 512];
    // Set the program path in the container filesystem
    filesystem_tar_header[..PROGRAM_NAME.len()].copy_from_slice(PROGRAM_NAME.as_bytes());
    // Set mode to rx (Read+Execute)
    filesystem_tar_header[100] = b'5';
    set_tar_header_size_cksum(&mut filesystem_tar_header, program_file.len());

    let layer_tar_bytes = [filesystem_tar_header.as_ref(), &program_file].concat();

    // compute the SHA256
    let layer_tar_sha256 = hex::encode(sha2::Sha256::digest(&layer_tar_bytes));

    // Generate images with a fake manifest digest
    const FAKE_IMAGE_MANIFEST_SHA256: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    // "2562562562562562562562562562562562562562562562562562562562562562";
    let image_manifest_sha256 =
        if arg_tag.len() == 64 && !cfg!(feature = "never-use-arg-as-manifest-digest") {
            &arg_tag
        } else {
            FAKE_IMAGE_MANIFEST_SHA256
        };

    // Craft an image configuration file
    // https://github.com/opencontainers/image-spec/blob/v1.1.1/config.md
    let image_config = if cfg!(feature = "docker-archive") {
        format!(r#"{{"config":{{"entrypoint":["/{PROGRAM_NAME}"]}},"rootfs":{{"diff_ids":["sha256:{layer_tar_sha256}"]}}}}"#)
    } else if cfg!(feature = "merge-config-index") {
        // Merge the index with the configuration
        format!(
            r#"{{"config":{{"entrypoint":["/{PROGRAM_NAME}"]}},"manifests":[{{"digest":"sha256:{image_manifest_sha256}","annotations":{{"org.opencontainers.image.ref.name":"ocinception_{NICKNAME}:{arg_tag}"}}}}]}}"#
        )
    } else {
        format!(r#"{{"config":{{"entrypoint":["/{PROGRAM_NAME}"]}}}}"#)
    }.into_bytes();
    let image_config_sha256 = hex::encode(sha2::Sha256::digest(&image_config));

    // Craft an image manifest file
    // https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md
    let image_manifest = if cfg!(feature = "docker-archive") {
        // Use an empty file name for the configuration, so remove field "config"
        if arg_tag == "latest" {
            format!(
                r#"[{{"layers":["l"],"repotags":["ocinception_{NICKNAME}:{arg_tag}"]}}]"#
            )
        } else {
            // Remove the layer
            format!(
                r#"[{{"layers":[""],"repotags":["ocinception_{NICKNAME}:{arg_tag}"]}}]"#
            )
        }
    } else {
        // let config_size = -1;
        let config_size = image_config.len();
        format!(
            r#"{{"schemaversion":2,"config":{{"mediatype":"application/vnd.oci.image.config.v1+json","digest":"sha256:{image_config_sha256}","size":{config_size}}},"layers":[{{"digest":"sha256:{layer_tar_sha256}"}}]}}"#
        )
    }.into_bytes();

    // Craft an index.json file
    // https://github.com/opencontainers/image-spec/blob/v1.1.1/image-layout.md#indexjson-file
    let index_json = if cfg!(feature = "docker-archive") || cfg!(feature = "merge-config-index") {
        "".to_string()
    } else {
        format!(
            r#"{{"manifests":[{{"digest":"sha256:{image_manifest_sha256}","annotations":{{"io.containerd.image.name":"ocinception_{NICKNAME}:{arg_tag}"}}}}]}}"#
        )
        // No better compression when swapping the fields
        // format!(
        //     r#"{{"manifests":[{{"annotations":{{"io.containerd.image.name":"ocinception_{NICKNAME}:{arg_tag}"}},"digest":"sha256:{image_manifest_sha256}"}}]}}"#
        // )
    }.into_bytes();

    // Build the image archive
    let mut image_tar_bytes = Vec::with_capacity(3 * 1024 + 512 + layer_tar_bytes.len());

    if cfg!(feature = "docker-archive") {
        let mut manifest_header = [0u8; 512];
        manifest_header[0..13].copy_from_slice(b"manifest.json");
        set_tar_header_size_cksum(&mut manifest_header, image_manifest.len());
        image_tar_bytes.extend(manifest_header);
        image_tar_bytes.extend(&image_manifest);
        add_tar_padding(&mut image_tar_bytes);

        let mut config_header = [0u8; 512];
        set_tar_header_size_cksum(&mut config_header, image_config.len());
        image_tar_bytes.extend(config_header);
        image_tar_bytes.extend(&image_config);
    } else if cfg!(feature = "merge-config-index") {
        let mut index_header = [0u8; 512];
        index_header[0..10].copy_from_slice(b"index.json");
        set_tar_header_size_cksum(&mut index_header, image_config.len());
        image_tar_bytes.extend(index_header);
        image_tar_bytes.extend(&image_config);
        add_tar_padding(&mut image_tar_bytes);

        let mut config_header = [0u8; 512];
        config_header[0..77]
            .copy_from_slice(&format!("blobs/sha256/{}", image_config_sha256).into_bytes());
        // Create a hard link to index.json
        config_header[156] = b'1';
        config_header[157..][..10].copy_from_slice(b"index.json");
        set_tar_header_size_cksum(&mut config_header, 0);
        image_tar_bytes.extend(config_header);

        let mut manifest_header = [0u8; 512];
        manifest_header[0..77]
            .copy_from_slice(&format!("blobs/sha256/{}", image_manifest_sha256).into_bytes());
        set_tar_header_size_cksum(&mut manifest_header, image_manifest.len());
        image_tar_bytes.extend(manifest_header);
        image_tar_bytes.extend(&image_manifest);
    } else {
        let mut config_header = [0u8; 512];
        config_header[0..77]
            .copy_from_slice(&format!("blobs/sha256/{}", image_config_sha256).into_bytes());
        set_tar_header_size_cksum(&mut config_header, image_config.len());
        image_tar_bytes.extend(config_header);
        image_tar_bytes.extend(&image_config);
        add_tar_padding(&mut image_tar_bytes);

        let mut manifest_header = [0u8; 512];
        manifest_header[0..77]
            .copy_from_slice(&format!("blobs/sha256/{}", image_manifest_sha256).into_bytes());
        set_tar_header_size_cksum(&mut manifest_header, image_manifest.len());
        image_tar_bytes.extend(manifest_header);
        image_tar_bytes.extend(&image_manifest);
        add_tar_padding(&mut image_tar_bytes);

        let mut index_header = [0u8; 512];
        index_header[0..10].copy_from_slice(b"index.json");
        set_tar_header_size_cksum(&mut index_header, index_json.len());
        image_tar_bytes.extend(index_header);
        image_tar_bytes.extend(&index_json);
    }

    // Docker archive format requires the layer to be in the image
    if arg_tag == "latest" {
        // Include the filesystem layer only in the first archive
        add_tar_padding(&mut image_tar_bytes);

        let mut layer_header = [0u8; 512];
        if cfg!(feature = "docker-archive") {
            layer_header[0] = b'l';
        } else {
            layer_header[0..77]
                .copy_from_slice(&format!("blobs/sha256/{}", layer_tar_sha256).into_bytes());
        }
        set_tar_header_size_cksum(&mut layer_header, layer_tar_bytes.len());
        image_tar_bytes.extend(layer_header);
        image_tar_bytes.extend(&layer_tar_bytes);
    }

    let image_tar_compressed: Vec<u8>;
    #[cfg(feature = "gz")]
    {
        image_tar_compressed = compress_gzip(&image_tar_bytes);
    }
    #[cfg(feature = "zstd")]
    {
        image_tar_compressed = compress_zstd(&image_tar_bytes);
    }
    #[cfg(not(any(feature = "gz", feature = "zstd")))]
    {
        image_tar_compressed = image_tar_bytes;
    }

    let mut stdout = std::io::stdout();
    if stdout.is_terminal() {
        eprintln!("Refusing to send binary data to stdout");
        return;
    }
    stdout.write_all(&image_tar_compressed).expect("tar write");
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

    #[test]
    fn sha256_hex() {
        assert_eq!(
            hex::encode(sha2::Sha256::digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex::encode(sha2::Sha256::digest(b"hello world")),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert_eq!(
            hex::encode(sha2::Sha256::digest(
                b"{\"config\":{\"entrypoint\":[\"/s\"]}}"
            )),
            "e51991d5c6c243c04e6b0f06982b1dea6032ec12452f73550d726bb2dc46d9f1"
        );
    }

    #[test]
    fn tar_header() {
        let name = "test-file";
        let mut tar_header = [0u8; 512];
        tar_header[..name.len()].copy_from_slice(name.as_bytes());
        tar_header[100] = b'5';
        set_tar_header_size_cksum(&mut tar_header, 42);
        assert_eq!(
            tar_header,
            *b"test-file\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\052\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\02451\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        );
    }
}
