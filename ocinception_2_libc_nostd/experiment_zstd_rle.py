#!/usr/bin/env python3
"""Experiment with zstd format in RLE mode"""
from __future__ import annotations

import subprocess
import sys

from pathlib import Path

# Frame header: Magic
zstd_header = b"\x28\xb5\x2f\xfd"
# Frame Header Descriptor: no option set
zstd_header += b"\0"
# Window Descriptor: 2 MB
zstd_header += b"\x58"

zstd_data = zstd_header
chunk = b"Hello"
block_header = len(chunk) << 3
zstd_data += block_header.to_bytes(3, "little") + chunk

# Repeat 10 spaces
block_header = (20 << 3) | 2  # RLE
zstd_data += block_header.to_bytes(3, "little") + b" "

chunk = b"world!"
block_header = (len(chunk) << 3) | 1  # Last block
zstd_data += block_header.to_bytes(3, "little") + chunk

output = subprocess.check_output("zstdcat", input=zstd_data)
print(output)
assert output == b"Hello                    world!"


def analyze_zstd(studied_image_zstd: bytes, desc: str) -> None:
    """Decode the zstd data by hand"""
    assert studied_image_zstd[:5] == b"(\xb5/\xfd\x00"
    pos = 6
    real_offset = 0
    print(f"ZSTD blocks from {desc} [{len(studied_image_zstd)}]:")
    while pos < len(studied_image_zstd):
        block_header = int.from_bytes(studied_image_zstd[pos : pos + 3], "little")
        block_size = block_header >> 3
        block_type = (block_header >> 1) & 3
        block_last = block_header & 1
        if block_type == 0:  # RAW
            assert pos + 3 + block_size <= len(studied_image_zstd)
            block_data = studied_image_zstd[pos + 3 : pos + 3 + block_size]
            print(f"[{pos:#06x}->{real_offset:#06x}] RAW [{block_size:#5x}] {block_data!r}")
            pos += 3 + block_size
            real_offset += block_size
        elif block_type == 1:  # RLE
            assert pos + 1 <= len(studied_image_zstd)
            block_data = studied_image_zstd[pos + 3 : pos + 4]
            print(f"[{pos:#06x}->{real_offset:#06x}] RLE [{block_size:#5x}] {block_data!r}")
            pos += 4
            real_offset += block_size
        else:
            assert 0, f"unknown block type {block_type}"
        if pos == len(studied_image_zstd):
            assert block_last, "LAST bit was not set for the last block"
            assert block_type == 0
        else:
            assert not block_last, "LAST bit was set for a non-last block"

    # Ensure zstdcat is happy, as there could be issues with the window size
    return subprocess.check_output(["zstdcat"], input=studied_image_zstd)


RUST_PROJECT = Path(__file__).parent

for rust_target in ("x86_64-unknown-linux-musl", "i686-unknown-linux-musl"):
    target_dir_name = "/tmp/ocinception-target/target-zstd-experiment"
    subprocess.run(
        [
            "cargo",
            "build",
            "--target",
            rust_target,
            "--target-dir",
            target_dir_name,
            "--release",
            "--features",
            "zstd",
            # "zstd,with-debug",
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        cwd=RUST_PROJECT,
    )
    target_dir_path = Path(target_dir_name) / rust_target / "release"
    compiled_program_path = target_dir_path / "ocinception_2"
    program_path = target_dir_path / "ocinception_2_strip"

    # Strip the section header with llvm-objcopy
    subprocess.run(
        ["llvm-objcopy", "--strip-sections", compiled_program_path.name, program_path.name],
        check=True,
        stdin=subprocess.DEVNULL,
        cwd=target_dir_path,
    )

    EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    studied_image_zstd = subprocess.check_output([program_path, EMPTY_SHA256])
    studied_image = analyze_zstd(studied_image_zstd, rust_target)

    if "--seq" in sys.argv:
        print(f"Studying RLE-able sequences in tar file of {len(studied_image)} bytes")
        offset = 0
        while offset < len(studied_image):
            repeat_len = 1
            while (
                offset + repeat_len < len(studied_image)
                and studied_image[offset] == studied_image[offset + repeat_len]
            ):
                repeat_len += 1
            if repeat_len >= 8:
                print(f"[{offset:#06x}] {repeat_len:3} {studied_image[offset:offset + 1]!r}")
            elif repeat_len >= 5:
                print(
                    f"[{offset:#06x}] {repeat_len:3} {studied_image[offset:offset + 1]!r} (small)"
                )
            offset += repeat_len
