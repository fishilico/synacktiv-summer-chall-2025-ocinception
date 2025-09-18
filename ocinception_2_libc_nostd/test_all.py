#!/usr/bin/env python3
"""Test ocinception challenge with several configurations of targets and features

black --line-length=100 test_all.py
mypy --strict test_all.py
./test_all.py
"""
from __future__ import annotations

import datetime
import gzip
import hashlib
import io
import json
import subprocess
import sys
import tarfile

from pathlib import Path

IMAGE_NAME = "ocinception_2"

RUST_PROJECT = Path(__file__).parent

# Colorize good output
MY_BEST_SCORE = 2600

arg_debug = "--debug" in sys.argv
arg_notest = "--no-test" in sys.argv
arg_quiet = "--quiet" in sys.argv

# Detect whether we are running in a Vagrant virtual machine
is_vagrant_vm = RUST_PROJECT.resolve().is_relative_to("/vagrant")

RUST_TEST_TARGETS: tuple[str, ...] = (
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "i686-unknown-linux-musl",
)

# Build several versions of the program and run it
# Fields: name for target directory, Rust target, Rust features
BUILD_CONFIGURATIONS: tuple[tuple[str, str, str], ...] = (
    ("64_musl_raw", "i686-unknown-linux-musl", ""),
    ("64_musl_gzip", "i686-unknown-linux-musl", "gzip"),
    ("64_musl_zstd", "i686-unknown-linux-musl", "zstd"),
    ("32_musl_raw", "i686-unknown-linux-musl", ""),
    ("32_musl_gzip", "i686-unknown-linux-musl", "gzip"),
    ("32_musl_zstd", "i686-unknown-linux-musl", "zstd"),
    ("64_nolibc_raw", "x86_64-unknown-none", ""),
    ("64_nolibc_gzip", "x86_64-unknown-none", "gzip"),
    ("64_nolibc_zstd", "x86_64-unknown-none", "zstd"),
    ("32_nolibc_raw", "i686-unknown-none", ""),
    ("32_nolibc_gzip", "i686-unknown-none", "gzip"),
    ("32_nolibc_zstd", "i686-unknown-none", "zstd"),
)

if not arg_notest:
    if is_vagrant_vm:
        # Use a temporary directory outside of the synchronized folder
        # This is better for file timestamps to stay accurate
        target_dir_name = "/tmp/ocinception-target/target-test"
    else:
        target_dir_name = "target/target-test"

    # Execute the cargo tests
    for rust_target in RUST_TEST_TARGETS:
        for rust_features in ("with-debug", ""):
            print(f"Testing {rust_target} (features={rust_features!r})")
            try:
                subprocess.run(
                    [
                        "cargo",
                        "--offline",
                        "test",
                        "--target",
                        rust_target,
                        "--target-dir",
                        target_dir_name,
                        "--features",
                        rust_features,
                    ],
                    capture_output=arg_quiet,
                    check=True,
                    stdin=subprocess.DEVNULL,
                    cwd=RUST_PROJECT,
                )
            except subprocess.CalledProcessError as exc:
                print("Cargo test failed:")
                print(f"cargo test --target {rust_target} --features {rust_features!r}")
                if arg_quiet:
                    print(exc.output.decode())
                    print(exc.stderr.decode())
                sys.exit(1)

# Remove all previous images
previous_image_tags = (
    subprocess.check_output(["podman", "image", "list", "--format={{.Tag}}", IMAGE_NAME])
    .decode()
    .splitlines()
)

for tag in previous_image_tags:
    print(f"Removing tag {IMAGE_NAME}:{tag}")
    try:
        subprocess.run(
            ["podman", "rmi", f"{IMAGE_NAME}:{tag}"], check=True, stdin=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        if tag != "latest":  # Only stop when it is not possible to remove "latest"
            print("... ignoring error")


for config_name, rust_target, rust_features in BUILD_CONFIGURATIONS:
    # Add optional "with-debug" feature
    if arg_debug:
        rust_features += ("," if rust_features else "") + "with-debug"

    # Use a specific target directory for each configuration
    if is_vagrant_vm:
        target_dir_name = f"/tmp/ocinception-target/target-{config_name}"
    else:
        target_dir_name = f"target/target-{config_name}"

    # print(f"Building {config_name} with target {rust_target} features {rust_features!r}")
    if rust_target == "i686-unknown-none":
        # Custom target requires building core
        subprocess.run(
            [
                "cargo",
                "+nightly",
                "build",
                "--target",
                rust_target + ".json",
                "--target-dir",
                target_dir_name,
                "--release",
                "--features",
                rust_features,
                "-Zbuild-std=core,alloc",
                "-Zbuild-std-features=optimize_for_size",
            ]
            + (["--quiet"] if arg_quiet else []),
            check=True,
            stdin=subprocess.DEVNULL,
            cwd=RUST_PROJECT,
        )
    else:
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
                rust_features,
            ]
            + (["--quiet"] if arg_quiet else []),
            check=True,
            stdin=subprocess.DEVNULL,
            cwd=RUST_PROJECT,
        )
    target_dir_path = RUST_PROJECT / target_dir_name / rust_target / "release"
    compiled_program_path = target_dir_path / "ocinception_2"
    program_path = target_dir_path / "ocinception_2_strip"

    # Strip the section header with llvm-objcopy
    subprocess.run(
        ["llvm-objcopy", "--strip-sections", compiled_program_path.name, program_path.name],
        check=True,
        stdin=subprocess.DEVNULL,
        cwd=target_dir_path,
    )
    with program_path.open("rb") as f_prgm:
        program_bytes = f_prgm.read()

    program_size = program_path.stat().st_size
    assert program_size == len(program_bytes)

    # Craft a 64-byte argument with "latest"
    LATEST_ARG = 'latest",  \n"Hello": "https://www.youtube.com/watch?v=vzKyGv_Pv4s'
    assert len(LATEST_ARG) == 64

    # Run the program to produce an OCI image
    oci_content = subprocess.check_output(
        [program_path, LATEST_ARG],
        stdin=subprocess.DEVNULL,
        cwd="/tmp",
    )
    if not arg_quiet:
        print(f"{config_name}: prog {program_size:6} OCI {len(oci_content):6}")

    # Save the OCI image in the target directory
    saved_oci_image_path = RUST_PROJECT / target_dir_name / f"{IMAGE_NAME}.tar"
    with saved_oci_image_path.open("wb") as fout:
        fout.write(oci_content)

    # Verify the OCI content
    if oci_content.startswith(b"\x28\xb5\x2f\xfd"):
        # Decompress zstd data, as tarfile does not support zstd
        # ZSTD_MAGICNUMBER = 0xFD2FB528: https://github.com/facebook/zstd/blob/e128976193546dceb24249206a02ff8f444f7120/lib/zstd.h#L142
        # Requires: apt install zstd
        decompressed_oci_content = subprocess.check_output(["zstdcat"], input=oci_content)
    elif oci_content.startswith(b"\x1f\x8b\x08\x00"):
        # Decompress with zlib
        decompressed_oci_content = gzip.decompress(oci_content)
    else:
        decompressed_oci_content = oci_content

    # Add padding to the tar data, to enable Python to decode it
    if len(decompressed_oci_content) % 512:
        decompressed_oci_content += b"\0" * (512 - len(decompressed_oci_content) % 512)

    # Check the content of the tar file
    with tarfile.open(fileobj=io.BytesIO(decompressed_oci_content), mode="r") as oci_tar:
        index_file = oci_tar.extractfile("index.json")
        assert index_file is not None
        index_content = index_file.read()
        index_json = json.loads(index_content)
        manifest_digest = index_json["manifests"][0]["digest"].split(":")[-1]
        if index_json != {
            "config": {"entrypoint": ["/s"]},
            "manifests": [
                {
                    "digest": "sha256:" + manifest_digest,
                    "annotations": {
                        "io.containerd.image.name": f"{IMAGE_NAME}:latest",
                        "Hello": "https://www.youtube.com/watch?v=vzKyGv_Pv4s",
                    },
                }
            ],
        }:
            raise RuntimeError(f"Unexpected index.json: {index_json!r}")

        manifest_path = f"blobs/sha256/{manifest_digest}"
        manifest_file = oci_tar.extractfile(manifest_path)
        assert manifest_file is not None
        manifest_content = manifest_file.read()
        manifest_json = json.loads(manifest_content)
        config_digest = manifest_json["config"]["digest"].split(":")[-1]
        layer_digest = manifest_json["layers"][0]["digest"].split(":")[-1]
        if manifest_json != {
            "schemaversion": 2,
            "config": {
                "mediatype": "application/vnd.oci.image.config.v1+json",
                "digest": f"sha256:{config_digest}",
                "size": -1,
            },
            "layers": [{"digest": f"sha256:{layer_digest}"}],
        }:
            raise RuntimeError(f"Unexpected manifest: {manifest_json!r}")
        if manifest_content != json.dumps(manifest_json, separators=(",", ":")).encode():
            raise RuntimeError(f"Unoptimized manifest content: {manifest_content!r}")

        config_path = f"blobs/sha256/{config_digest}"
        config_file_info = oci_tar.getmember(config_path)
        assert config_file_info is not None
        assert config_file_info.islnk()
        assert config_file_info.linkname == "index.json"
        config_file = oci_tar.extractfile(config_path)
        assert config_file is not None
        config_content = config_file.read()
        config_json = json.loads(config_content)
        if config_json != index_json:
            raise RuntimeError(f"Unexpected config: {config_json!r}")

        layer_path = f"blobs/sha256/{layer_digest}"
        layer_file = oci_tar.extractfile(layer_path)
        assert layer_file is not None
        layer_content = layer_file.read()

        padded_layer = layer_content
        if len(padded_layer) % 512:
            padded_layer += b"\0" * (512 - len(padded_layer) % 512)
        with tarfile.open(fileobj=io.BytesIO(padded_layer), mode="r") as layer_tar:
            assert layer_tar.getnames() == ["s"]
            program_info = layer_tar.getmember("s")
            assert program_info is not None
            assert program_info.isreg()
            assert program_info.mode == 5
            program_file = layer_tar.extractfile("s")
            assert program_file is not None
            program_content = program_file.read()
            assert program_content == program_bytes

        computed_layer_digest = hashlib.sha256(layer_content).hexdigest()
        if computed_layer_digest != layer_digest:
            raise RuntimeError(
                f"Unexpected SHA256 layer: {layer_digest} != computed {computed_layer_digest}"
            )

        computed_config_digest = hashlib.sha256(config_content).hexdigest()
        if computed_config_digest != config_digest:
            raise RuntimeError(
                f"Unexpected SHA256 config: {config_digest} != computed {computed_config_digest}"
            )

        file_names = oci_tar.getnames()
        if sorted(file_names) != sorted([layer_path, config_path, manifest_path, "index.json"]):
            raise RuntimeError(f"Unexpected file names {file_names!r}")

        if not arg_quiet:
            # Show size details
            print(f"    {4 * 512:6} tar headers (x4)")
            print(f"    {len(index_content):6} index.json")
            print(f"    {0:6} config (link to index.json)")
            print(f"    {len(manifest_content):6} manifest")
            print(f"    {len(layer_content):6} FS layer")
            padding_sizes = (-len(index_content)) % 512
            padding_sizes += (-len(manifest_content)) % 512
            padding_sizes += (-len(layer_content)) % 512
            remaining = (
                len(decompressed_oci_content)
                - 4 * 512
                - len(index_content)
                - len(manifest_content)
                - len(layer_content)
                - padding_sizes
            )
            print(f"    {padding_sizes:6} 512-block paddings")
            if remaining:
                print(f"    {remaining:6} remaining")
            print(f"  = {len(decompressed_oci_content):6} decompressed OCI image")

    # Ensure the image did not exist previously
    try:
        subprocess.run(["podman", "image", "exists", f"{IMAGE_NAME}:latest"], check=True)
    except subprocess.CalledProcessError:
        pass
    else:
        raise RuntimeError(f"Podman image {IMAGE_NAME}:latest already exists!")

    # Load the image
    podman_load_output = subprocess.check_output(
        ["podman", "load", "--input", saved_oci_image_path.name]
        + (["--quiet"] if arg_quiet else []),
        cwd=saved_oci_image_path.parent,
    )
    if podman_load_output not in {
        f"Loaded image(s): localhost/{IMAGE_NAME}:latest\n".encode(),
        f"Loaded image: localhost/{IMAGE_NAME}:latest\n".encode(),
    }:
        raise RuntimeError(f"Unexpected podman load output: {podman_load_output!r}")

    # Ensure the image was loaded correctly
    subprocess.run(["podman", "image", "exists", f"{IMAGE_NAME}:latest"], check=True)

    # Retag the image, so that latest can be reused
    now = datetime.datetime.now().strftime("%Y%m%d%H%M%S-%f")
    base_tag = f"test_{config_name}_{now}"
    current_tag = hashlib.sha256(base_tag.encode()).hexdigest()
    subprocess.run(
        ["podman", "tag", f"{IMAGE_NAME}:latest", f"{IMAGE_NAME}:{current_tag}"], check=True
    )

    # Remove the previous image before running iterations, to ensure layers are not re-used
    subprocess.run(["podman", "rmi", f"{IMAGE_NAME}:latest"], check=True, stdout=subprocess.DEVNULL)

    # Run the image
    score = len(oci_content)
    for iteration in range(3):
        prev_tag = current_tag
        current_tag = hashlib.sha256(f"{base_tag}_{iteration}".encode()).hexdigest()
        assert len(current_tag) == 64
        if not arg_quiet:
            print(f"    [{config_name} {iteration}] run image {IMAGE_NAME}:{prev_tag}")
        new_oci_content = subprocess.check_output(
            [
                "timeout",
                "8",
                "podman",
                "run",
                "--network=none",
                "--rm",
                "--rmi",
                f"{IMAGE_NAME}:{prev_tag}",
                current_tag,
            ],
            stdin=subprocess.DEVNULL,
            cwd="/tmp",
        )
        if score != len(new_oci_content):
            score = len(new_oci_content)
            if not arg_quiet:
                print(f"    [{config_name} {iteration}] new score {score}")
        # Save the OCI image in the target directory
        with (RUST_PROJECT / target_dir_name / f"{IMAGE_NAME}_{iteration}.tar").open("wb") as fout:
            fout.write(new_oci_content)
        podman_load_output = subprocess.check_output(
            ["podman", "load", "--quiet"],
            input=new_oci_content,
            cwd="/tmp",
        )
        if podman_load_output not in {
            f"Loaded image(s): localhost/{IMAGE_NAME}:{current_tag}\n".encode(),
            f"Loaded image: localhost/{IMAGE_NAME}:{current_tag}\n".encode(),
        }:
            raise RuntimeError(
                f"Unexpected podman load output (iteration {iteration}: {podman_load_output!r}"
            )
        subprocess.run(["podman", "image", "exists", f"{IMAGE_NAME}:{current_tag}"], check=True)

    # Remove the last tag
    subprocess.run(
        ["podman", "rmi", f"{IMAGE_NAME}:{current_tag}"], check=True, stdout=subprocess.DEVNULL
    )
    if score <= MY_BEST_SCORE:
        color_score = "\033[32m"
        color_score_end = "\033[m"
    else:
        color_score = ""
        color_score_end = ""
    if not arg_quiet:
        print(f"    {color_score}{config_name:6} final score {score}{color_score_end}")
    elif score == len(oci_content):
        print(
            f"{color_score}{config_name:14}: prog {program_size:6} score {len(oci_content):6}{color_score_end}"  # noqa: E501
        )
    else:
        print(
            f"{color_score}{config_name:14}: prog {program_size:6} score {len(oci_content):6} -> {score}{color_score_end}"  # noqa: E501
        )
