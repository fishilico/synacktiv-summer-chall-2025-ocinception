# Write-up for Synacktiv's 2025 Summer Challenge: OCInception

- *Author: [IooNag](https://infosec.exchange/@IooNag) ([GitHub](https://github.com/fishilico))*
- *Date: 2025-09-18*

## 1. An unusual challenge

In summer 2025, Synacktiv [published](https://x.com/Synacktiv/status/1950930087781580992) a quite uncoventional challenge in the cybersecurity world.
Instead of attacking some pieces of software to exploit them, it consisted in creating a file with some specific constraints.
The winner was determined on how small their file was.

The [subject](https://web.archive.org/web/20250801123903/https://www.synacktiv.com/en/publications/2025-summer-challenge-ocinception) started by giving a general overview:

> This challenge is inspired by code golfing, where the goal is to produce the smallest program implementing a feature.
> But this time, it will be about creating the smallest self-replicating Podman image archive...
>
> [...]
>
> To be validated, your archive must be an image capable of generating another image, which in turn will generate another one, and so on!  You can see it as a self-replicating program or Quine, but in an OCI-flavored version!

This sounded fun!

For readers not familiar with the container ecosystem, [Podman](https://podman.io/) is an alternative to [Docker](https://www.docker.com/), [nerdctl](https://github.com/containerd/nerdctl) and other tools used to run applications in constrained environments called *containers*.
Applications get packaged as *container images* that can eventually be published in *container registries* such as [Docker Hub](https://hub.docker.com/), [Quay](https://quay.io/), [GitHub Container Registry](https://github.blog/news-insights/product-news/introducing-github-container-registry/), [GitLab Container Registry](https://docs.gitlab.com/user/packages/container_registry/), etc.
These concepts were pioneered by Docker and enhanced by the ecosystem, leading to the need for proper specifications.
This took the shape of the [Open Container Initiative (OCI)](https://opencontainers.org/), which published the [OCI Image specification](https://github.com/opencontainers/image-spec/blob/v1.0/spec.md) as an alternative to the [Docker Image specification](https://github.com/moby/moby/blob/v25.0.0/image/spec/README.md).

The web page of the challenge provided a [script](./the_ultimate_test_script.sh) to test solutions.
This Bash script gave a bit more details about what was requested:

- It uses a file named `ocinception_nickname.tar` where `nickname` is decided by the participant.
  This is the file to be crafted.
- It loads the file using `podman load` after having completely reset the Podman system (with `podman system reset --force`).
- It expects an image named `ocinception_nickname:latest` to appear in the local registry and tags it with a randomly-generated tag.
- In a loop executed an arbitrary amount of time (the number of iterations is specified on the command line), it generates a new random string `$current_random_tag`, runs the previous image with `$current_random_tag` as parameter and loads the output to `podman load`.
- In the end, it displays the size of the last output as the score (using `stat --printf '... %s' "$FINAL_ARCHIVE_NAME"`).

In short, each iteration of the loop was expected to produce the container image to be executed in the next iteration, by running the image.

Creating an image is quite easy on its own: many tutorials on the Internet explain how to write a `Dockerfile` or a `Containerfile` and run [`podman build`](https://github.com/containers/podman/blob/v4.3.1/docs/source/markdown/podman-build.1.md.in), [`docker buildx build`](https://docs.docker.com/reference/cli/docker/buildx/build/) to convert it to an image.
However creating a self-replicating image sounds more challenging.

## 2. The OCI Image format

Let's take a look at what a container image contains.
Some blog posts already explained with many details what an image contains (for example posts [by Quarkslab](https://blog.quarkslab.com/digging-into-the-oci-image-specification.html) or [by Ravikanth Chaganti](https://ravichaganti.com/blog/2022-10-28-understanding-container-images-oci-image-specification/)).
Instead of repeating their content, let's take a look at an existing image.

Docker Hub hosts a small image named [`hello-world`](https://hub.docker.com/_/hello-world).
In a Debian 12 virtual machine with Podman version [4.3.1](https://packages.debian.org/bookworm/podman), downloading this image is achieved with:

```console
$ podman pull docker.io/hello-world
Trying to pull docker.io/library/hello-world:latest...
Getting image source signatures
Copying blob 17eec7bbc9d7 done  
Copying config 1b44b5a3e0 done  
Writing manifest to image destination
Storing signatures
1b44b5a3e06a9aae883e7bf25e45c100be0bb81a0e01b32de604f3ac44711634
```

The container image gets loaded in Podman's local registry but this is not a file:

```console
$ podman images
docker.io/library/hello-world  latest      1b44b5a3e06a  3 weeks ago  26.7 kB
```

To get a file with the content of the container, `podman save` can be used:

```console
$ podman save --output hello-world docker.io/hello-world
Copying blob 53d204b3dc5d done  
Copying config 1b44b5a3e0 done  
Writing manifest to image destination
Storing signatures

$ file hello-world 
hello-world: POSIX tar archive
```

This is a [Tar archive](https://en.wikipedia.org/wiki/Tar_(computing)).
Let's extract it:

```console
$ tar -xvf hello-world
53d204b3dc5ddbc129df4ce71996b8168711e211274c785de5e0d4eb68ec3851.tar
1b44b5a3e06a9aae883e7bf25e45c100be0bb81a0e01b32de604f3ac44711634.json
ccbb50ff49d360a84143aae385758520507df1c64e403698b61b91aa9d5d3f41/layer.tar
ccbb50ff49d360a84143aae385758520507df1c64e403698b61b91aa9d5d3f41/VERSION
ccbb50ff49d360a84143aae385758520507df1c64e403698b61b91aa9d5d3f41/json
manifest.json
repositories
```

These files do not match the OCI Image Specification described in blog posts.
`podman save` actually used the Docker Image format by default.
Let's remove the extracted files and adjust the `podman save` command:

```console
$ podman save --output hello-world --format oci-archive docker.io/hello-world
Copying blob 53d204b3dc5d done  
Copying config 1b44b5a3e0 done  
Writing manifest to image destination
Storing signatures

$ file hello-world 
hello-world: POSIX tar archive

$ tar -xvf hello-world
blobs/
blobs/sha256/
blobs/sha256/1b44b5a3e06a9aae883e7bf25e45c100be0bb81a0e01b32de604f3ac44711634
blobs/sha256/63d6e0e5091ec3518d33db48051675d3f2c872e092d77d40b1c331dd0de055bf
blobs/sha256/a269ae79fd213f6eca6648e1136c2d1d90d83ff6d73f28b73e85e732661dbe20
index.json
oci-layout
```

By the way, it would have also been possible to use [`skopeo`](https://github.com/containers/skopeo) to get the image in one command:

```sh
skopeo copy docker://docker.io/hello-world oci-archive:hello-world
```

The Tar archive contains 5 files matching the [OCI Layout Specification](https://github.com/opencontainers/image-spec/blob/v1.0/image-layout.md).

To re-create the container image without any dedicated tool such as podman, docker or skopeo, it is essential to understand what each file contains.

```console
$ cat oci-layout 
{"imageLayoutVersion": "1.0.0"}
```

- `oci-layout` contains `{"imageLayoutVersion": "1.0.0"}`.
  This is a [JSON](https://www.json.org/json-en.html) object with a single field.
  It is documented in <https://github.com/opencontainers/image-spec/blob/v1.0/image-layout.md#oci-layout-file>.

```console
$ jq < index.json 
{
  "schemaVersion": 2,
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:63d6e0e5091ec3518d33db48051675d3f2c872e092d77d40b1c331dd0de055bf",
      "size": 911,
      "annotations": {
        "org.opencontainers.image.ref.name": "docker.io/library/hello-world:latest"
      }
    }
  ]
}
```

- `index.json` (the [index](https://github.com/opencontainers/image-spec/blob/v1.0/image-index.md)) contains a JSON with a reference to the manifest, located in directory `blobs/sha256/`.

```console
$ jq < blobs/sha256/63d6e0e5091ec3518d33db48051675d3f2c872e092d77d40b1c331dd0de055bf
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:1b44b5a3e06a9aae883e7bf25e45c100be0bb81a0e01b32de604f3ac44711634",
    "size": 547
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:a269ae79fd213f6eca6648e1136c2d1d90d83ff6d73f28b73e85e732661dbe20",
      "size": 2424
    }
  ],
  "annotations": {
    "com.docker.official-images.bashbrew.arch": "amd64",
    "org.opencontainers.image.base.name": "scratch",
    "org.opencontainers.image.created": "2025-08-08T19:05:17Z",
    "org.opencontainers.image.revision": "6930d60e10e81283a57be3ee3a2b5ca328a40304",
    "org.opencontainers.image.source": "https://github.com/docker-library/hello-world.git#6930d60e10e81283a57be3ee3a2b5ca328a40304:amd64/hello-world",
    "org.opencontainers.image.url": "https://hub.docker.com/_/hello-world",
    "org.opencontainers.image.version": "linux"
  }
}
```

- The [manifest](https://github.com/opencontainers/image-spec/blob/v1.0/manifest.md) contains references to a configuration file and a layer file, as well as some more annotations.

```console
$ jq < blobs/sha256/1b44b5a3e06a9aae883e7bf25e45c100be0bb81a0e01b32de604f3ac44711634
{
  "architecture": "amd64",
  "config": {
    "Env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ],
    "Cmd": [
      "/hello"
    ],
    "WorkingDir": "/"
  },
  "created": "2025-08-08T19:05:17Z",
  "history": [
    {
      "created": "2025-08-08T19:05:17Z",
      "created_by": "COPY hello / # buildkit",
      "comment": "buildkit.dockerfile.v0"
    },
    {
      "created": "2025-08-08T19:05:17Z",
      "created_by": "CMD [\"/hello\"]",
      "comment": "buildkit.dockerfile.v0",
      "empty_layer": true
    }
  ],
  "os": "linux",
  "rootfs": {
    "type": "layers",
    "diff_ids": [
      "sha256:53d204b3dc5ddbc129df4ce71996b8168711e211274c785de5e0d4eb68ec3851"
    ]
  }
}
```

- The [configuration](https://github.com/opencontainers/image-spec/blob/v1.0/config.md) contains a JSON object specifying how the container is launched.
  The referenced layer in `rootfs.diff_ids[0]` does not exist in `blobs/sha256/`.
  This is because the layer was compressed in a file referenced in the manifest.

```console
$ file blobs/sha256/a269ae79fd213f6eca6648e1136c2d1d90d83ff6d73f28b73e85e732661dbe20
blobs/sha256/a269ae79fd213f6eca6648e1136c2d1d90d83ff6d73f28b73e85e732661dbe20: gzip compressed data, original size modulo 2^32 11776

$ gunzip < blobs/sha256/a269ae79fd213f6eca6648e1136c2d1d90d83ff6d73f28b73e85e732661dbe20 | sha256sum 
53d204b3dc5ddbc129df4ce71996b8168711e211274c785de5e0d4eb68ec3851  -

$ gunzip < blobs/sha256/a269ae79fd213f6eca6648e1136c2d1d90d83ff6d73f28b73e85e732661dbe20 | file -
/dev/stdin: POSIX tar archive

$ tar xvzf blobs/sha256/a269ae79fd213f6eca6648e1136c2d1d90d83ff6d73f28b73e85e732661dbe20
hello

$ file hello
hello: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```

- The [filesystem layer](https://github.com/opencontainers/image-spec/blob/v1.0/layer.md) is a compressed Tar archive containing the filesystem used by the container.
  Here, it contains a single program, compiled from a [simple C file](https://github.com/docker-library/hello-world/blob/c29a5d34cdbda000754de575d8805a8c062597d7/hello.c).

Packing the image again is possible with command `tar`:

```sh
$ tar -c oci-layout index.json blobs/sha256/{63d6e0e5091ec3518d33db48051675d3f2c872e092d77d40b1c331dd0de055bf,1b44b5a3e06a9aae883e7bf25e45c100be0bb81a0e01b32de604f3ac44711634,a269ae79fd213f6eca6648e1136c2d1d90d83ff6d73f28b73e85e732661dbe20} \
  | podman load
Getting image source signatures
Copying blob a269ae79fd21 skipped: already exists  
Copying config 1b44b5a3e0 done  
Writing manifest to image destination
Storing signatures
Loaded image: docker.io/library/hello-world:latest
```

Back to the challenge, how can the image be made as small as possible?

First, it seems to be possible to remove `oci-layout`, even though the [specification](https://github.com/opencontainers/image-spec/blob/v1.0/image-layout.md#content) states it must exist.

Then, every metadata field in JSON objects can be removed.
After modifying the files, their [SHA256 digests](https://en.wikipedia.org/wiki/SHA-2) need to be updated.
Moreover, some fields are actually unneeded and can be removed from the JSON objects.
Another trick is that fields `size` can be removed or set to `-1` ([thanks to a helpful condition in `storageImageDestination.putBlobToPendingFile`](https://github.com/containers/image/blob/v5.36.2/storage/storage_dest.go#L309-L310)).
Here are some commands which generate a much smaller image, not compliant with OCI Image Specification but still able to be loaded by Podman.

```console
$ echo -n '{"config":{"cmd":["/hello"]}}' > config
$ sha256sum config
8b8a7e4ee28b9ca8b6d7ca53204b31064163b8cd4ba5fe15dfac2f2d73451721  config
$ mv config blobs/sha256/8b8a7e4ee28b9ca8b6d7ca53204b31064163b8cd4ba5fe15dfac2f2d73451721
$ echo -n '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:8b8a7e4ee28b9ca8b6d7ca53204b31064163b8cd4ba5fe15dfac2f2d73451721","size":-1},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:a269ae79fd213f6eca6648e1136c2d1d90d83ff6d73f28b73e85e732661dbe20"}]}' > manifest
$ sha256sum manifest
ec71c10d72bcee3c5428b6697c412f0dda0a7f0975c557674290e303f4345ce5  manifest
$ mv manifest blobs/sha256/ec71c10d72bcee3c5428b6697c412f0dda0a7f0975c557674290e303f4345ce5
$ echo -n '{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:ec71c10d72bcee3c5428b6697c412f0dda0a7f0975c557674290e303f4345ce5"}]}' > index.json
$ tar -c index.json blobs/sha256/{ec71c10d72bcee3c5428b6697c412f0dda0a7f0975c557674290e303f4345ce5,8b8a7e4ee28b9ca8b6d7ca53204b31064163b8cd4ba5fe15dfac2f2d73451721,a269ae79fd213f6eca6648e1136c2d1d90d83ff6d73f28b73e85e732661dbe20} > my-hello.tar
$ podman load --input my-hello.tar
Getting image source signatures
Copying blob a269ae79fd21 done  
Copying config 8b8a7e4ee2 done  
Writing manifest to image destination
Storing signatures
Loaded image: sha256:8b8a7e4ee28b9ca8b6d7ca53204b31064163b8cd4ba5fe15dfac2f2d73451721
```

This command displays the ID of the image, which is the digest of the configuration.
No tag was defined, and the image is referenced as `<none>` in Podman:

```console
$ podman images
REPOSITORY  TAG         IMAGE ID      CREATED        SIZE
<none>      <none>      8b8a7e4ee28b  1 minutes ago  12.6 kB
```

It is nonetheless possible to launch it:

```console
$ podman run --rm -it 8b8a7e4ee28b

Hello from Docker!
This message shows that your installation appears to be working correctly.
```

## 3. A better OCI image

The previous section explained how to assemble an OCI image.
Before going to making a self-replicating image archive, it needs to be slightly adjusted:

First, when launching the container with a parameter, the program still needs to run. Currently, the image reports an error:

```console
$ podman run --rm -it 8b8a7e4ee28b some_random_string
Error: crun: executable file `some_random_string` not found in $PATH: No such file or directory: OCI runtime attempted to invoke a command that was not found
```

This issue is fixed by defining an [*entrypoint*](https://github.com/opencontainers/image-spec/blob/v1.0/config.md#:~:text=Entrypoint%20array%20of%20strings%2C%20OPTIONAL) instead of a *command* in the configuration.

Then, the image needs to define a tag when it is loaded.
The specification defines [annotation `org.opencontainers.image.ref.name` in `index.json`](https://github.com/opencontainers/image-spec/blob/v1.0.1/annotations.md#:~:text=org.opencontainers.image.ref.name).
This was what the `hello-world` image used.
Nonetheless, Podman also supports another annotation, `io.containerd.image.name`, according to [function `nameFromAnnotations` in `libimage`](https://github.com/containers/podman/blob/v4.3.1/vendor/github.com/containers/common/libimage/pull.go#L199-L203) (and [GitHub issue #12560](https://github.com/containers/podman/issues/12560)):

```go
// nameFromAnnotations returns a reference string to be used as an image name,
// or an empty string.  The annotations map may be nil.
func nameFromAnnotations(annotations map[string]string) string {
    if annotations == nil {
        return ""
    }
    // buildkit/containerd are using a custom annotation see
    // containers/podman/issues/12560.
    if annotations["io.containerd.image.name"] != "" {
        return annotations["io.containerd.image.name"]
    }
    return annotations[ociSpec.AnnotationRefName]
}
```

This other annotation is shorter than the first.

What about using other digest algorithms?
Unfortunately [`go-digest`](https://github.com/containers/podman/blob/v4.3.1/vendor/github.com/opencontainers/go-digest/algorithm.go#L31-L41) only supports algorithms producing at least 32 bytes, so SHA256 is the shortest one.

The regular expression used to verify digests in [`containers/image`](https://github.com/containers/podman/blob/v4.3.1/vendor/github.com/containers/image/v5/docker/reference/regexp.go#L43-L44) seems to support digests with only 32 hexdigits (so 16 bytes):

```go
// DigestRegexp matches valid digests.
DigestRegexp = match(`[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*[:][[:xdigit:]]{32,}`)
```

However in practice, no supported digest algorithm seemed to support generating 16-byte digests.

Would it be possible to compress the image?
Yes!
`podman load` supports loading archives compressed with [GZip](https://en.wikipedia.org/wiki/Gzip) or [Zstandard](https://en.wikipedia.org/wiki/Zstd).
These commands confirm this:

```console
$ gzip --best < my-hello.tar > my-hello.tar.gz
$ podman load --input my-hello.tar.gz

$ zstd --ultra -22 < my-hello.tar > my-hello.tar.zstd
$ podman load --input my-hello.tar.zstd

$ stat --format='%s %n' my-hello.tar*
10240 my-hello.tar
3068 my-hello.tar.gz
2988 my-hello.tar.zstd
```

This enables crafting very small OCI images.

## 4. Towards self-replication

In previous sections, a simple usual container image was studied.
How is it possible to create one which creates itself?

First, how a program can output its content?
This is actually an easy task on Linux-based system: open the program file, read it and write the content to the standard output.
In Rust, this takes few lines of code:

```rust
use std::io::Write;

fn main() {
    let content = std::fs::read("/proc/self/exe").unwrap();
    std::io::stdout().write_all(&content).unwrap();
}
```

This used the `exe` symbolic link to the program, in the [process-specific subdirectory `/proc/self/`](https://docs.kernel.org/filesystems/proc.html#process-specific-subdirectories).
It is also possible to use the first program argument (named `argv[0]` in C):

```rust
use std::io::Write;

fn main() {
    let program_name = std::env::args().next().unwrap();
    let content = std::fs::read(program_name).unwrap();
    std::io::stdout().write_all(&content).unwrap();
}
```

Then, the program needs to craft a filesystem layer.
Reading the [specification of the Tar file format](https://www.gnu.org/software/tar/manual/html_node/Standard.html), this means crafting a 512-byte header, adding some optional extension headers, the content and a footer consisting of 1024 zero bytes.
This could be achieved with [Rust crate `tar`](https://crates.io/crates/tar).

```rust
let mut layer_tar = tar::Builder::new(Vec::new());
let mut header = tar::Header::new_old();
header.set_path(PROGRAM_NAME).unwrap();
header.set_mode(0o555); // Set the program executable
header.set_size(content.len() as u64);
header.set_cksum();
layer_tar.append(&mut header, &content[..]).unwrap();
let layer_tar_bytes = layer_tar.into_inner().unwrap();
```

However, it is possible to make the Tar overhead much smaller:

- The 1024-zero footer is actually optional in Podman (and actually when using [Go's `tar.Reader`](https://cs.opensource.google/go/go/+/refs/tags/go1.25.0:src/archive/tar/reader.go)).
- It is not even required for the Tar archive to have a size aligned on 512 bytes.
- The mode can be a single octal digit, `5` (for permissions read, `4`, and execute, `1`).

So instead of relying on a Rust crate, it seems necessary to directly create a Tar header, to craft an archive as small as possible.

```rust
// Fill field size and compute the tar header checksum
fn set_tar_header_size_cksum(tar_header: &mut [u8], size: usize) {
    if size != 0 {
        // Write the size in octal in tar_header[124..136]
        let octal_size = format!("{size:o}").into_bytes();
        assert!(octal_size.len() <= 12);
        tar_header[124..][..octal_size.len()].copy_from_slice(&octal_size);
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

const PROGRAM_NAME: &str = "s";

fn main() {
    // ...
    let mut fs_tar_header = [0u8; 512];
    fs_tar_header[..PROGRAM_NAME.len()].copy_from_slice(
        PROGRAM_NAME.as_bytes());
    fs_tar_header[100] = b'5'; // Set mode to rx
    set_tar_header_size_cksum(&mut fs_tar_header, content.len());
    let layer_tar_bytes = [filesystem_tar_header.as_ref(), &content].concat();
}
```

Once the layer is created, its SHA256 digest needs to be computed.
Because this digest depends on the content of the program itself, it cannot be computed while compiling the program (more generally, it is considered impossible for a file to contain its own SHA256 digest).
Therefore, let's use [`sha2`](https://crates.io/crates/sha2) to compute the digest and [`hex`](https://crates.io/crates/hex) to encode it in hexadecimal:

```rust
let layer_tar_sha256 = hex::encode(sha2::Sha256::digest(&layer_tar_bytes));
```

Finally, creating a container image is a matter of creating a configuration, a manifest and an index and joining all these components together in a single archive with code such as:

```rust
let mut layer_header = [0u8; 512];
layer_header[0..77]
    .copy_from_slice(&format!("blobs/sha256/{}", layer_tar_sha256).into_bytes());
set_tar_header_size_cksum(&mut layer_header, layer_tar_bytes.len());
image_tar_bytes.extend(layer_header);
image_tar_bytes.extend(&layer_tar_bytes);
```

This is what the Rust project [`ocinception_1_rust_std`](./ocinception_1_rust_std) does.
Moreover, this project enables compressing the resulting image with either GZip or Zstandard, using cargo features that can be enabled when compiling.

Running it seems to work:

```console
$ cd ocinception_1_rust_std
$ cargo run -r | podman load
    Finished `release` profile [optimized] target(s) in 0.10s
     Running `target/release/ocinception_6`
Getting image source signatures
Copying blob d0eb8cd266ae done  
Copying config e51991d5c6 done  
Writing manifest to image destination
Storing signatures
Loaded image: localhost/ocinception_1:latest
```

But launching the container fails:

```console
$ podman run --rm -it localhost/ocinception_1:latest
{"msg":"exec container process (missing dynamic library?) `/s`: No such file or directory","level":"error"}
```

Of course, as the program is built as a dynamically-linked executable, it will not work in a container image without any shared libraries.

To fix this, the program needs to be linked statically.
With Rust, this is a matter of installing a toolchain using [Musl](https://musl.libc.org/):

```console
$ rustup target add x86_64-unknown-linux-musl
$ sudo apt install -y musl-tools
$ cargo run -r --target x86_64-unknown-linux-musl | podman load
[...]
Error: payload does not match any of the supported image formats:
 * oci: initializing source oci:/var/tmp/podman3699972949:: open /var/tmp/podman3699972949/index.json: not a directory
 * oci-archive: committing the finished image: image with ID "e51991d5c6c243c04e6b0f06982b1dea6032ec12452f73550d726bb2dc46d9f1" already exists, but uses a different top layer: that ID is already in use
 * docker-archive: loading tar component manifest.json: file does not exist
 * dir: open /var/tmp/podman3699972949/manifest.json: not a directory
```

What is it, this time?
The program is generating a new image with different content but with the same configuration (`e51991d5c6c243c04e6b0f06982b1dea6032ec12452f73550d726bb2dc46d9f1` is the SHA256 digest of `{"config":{"entrypoint":["/s"]}}`).
To make Podman happy, it is necessary to first remove the previous image.

```console
$ podman rmi e51991d5c6c243c04e6b0f06982b1dea6032ec12452f73550d726bb2dc46d9f1
Untagged: localhost/ocinception_1:latest
Deleted: e51991d5c6c243c04e6b0f06982b1dea6032ec12452f73550d726bb2dc46d9f1

$ cargo run -qr --target x86_64-unknown-linux-musl | podman load --quiet
Loaded image: localhost/ocinception_1:latest

$ podman run --rm localhost/ocinception_1:latest 12345678 > next-image.tar
$ podman load --quiet --input next-image.tar 
Loaded image: localhost/ocinception_1:12345678
```

This is looking good.

What does the [Ultimate Test Script](./the_ultimate_test_script.sh) says?

```console
$ cargo run -qr --target x86_64-unknown-linux-musl > ocinception_1.tar
$ ../the_ultimate_test_script.sh 1 3
Loaded image: localhost/ocinception_1:latest
Loaded image: localhost/ocinception_1:f4f67250ccf8bceea16410dfc47f3af9a67591b6b9ed330b00fac6ea80a9b2d6
Loaded image: localhost/ocinception_1:16cc16e43060c68e4608fb484b0dc3db2c724b14e378c752f363d57ae5cef63c
Loaded image: localhost/ocinception_1:e29c77c5691f28744ec914ad00cda77f9ea8590652f92a74eddf989a06e9146c
🦭 Well done little seal! Your score: 595320 🦭
```

The score is so high!
Contrary to usual games, the aim of the challenge is to get a score as low as possible.

Now there is a Rust project, it does not take much time to test a few tricks to optimize the score.
For example, compressing the image with Zstandard is just a matter of enabling a feature:

```console
$ cargo run -qr --target x86_64-unknown-linux-musl --features=zstd > ocinception_1.tar
$ ../the_ultimate_test_script.sh 1 3
Loaded image: localhost/ocinception_1:latest
Loaded image: localhost/ocinception_1:42ae69caab426607cf6b0d120ef89de8c4497e959b9aa9d488b7231e525feebc
Loaded image: localhost/ocinception_1:163ff18017a052880caf99cc5d82fac5c068c2c955f806f557d5ac68c3da6740
Loaded image: localhost/ocinception_1:627d314ceb74265344d5fc2272e71c3fe6dd96391ad6f9f7314c9437163088a6
🦭 Well done little seal! Your score: 429441 🦭
```

Can the image be optimized more?

## 5. Shrinking the image

Some tricks can be implemented to make the image more likely to compress better:

- The file mode (containing permissions) can be empty in the main Tar archive.
- The octal numbers in the Tar header can be written without leading zeros (some Tar libraries add leading zeros to fill the whole field).
- Every JSON object can use lowercase letters, thanks to [Go's `json.Unmarshal`](https://pkg.go.dev/encoding/json#Unmarshal) matching keys case-insensitively.

What about reducing the size of the program?

This is actually not necessary.
Reading the [Ultimate Test Script](./the_ultimate_test_script.sh) again, something strange appears to be going on.
Before the provided image is launched, it is tagged with a different (random) tag:

```sh
current_random_tag=$(head -c 32 /dev/urandom | sha256sum | awk '{print $1}')
podman tag "$IMAGE_NAME:latest" "$IMAGE_NAME:$current_random_tag"
```

When `podman run --network=none --rm --rmi ...` runs, it deletes the image (thanks to option `--rmi`) but the `latest` tag stays in Podman local registry.
In the end, the script removes the last random tag, but `latest` stays:

```console
$ podman images
REPOSITORY               TAG         IMAGE ID      CREATED         SIZE
localhost/ocinception_1  latest      e51991d5c6c2  ...             1.16 MB
```

This detail has an interesting consequence: Podman does not import layers it already has.
So the layer can actually be removed from the image to reduce its size even more.

In practice, the Rust program can:

- generate the whole image (with a layer containing itself) when being executed without any argument ;
- or generate an image without the layer blob when being executed with a command-line argument (to handle executions by the [Ultimate Test Script](./the_ultimate_test_script.sh)).

Doing so makes the score much lower!

Some other ideas can be experimented:

- In Tar headers, the size can be written directly in binary instead of octal, in Big Endian with a `0x80` prefix.
  This is thanks to [Go function `tar.parser.parseNumeric`](https://cs.opensource.google/go/go/+/refs/tags/go1.25.0:src/archive/tar/strconv.go;l=85) supporting this format even for Tar archives using the "old format".

- Podman supports loading images in the Docker archive format.
  Like OCI images, this format uses Tar and can be compressed.
  Nevertheless, Podman does not support removing the layer from such an archive: doing so triggers an error, "Inconsistent layer count: 0 in manifest, 1 in config".

  - Actually, [Synacktiv's solution](https://www.synacktiv.com/en/publications/2025-summer-challenge-writeup) uses the Docker archive format and work around this issue by adding a file with an empty name to the archive.
    This way, when `podman load` sees the manifest with `"layers":[""]`, it knows there is a file, and when it sees the configuration with the right SHA256 digest of the layer, it uses it.

- Zstandard compression format includes an optional checksum which can be disabled (contrary to GZip).

- The SHA256 digest of some blobs can be modified to see whether Podman actually verifies them.
  It never verifies the digest of the manifest!
  So it can be replaced by a fake one which compresses better, like `1111111111111111111111111111111111111111111111111111111111111111` or the provided random tag.

- As the digest of the manifest can be manipulated, the configuration and the index can be merged together and the image can use a tar link to make the manifest target index.json:

```json
{
  "config": {
    "entrypoint": [
      "/s"
    ]
  },
  "manifests": [
    {
      "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "annotations": {
        "org.opencontainers.image.ref.name": "ocinception_1:latest"
      }
    }
  ]
}
```

Is any of these ideas worth it?
Some were implemented using Rust features.
This enables comparing the result when each one is used.
This was done in a simple Bash script, [`test_features.sh`](./ocinception_1_rust_std/test_features.sh) (some features were negated, so that the default build produces the lowest score):

```console
$ ./ocinception_1_rust_std/test_features.sh
  2784 
  2784 tar-binary-size
  2784 never-use-arg-as-manifest-digest
  2323 merge-config-index
   408 gz
   421 gz,tar-binary-size
   411 gz,never-use-arg-as-manifest-digest
   414 gz,merge-config-index
   393 zstd
   408 zstd,tar-binary-size
   394 zstd,never-use-arg-as-manifest-digest
   405 zstd,merge-config-index

$ cd ocinception_1_rust_std/target/target-zstd
$ ../../../the_ultimate_test_script.sh 1 3
Loaded image: localhost/ocinception_1:latest
Loaded image: localhost/ocinception_1:41af8808810037c26c1857e8a984d13ed3684d31fbb5aea526efd2b7a835cf80
Loaded image: localhost/ocinception_1:01afd8a22652917dc8432665b8f6148e1d567ef6c7df485c00cdc36751f2ad43
Loaded image: localhost/ocinception_1:c503a484208577d1e294e9443e15d80b916eb75cbcdf27f2973602f4940702d5
🦭 Well done little seal! Your score: 393 🦭
```

This seems to be a good score!

## 6. (Bonus) Code-golfing the executable

Removing the actual filesystem layer felt like cheating.
Even though the organizers of the challenge confirmed this was an intended (and accepted) solution, this broke the principle of self-replicating program or Quine: the image needs to be already loaded to make it work.

What happens when we keep the layer?
The score explodes, because Rust binaries are quite large by default.

Some people already explained how to produce tiny Rust programs and shared some tricks to make tiny ELF executable files:

- <https://mainisusuallyafunction.blogspot.com/2015/01/151-byte-static-linux-binary-in-rust.html>
- <https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html>
- <http://hookrace.net/blog/nim-binary-size/>
- <https://github.com/johnthagen/min-sized-rust>

The first steps almost always consist in enabling some options in [`.cargo/config.toml`](./ocinception_2_libc_nostd/.cargo/config.toml) and the second step to be getting rid of Rust's standard library, known to be quite large.

Let's create a new project, [`ocinception_2_libc_nostd`](./ocinception_2_libc_nostd), where the code is made as small as possible while still relying on the C library (this last dependency will be removed later).

The project needs to compute some SHA256 digests.
Instead of relying on [RustCrypto's `sha2`](https://crates.io/crates/sha2), it is possible to implement the algorithm directly in the project.
Or another option exists, which makes the code much smaller: using [Linux crypto userspace API](https://www.kernel.org/doc/html/v6.16/crypto/userspace-if.html).
This involves some socket invocations to create a *transformation file descriptor* `tfmfd` and an *operation file descriptor* `opfd` to finally use the SHA256 implementation provided by Linux kernel:

```rust
const AF_ALG: u32 = 38;
const SOCK_SEQPACKET: u32 = 5;

// Fill a struct sockaddr_alg to use SHA256
let mut addr_buffer = [0u8; 88];
addr_buffer[0] = AF_ALG as u8; // salg_family
addr_buffer[2..6].copy_from_slice(b"hash"); // salg_type
addr_buffer[24..30].copy_from_slice(b"sha256"); // salg_name

let tfmfd = syscall_socket(AF_ALG, SOCK_SEQPACKET, 0);
syscall_bind(tfmfd, addr_buffer.as_ptr(), addr_buffer.len());
let opfd = syscall_accept1(tfmfd);

// Compute the SHA256 digest of some data
let mut digest = [0u8; 32];
syscall_write(opfd, data.as_ptr(), data.len());
syscall_read(opfd, digest.as_mut_ptr(), digest.len());
```

This was implemented in [`src/sha256.rs`](./ocinception_2_libc_nostd/src/sha256.rs).

By the way, `/proc/crypto` shows that the kernel also implements [Deflate compression algorithm](https://elixir.bootlin.com/linux/v6.1/source/crypto/deflate.c), which is used in GZip.
Nevertheless, this implementation seems to be restricted to some IPSec features and it does not seem possible to invoke it from an unprivileged userspace program.
This is well-known on [Stack Overflow](https://stackoverflow.com/questions/73669175/can-i-use-af-alg-to-compress).

The SHA256 digests need to be transformed in hexadecimal in the OCI image.
Instead of using [crate `hex`](https://crates.io/crates/hex) or Rust standard format macro `format!("{:02x}{:02x}...")`, a much smaller implementation is possible on 32-bit x86 architecture, written in [assembly poem 0x1e of book *xchg rax,rax*](https://www.xorpd.net/pages/xchg_rax/snip_1e.html):

```text
cmp      al,0x0a
sbb      al,0x69
das
```

More precisely, this sequence of instructions uses [`cmp` (Compare)](https://revers.engineering/x86/cmp.pdf), [`sbb` (Integer Subtraction With Borrow)](https://revers.engineering/x86/sbb.pdf) and [`das` (Decimal Adjust AL After Subtraction)](https://revers.engineering/x86/das.pdf) to convert a nibble (byte between `0` and `0xf` included) to a character.
To better understand how this sequence works, here is a table showing the values of register `al`, carry flag `cf` and arithmetic flag `af` after each instructions:

| Initial `al` | After `cmp` | After `sbb` | `al` after `das` |
| --- | --- | --- | --- |
| `0x0` | `cf=1` | `al=0x96`, `cf=1`, `af=1` | `0x96 - 0x66 = 0x30 '0'` |
| `0x1` | `cf=1` | `al=0x97`, `cf=1`, `af=1` | `0x97 - 0x66 = 0x31 '1'` |
| `0x2` | `cf=1` | `al=0x98`, `cf=1`, `af=1` | `0x98 - 0x66 = 0x32 '2'` |
| `0x3` | `cf=1` | `al=0x99`, `cf=1`, `af=1` | `0x99 - 0x66 = 0x33 '3'` |
| `0x4` | `cf=1` | `al=0x9a`, `cf=1`, `af=1` | `0x9a - 0x66 = 0x34 '4'` |
| `0x5` | `cf=1` | `al=0x9b`, `cf=1`, `af=1` | `0x9b - 0x66 = 0x35 '5'` |
| `0x6` | `cf=1` | `al=0x9c`, `cf=1`, `af=1` | `0x9c - 0x66 = 0x36 '6'` |
| `0x7` | `cf=1` | `al=0x9d`, `cf=1`, `af=1` | `0x9d - 0x66 = 0x37 '7'` |
| `0x8` | `cf=1` | `al=0x9e`, `cf=1`, `af=1` | `0x9e - 0x66 = 0x38 '8'` |
| `0x9` | `cf=1` | `al=0x9f`, `cf=1`, `af=1` | `0x9f - 0x66 = 0x39 '9'` |
| `0xa` | `cf=0` | `al=0xa1`, `cf=1`, `af=0` | `0xa1 - 0x60 = 0x41 'A'` |
| `0xb` | `cf=0` | `al=0xa2`, `cf=1`, `af=0` | `0xa2 - 0x60 = 0x42 'B'` |
| `0xc` | `cf=0` | `al=0xa3`, `cf=1`, `af=0` | `0xa3 - 0x60 = 0x43 'C'` |
| `0xd` | `cf=0` | `al=0xa4`, `cf=1`, `af=0` | `0xa4 - 0x60 = 0x44 'D'` |
| `0xe` | `cf=0` | `al=0xa5`, `cf=1`, `af=0` | `0xa5 - 0x60 = 0x45 'E'` |
| `0xf` | `cf=0` | `al=0xa6`, `cf=1`, `af=0` | `0xa6 - 0x60 = 0x46 'F'` |

These 3 instructions achieved what would otherwise require a conditional operation to correctly map `0xa` to `'A'`, `0xb` to `'B'`, etc.
There are nonetheless two issues:

- The resulting character is in uppercase while OCI images require digests to be lowercase.
  This is fixed by adding `0x20` to the value of letters.
  Observing the values, this can be achieved without any branch with `or al, 0x20`.
- Instruction `das` only exists in 32-bit x86 instruction set.
  It has been removed from the 64-bit instruction set.
  This does not actually cause any issue as many code-golfing guides recommend using 32-bit x86 instruction set because it produces shorter instructions.

Moreover, the code only converts a single nibble. To convert 32 bytes from `esi` to a 64-character string in `edi`, a loop needs to be added, which process each nibble one after another.
Here is a 29-byte assembly function implementing such a loop using 2 decrementing counters (in registers `ecx` and `edx`):

```text
$ echo 6a 20 5a 89 d1 ac c1 c8 04 a8 4a 3c 0a 1c 69 2f 0c 20 aa c1 e8 1c 39 d1 74 f0 e2 e9 c3 | xxd -p -r > hexlify.bin
$ objdump -D -bbinary -mi386 -Mintel hexlify.bin
   0:  6a 20              push   0x20
   2:  5a                 pop    edx
   3:  89 d1              mov    ecx,edx
   5:  ac                 lods   al,BYTE PTR ds:[esi]
   6:  c1 c8 04           ror    eax,0x4
   9:  a8 4a              test   al,0x4a  ; This instruction is a "skip"
   -> a: 4a                 dec    edx    ; ... for this one

   b:  3c 0a              cmp    al,0xa
   d:  1c 69              sbb    al,0x69
   f:  2f                 das
  10:  0c 20              or     al,0x20
  12:  aa                 stos   BYTE PTR es:[edi],al

  13:  c1 e8 1c           shr    eax,0x1c
  16:  39 d1              cmp    ecx,edx
  18:  74 f0              je     0xa
  1a:  e2 e9              loop   0x5
  1c:  c3                 ret
```

This was implemented in [function `sha256_hex` in `src/sha256.rs`](./ocinception_2_libc_nostd/src/sha256.rs#L51-L127).

About assembly instructions, it is well known that function `memcpy` can be implemented with 2 bytes using [`rep`](https://revers.engineering/x86/rep.pdf) and [`movs`](https://revers.engineering/x86/movs.pdf):

```text
f3 a4      rep movs BYTE PTR es:[edi],BYTE PTR ds:[esi]
```

Creating a Rust function taking advantage of these instructions could be as simple as:

```rust
pub unsafe fn asm_memcpy(mut dst: *mut u8, src: *const u8, size: usize) {
    unsafe {
        #[cfg(target_arch = "x86")]
        core::arch::asm!(
            "rep movsb byte ptr es:[edi], byte ptr [esi]",
            inout("esi") src => _,
            inout("edi") dst => _,
            inout("ecx") size => _,
            options(nostack, preserves_flags)
        );
    }
}
```

But this does does not compile:

```console
$ cargo build --release --target i686-unknown-linux-musl
   Compiling ocinception_2 v0.1.0 (/vagrant/ocinception_2_libc_nostd)
error: cannot use register `si`: esi is used internally by LLVM and cannot be used as an operand for inline asm
   --> src/mem_ops.rs:143:13
    |
143 |             inout("esi") src => _,
    |             ^^^^^^^^^^^^^^^^^^^^^

error: could not compile `ocinception_2` (bin "ocinception_2") due to 1 previous error
```

Indeed, the Rust compiler has forbidden us from using register `esi` as a parameter of the inline `asm!` macro since 2021 ([Pull Request #84658: Be stricter about rejecting LLVM reserved registers in asm!](https://github.com/rust-lang/rust/pull/84658) ; [Zulip discussion from 2021](https://rust-lang.zulipchat.com/#narrow/channel/216763-project-inline-asm/topic/Handling.20clobbers)) because LLVM is [internally using `esi`](https://github.com/llvm/llvm-project/blob/01f36b39bd2475a271bbeb95fb9db8ed65e2d065/llvm/lib/Target/X86/X86RegisterInfo.cpp#L83) to store the base address of local variables when variable-length arrays are used on the stack.

Instead, Rust code may gently request the compiler to use another available register to store the source address.
To use `esi` anyway, the code is required to save and restore its value so that the inline `asm!` block does not appear to modify it:

```rust
pub unsafe fn asm_memcpy(mut dst: *mut u8, src: *const u8, size: usize) {
    unsafe {
        #[cfg(target_arch = "x86")]
        core::arch::asm!(
            "xchg esi, {src}",
            "rep movsb byte ptr es:[edi], byte ptr [esi]",
            "mov esi, {src}",
            src = inout(reg) src => _,  // esi is used internally by LLVM
            inout("edi") dst => _,
            inout("ecx") size => _,
            options(nostack, preserves_flags)
        );
    }
}
```

Doing so does not produce optimal assembly code: these save/restore instructions can accumulate much.
To generate less instructions using Rust functions, the only way consists in inlining all `asm!` blocks in calling functions and making sure they do not modify `esi` in unintended ways.

This is what [project `ocinception_3_asm`](./ocinception_3_asm) did.

Before going into much details with this last project, other optimisations can be implemented.

## 7. (Bonus) Custom compression: RLE and base64-like

As seen in previous sections, the OCI image can be compressed with GZip and Zstandard formats.
Using the compression implementation from the usual crates ([`miniz_oxide`](https://crates.io/crates/miniz_oxide) and [`zstd`](https://crates.io/crates/zstd)) takes much space (about tens of kilobytes).
How would it be possible to do better?

Both Deflate algorithm (used in GZip file format) and Zstandard support a simple compression mode called Runtime Length Encoding (RLE).
Deflate RLE mode is nonetheless not so straightforward to implement because it still requires handling bits instead of bytes (more precisely: symbols make take 8 or 9 bits using the fixed Huffman codes from [section 3.2.6. of RFC 1951](https://datatracker.ietf.org/doc/html/rfc1951#section-3.2.6)).

Contrary to Deflate, Zstandard supports a byte-oriented encoding to repeat a single byte.
Reading [RFC 8878](https://datatracker.ietf.org/doc/html/rfc8878) enables constructing a simple test Zstandard file to show how RLE encoding works, in Python:

```python
# Frame header: Zstandard Magic 0xFD2FB528 (section 3.1.1)
zstd_data = b"\x28\xb5\x2f\xfd"
# Frame Header Descriptor: no option set
zstd_data += b"\0"
# Window Descriptor: 2 MB
zstd_data += b"\x58"

# Add a raw (uncompressed) block
chunk = b"Hello"
block_header = (len(chunk) << 3)
zstd_data += block_header.to_bytes(3, "little") + chunk

# Repeat 20 spaces using RLE encoding
block_header = (20 << 3) | 2
zstd_data += block_header.to_bytes(3, "little") + b" "

# Add a last raw block
chunk = b"world!"
block_header = (len(chunk) << 3) | 1
zstd_data += block_header.to_bytes(3, "little") + chunk

print(zstd_data)
# => b'(\xb5/\xfd\x00X(\x00\x00Hello\xa2\x00\x00 1\x00\x00world!'

# Run zstdcat to uncompress the data
import subprocess
output = subprocess.check_output("zstdcat", input=zstd_data)
print(output)
# => b'Hello                    world!'
```

Detecting repeated bytes is quite easy.
Actually, in x86 assembly there even exists an instruction to count how many times a byte is repeated: `repe scasb al, byte ptr es:[edi]` (using [SCAS (Scan String)](https://revers.engineering/x86/scas.pdf)).

This enables compressing most blocks of zero bytes without adding much code.

Nonetheless this no longer compresses data such as the strings used by the program to generate the JSON files.
Can they be compressed anyway?

Grouping all strings in a single place ([`src/global_strings.rs`](./ocinception_2_libc_nostd/src/global_strings.rs)) and deduplicating what is possible leads to the following sequence:

```text
blobs/sha256/
1index.json"
{"schemaversion":2,"config":{"mediatype":"application/vnd.oci.image.config.v1+json",
","size":-1},"layers":[{"digest":"sha256:
hash
"{"config":{"entrypoint":["/s"]},"manifests":[{
","annotations":{"io.containerd.image.name":"ocinception_2:
"}}]}
```

By the way, as Go JSON unmarshalling accepts lowercase identifiers, every uppercase letter was transformed into lowercase.

These strings are using 38 distinct characters: `"+,-./1256:[]_abcdefghijlmnoprstvxyz{}`.
Each character can be represented by 6 bits, in an encoding similar as base64!

Moreover, taking a look as the [ASCII table](https://en.wikipedia.org/wiki/ASCII), the encoding cab=n involves only 2 ranges (much simpler than the actual base64 encoding!):

- 0x22 (`"`) to 0x3a (`:`): 25 characters
- 0x5b (`[`) to 0x7d (`}`): 35 characters

So the encoding contains 25 + 35 = 60 characters.
It is possible to specify that the first symbol of the custom base64-encoding marks the end of stream.
This means that to decode a 6-bit symbol:

- `0` is the end of stream.
- `1...25` maps to character `symbol - 1 + 0x22`.
- `26...61` maps to character `symbol - 26 + 0x5b`.

Such a logic is very straightforward to implement in assembly using a single conditional branch.
Moreover some tricks from a [code-golf solution for base64 encoding](https://codegolf.stackexchange.com/questions/26584/convert-a-bytes-array-to-base64/158039#158039) can be used to make the string decompressor very short ([function `decompress_strings` in `src/global_strings.rs`](./ocinception_2_libc_nostd/src/global_strings.rs#L172-L227)):

```text
<decompress_strings>:
804914c:  55                      push   ebp
804914d:  89 e5                   mov    ebp,esp
804914f:  57                      push   edi
8049150:  bf 61 c0 04 08          mov    edi,0x804c061 ; decompressed strings
8049155:  56                      push   esi
8049156:  be 00 a0 04 08          mov    esi,0x804a000 ; compressed strings
                      ; Load 3 bytes from the compressed strings
804915b:  4e                      dec    esi
804915c:  ad                      lods   eax,DWORD PTR ds:[esi]
                      ; Repeat 4 times to decode symbols
804915d:  6a 04                   push   0x4
804915f:  59                      pop    ecx
8049160:  c1 c0 06                rol    eax,0x6
8049163:  24 3f                   and    al,0x3f
8049165:  74 0d                   je     8049174 <decompress_strings+0x28>
8049167:  3c 1a                   cmp    al,0x1a
8049169:  72 02                   jb     804916d <decompress_strings+0x21>
804916b:  04 20                   add    al,0x20
804916d:  04 21                   add    al,0x21
804916f:  aa                      stos   BYTE PTR es:[edi],al
8049170:  e2 ee                   loop   8049160 <decompress_strings+0x14>
                      ; Jump to the next 3-byte symbols
8049172:  eb e7                   jmp    804915b <decompress_strings+0xf>
                      ; End of the function
8049174:  5e                      pop    esi
8049175:  5f                      pop    edi
8049176:  5d                      pop    ebp
8049177:  c3                      ret
```

Now, how is it possible to compress the strings in a way which makes it quite easy to maintain (and to change the content of the strings)?
In Rust, the most straightforward way consists in using a `const` function, which.
Such a function is executed when the project is being built.

In [`src/global_strings.rs`](./ocinception_2_libc_nostd/src/global_strings.rs#L71-L147), both the concatenation of all strings and the compressed string are built using constant functions:

```rust
const STRINGS: [u8; ALL_STRING_LENGTHS] = concatenate_strings();

const fn compress_char(c: u8) -> u8 {
    if c < b'[' { c - b'!' } else { c - b'[' + 26 }
}

const fn compress_strings() -> [u8; 201] {
    let mut compressed = [0u8; 201];
    let mut pos = 0usize;
    while pos < STRINGS.len() / 4 {
        let sym0 = compress_char(STRINGS[4 * pos]);
        let sym1 = compress_char(STRINGS[4 * pos + 1]);
        let sym2 = compress_char(STRINGS[4 * pos + 2]);
        let sym3 = compress_char(STRINGS[4 * pos + 3]);
        compressed[3 * pos] = sym3 | (sym2 << 6);
        compressed[3 * pos + 1] = (sym2 >> 2) | (sym1 << 4);
        compressed[3 * pos + 2] = (sym1 >> 4) | (sym0 << 2);
        pos += 1;
    }
    compressed
}

static COMPRESSED_STRINGS: [u8; 201] = compress_strings();
```

Even though `STRINGS` and `COMPRESSED_STRINGS` are both global variables, only `COMPRESSED_STRINGS` appears in the compiled program: `STRINGS` is never used directly.

## 8. (Bonus) Removing the C library

After implementing a few tricks to save size, something still takes much space: the C library.
This is the component which provides the interface with the Linux kernel: system calls (*syscalls*) to use some features ; `_start` code to retrieve the arguments and set a few things up before the usual `main` ; dynamic memory allocator (functions `malloc`, `free`...) ; etc.

To remove this dependency, two things need to be done:

1. Every feature provided by the C library needs to be implemented on its own.
  This is something documented in many places.
  In this repository:

  - syscalls were implemented in [`src/linux_syscall.rs`](./ocinception_2_libc_nostd/src/linux_syscalls.rs) ;
  - a simple allocator for Rust was implemented in [`src/nostd_bump_alloc.rs`](./ocinception_2_libc_nostd/src/nostd_bump_alloc.rs) ;
  - a simple `_start` function was implemented in [`src/main.rs`](./ocinception_2_libc_nostd/src/main.rs#L156-L183).

2. The compilation needs to link without a C library.
  When using x86_64, there directly exists a Rust toolchain for this: `x86_64-unknown-none` (and using it is as simple as `rustup target add x86_64-unknown-none && cargo --target x86_64-unknown-none ...`).
  But there is no 32-bit `-none` toolchain in `rustup target list`.
  To compile without a C library, a custom Rust target needs to be defined.

The second point seems difficult at first glance.
Thankfully, using a custom Rust target for which the system already has a working LLVM compiler is actually quite simple, thanks to information from [the rustc book, section 7.2 Custom Targets](https://doc.rust-lang.org/beta/rustc/targets/custom.html):

```console
# Display the JSON for a supported 32-bit x86 target for Linux
$ rustc +nightly -Z unstable-options --print target-spec-json --target i686-unknown-linux-musl
{
  "arch": "x86",
  "cpu": "pentium4",
  "crt-objects-fallback": "musl",
  "crt-static-default": true,
  "crt-static-respected": true,
  "data-layout": "e-m:e-p:32:32-p270:32:32-p271:32:32-p272:64:64-i128:128-f64:32:64-f80:32-n8:16:32-S128",
  "dynamic-linking": true,
...

# Display the associated JSON Schema
$ rustc +nightly -Zunstable-options --print target-spec-json-schema
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "TargetSpecJson",
  "type": "object",
  "properties": {
    "abi": {
      "type": [
        "string",
        "null"
      ]
...

# Validate the JSON schema
$ sudo apt install python3-jsonschema
$ rustc +nightly -Z unstable-options --print target-spec-json --target i686-unknown-linux-musl | jsonschema "$(rustc +nightly --print sysroot)/etc/target-spec-json-schema.json"
```

Adjusting a few fields, [`i686-unknown-none.json`](./ocinception_2_libc_nostd/i686-unknown-none.json) was created.
Using it directly unfortunately does not work:

```console
$ cd ocinception_2_libc_nostd/
$ cargo build -r --target i686-unknown-none.json
error[E0463]: can't find crate for `core`
  |
  = note: the `i686-unknown-none` target may not be installed
  = help: consider downloading the target with `rustup target add i686-unknown-none`

For more information about this error, try `rustc --explain E0463`.
error: could not compile `ocinception_2` (bin "ocinception_2") due to 1 previous error
```

Indeed, even though the project does not use Rust's standard library, `core` crate is still required.
`cargo` can compile it on its own when using the `nightly` toolchain:

```console
$ rustup component add --toolchain nightly rust-src
$ cargo +nightly build -r --target i686-unknown-none.json -Zbuild-std=core

$ stat -c '%s %n' target/i686-unknown-linux-musl/release/ocinception_2 target/i686-unknown-none/release/ocinception_2
15920 target/i686-unknown-linux-musl/release/ocinception_2
2500 target/i686-unknown-none/release/ocinception_2
```

Wow, 13 KB saved just by removing the C library!

While at it, it is possible to also remove the symbols, the section header and a few other things (such as section `.comment`) from the executable:

```console
$ llvm-objcopy --strip-sections target/i686-unknown-none/release/ocinception_2{,_strip}
$ stat -c '%s %n' target/i686-unknown-none/release/ocinception_2{,_strip}
2500 target/i686-unknown-none/release/ocinception_2
1208 target/i686-unknown-none/release/ocinception_2_strip
```

The program is now only 1.2 KB large.
So small!

And this result is before optimizing the assembly code to remove unneeded instructions used to save register `esi`, as [project `ocinception_3_asm`](./ocinception_3_asm) does.

## 9. (Bonus) Crafting a custom ELF using a linker script

Analyzing the executable produced by using `i686-unknown-none` target leads to an annoying observation: the program header always contains a `GNU_STACK` entry:

```console
$ readelf -l ocinception_3_asm/target/i686-unknown-none/release/ocinception_3
Elf file type is EXEC (Executable file)
Entry point 0x100009e
There are 2 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD           0x000074 0x01000074 0x01000074 0x002e3 0x1223a RWE 0x1
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0

 Section to Segment mapping:
  Segment Sections...
   00     .text .rodata .bss 
   01   
```

This is a security feature (to ensure the stack is not executable) but this adds some bytes that can be removed to reduce the score for the challenge.

Instead of going to war with LLVM's linker `lld`, reading [A Whirlwind Tutorial on Creating Really Teensy ELF Executables for Linux (or, "Size Is Everything")](https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html) gave the idea of customizing the ELF header directly.
Can this be done without having to use a raw assembly file?
Yes, using `global_asm!` to write the header using raw assembly statements and a linker script to craft the final ELF file.

More precisely, [`src/main.rs`](./ocinception_3_asm/src/main.rs#L171-L220) contains an ELF header mixing both the executable header (`Ehdr`), the program header (`Phdr`) and some code:

```rust
core::arch::global_asm!(
    ".pushsection .headers, \"ax\"",
    "ELF_ehdr:",
    ".int 0x464c457f",           // Elf32_Ehdr.e_ident[EI_MAG0..3] = ELF magic
    "_start:", // Elf32_Ehdr.e_ident[...] contains the entrypoint (12 bytes)
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
    ".byte 7",   // Elf32_Phdr.p_flags = PF_R | PR_W | PF_X
    //".byte 0, 0, 0, 0, 0, 0", // Skip unneeded zeros
    "ELF_phdr_size = . - ELF_phdr + 7",
    ".popsection",
    COMPRESSED_STRINGS = sym COMPRESSED_STRINGS,
    STRINGS = sym DECOMPRESSED_STRINGS,
    real_start = sym real_start,
);
```

(By the way, using `mov esi, OFFSET ...` instead of `lea esi, ...` makes the instruction takes 5 bytes instead of 6, which makes it fit in the header.)

The linker script [`linker_script_optim.ld`](./ocinception_3_asm/linker_script_optim.ld) generates a file which is "binary" from the point of view of the linker (not ELF), but which will in practice be an ELF file with a very custom header.
It also defines some symbols used by the ELF header (`__executable_start`, `file_size` and `file_memory_size`):

```text
OUTPUT_FORMAT("binary")
OUTPUT_ARCH(i386)

SECTIONS {
    __executable_start = 0x01000000;
    . = __executable_start;
    .data : {
        KEEP(*(.headers))
        /* ... */
        KEEP(*(.text*))
        KEEP(*(.rodata*))
        KEEP(*(.data*))
    }
    file_size = ABSOLUTE(. - __executable_start);
    .bss : {
        /* ... */
    }
    file_memory_size = ABSOLUTE(. - __executable_start);
    /DISCARD/ : {
        *(.comment)
    }
}
```

To use the linker script, option `-Clink-args=-Tlinker_script_optim.ld` is automatically added when using the *optim* target thanks to a setting in [`.cargo/config.toml`](./ocinception_3_asm/.cargo/config.toml#L60).

A few other low-level assembly and linker tricks were used in `ocinception_3_asm` and this write-up is already too long to cover everything (for example, the last Zstandard block header is actually computed in the linker script ; the buffer holding the uncompressed OCI image fits exactly what is needed as its size depends on `file_size` ; the content of the program is copied using `memcpy(buffer, __executable_start, file_size)` instead of `open`+`read` ; ...).

In the end, the test script `./test_all.py --quiet` builds a 798-byte ELF file which produces a 1655-byte OCI image compressed with Zstandard RLE mode.

```console
$ cd /tmp/ocinception-target/target-32_optim_zstd/
$ stat -c '%s %n' i686-unknown-optim/release/ocinception_3 ocinception_3.tar
798 i686-unknown-optim/release/ocinception_3
1655 ocinception_3.tar

$ xxd -a i686-unknown-optim/release/ocinception_3
00000000: 7f45 4c46 be58 0200 01bf 2103 0001 eb5f  .ELF.X....!...._
00000010: 0200 0300 0100 0000 0400 0001 2c00 0000  ............,...
00000020: 0000 0000 0000 0000 3400 2000 0100 0000  ........4. .....
00000030: 0000 0000 0000 0001 0000 0001 1e03 0000  ................
00000040: 3c22 0100 0756 83c6 7cc6 0680 0fc8 8946  <"...V..|......F
00000050: 085e f7e1 fec6 fec5 ac01 c2e2 fbb1 0589  .^..............
00000060: d024 070c 3088 440e 93c1 ea03 e2f1 c34e  .$..0.D........N
00000070: adb1 04c1 c006 243f 740d 3c1a 7202 0420  ......$?t.<.r.. 
00000080: 0421 aae2 eeeb e88d 7c24 c0be af03 0001  .!......|$......
00000090: a566 a546 83ef 1ea4 47a5 b867 0100 00b3  .f.F....G..g....
000000a0: 26b1 05cd 8089 c38d 4ffa 6a58 5a66 b869  &.......O.jXZf.i
000000b0: 01cd 8031 c931 f6f7 e166 b86c 01cd 80bd  ...1.1...f.l....
000000c0: 4500 0001 be00 0c01 0156 c606 73c6 4664  E........V..s.Fd
000000d0: 3566 b81e 03ff d58d 75bb bf00 0e01 0166  5f......u......f
000000e0: b91e 03f3 a459 66ba 1e05 52bf ce08 0101  .....Yf...R.....
000000f0: 57e8 3301 0000 bf00 0a01 0157 be21 0300  W.3........W.!..
00000100: 01b1 0df3 a458 5e50 b140 f3a4 5e58 ffd5  .....X^P.@..^X..
00000110: bf00 0201 0157 bebb 0300 01b1 2ef3 a456  .....W.........V
00000120: 83c6 bcb1 11f3 a45e b061 b140 f3aa b13b  .......^.a.@...;
00000130: f3a4 568b 7424 10b1 40f3 a45e a5a4 59bf  ..V.t$..@..^..Y.
00000140: 6508 0101 5766 baff 0052 e8da 0000 0066  e...Wf...R.....f
00000150: 31ff 57be 2f03 0001 b10a f3a4 5e58 ffd5  1.W./.......^X..
00000160: bf00 0401 0189 fbbe 2103 0001 b10d f3a4  ........!.......
00000170: 5eb1 40f3 a483 c74f be2e 0300 01b1 0bf3  ^.@....O........
00000180: a489 dee8 cafe ffff bf00 0801 01be 3903  ..............9.
00000190: 0001 b154 f3a4 5683 c618 b111 f3a4 5e83  ...T..V.......^.
000001a0: c740 b129 f3a4 c747 4022 7d5d 7dbf 0006  .@.)...G@"}]}...
000001b0: 0101 57be 2103 0001 b10d f3a4 b061 b140  ..W.!........a.@
000001c0: f3aa 5e66 b812 01ff d566 31ff be24 1101  ..^f.....f1..$..
000001d0: 0131 ed8b 0747 3b07 7524 89e9 c1e5 0374  .1...G;.u$.....t
000001e0: 0601 2e01 ce31 ed31 c949 f3ae 4ff7 d1c1  .....1.1.I..O...
000001f0: e018 8d44 c802 8946 0383 c607 ebd5 8844  ...D...F.......D
00000200: 2e03 4581 ff1e 1101 0175 c831 db66 c706  ..E......u.1.f..
00000210: 3917 c707 28b5 2ffd 89f9 66ba 7706 6a04  9...(./...f.w.j.
00000220: 5843 cd80 89d8 4bcd 806a 0458 89c3 cd80  XC....K..j.X....
00000230: 6a03 588d 4c24 e06a 205a cd80 89ce 89d1  j.X.L$.j Z......
00000240: acc1 c804 a84a 3c0a 1c69 2f0c 20aa c1e8  .....J<..i/. ...
00000250: 1c39 d174 f0e2 e9c3 a1bb 86a7 ecc8 1515  .9.t............
00000260: 812d 0a39 cd4d 8ead 2ba7 a21c e820 4b9e  .-.9.M..+.... K.
00000270: 724c d641 eba2 c112 6565 eb8a 5960 a224  rL.A....ee..Y`.$
00000280: 1be8 3388 8e01 f9e2 2f18 6422 babe 2e3a  ..3...../.d"...:
00000290: 836d edb4 a2db 8c2c daa0 0d69 8265 eb8a  .m.....,...i.e..
000002a0: 7563 a272 aa40 4bd0 ba72 b004 0199 a33c  uc.r.@K..r.....<
000002b0: c464 e01a 2c72 4ce2 ba96 0526 3a06 c12c  .d..,rL....&:..,
000002c0: 93a7 1c64 1515 81e0 5964 817e ca65 eb8a  ...d....Yd.~.e..
000002d0: 5960 a22d 19e8 2f1e cf73 8bba 8196 055c  Y`.-../..s.....\
000002e0: 203b 6cb0 f025 da82 f22c 93ba 9605 60b0   ;l..%...,....`.
000002f0: 04b3 dbb6 2e3a 8359 20b7 2e1a e8ad 2b36  .....:.Y .....+6
00000300: 2d0a cecd 1893 26c8 a260 db90 5940 b2a8  -.....&..`..Y@..
00000310: e806 2f29 b6ad 8bce 4126 793c c7f3       ../)....A&y<..

$  /vagrant/the_ultimate_test_script.sh 3 5
Loaded image: localhost/ocinception_3:latest
Loaded image: localhost/ocinception_3:0339e92f6582fdd1ff7ceaf15250203e368e6624a02a0fc8177453b27edf20fc
Loaded image: localhost/ocinception_3:9f02b2e6a4910087d4559e35c877f6862152cbc4cdf73894a332f0309cb87326
Loaded image: localhost/ocinception_3:28c7152d2b692249caaba4751f73b8b5ca9221b4e58e682b59e7b3bdcded2fd6
Loaded image: localhost/ocinception_3:8cfdd0d5653fbcaf223c09a297bdcdcbf4d44548f92c39ee7d4c4a3041fcbc78
Loaded image: localhost/ocinception_3:04fa93815f201d98ddc45afaabc0732595899f2ad3fe7bb650c1e5c5e9494dc5
🦭 Well done little seal! Your score: 1655 🦭
```

## Conclusion and comments about Rust

The challenge of crafting an OCI image as small as possible was interesting.
It enabled digging in the specification, finding corner cases to optimize, etc.
While not necessary for the challenge, optimizing the size of a program was also something fun to do.
I hope readers learnt a few tricks from this detailed write-up.

Last but not least, why did I use Rust to solve this challenge?
Wouldn't Go be more appropriate when working with subjects related to containers (as most tools and libraries are written in Go), or assembly be better for low-level programming with heavy size constraints?

Here are some reasons why I chose Rust:

- Its rich ecosystem of [*crates*](https://crates.io/) enables to quickly prototype.
  Crafting a Tar archive and computing SHA256 digests are very straightforward tasks, whereas in other languages (such as C/C++) it would involve integrating libraries in a complex way.
- It is possible to replace some functions with assembly and C code.
  More generally Rust's [Foreign Function Interface (FFI)](https://doc.rust-lang.org/nomicon/ffi.html) makes it possible to mix Rust with other languages.
  It is all the more amazing to be able to compute values in a linker script which are directly used in Rust functions.
- The type system enables catching many errors at compile time.
  It also enables fearlessy refactoring the code as there is a feeling that if something is missed, `rustc` will complain.
- Integrating some tests (with `cargo test`) is easy and also makes iterating optimizations fast.
  Using `cargo` in general is a breeze, compared to Makefiles, CMake...
- The feature flags make it possible to test several hypotheses in parallel and see which one works.
- Functions executed at compile-time (`const fn`) and Rust macros are very powerful and expressive yet very readable.
  Doing something equivalent as the base64-like string compression function with the C preprocessor or C++ templates is much more difficult to achieve and I expect making the code easy to read/understand afterwards to be quite challenging.

Anyway, using Rust also came with some frustrating aspects:

- Not being able to tell the compiler "I'm going to use register `esi` in inline `asm!` statements, please take care of saving/restoring its value if it is used around" is quite unpleasant.
  This is all the more frustrating when LLVM chooses to use `esi` in a `reg` variable of the inline `asm!` statement and there is no way to tell it to use another register (in short: this generated code like `mov esi, esi` and there is no way to mark `esi` as clobbered, which would make LLVM choose another register).
- Many interesting features are still unstable.
  For example, aligning functions to byte instead of 4 bytes requires [unstable feature `fn_align`](https://github.com/rust-lang/rust/issues/82232) (there seems to be some recent activity going on).
  Moreover, while concatenating literal strings with `concat!("...", "...")` is stable, concatenating bytes [requires unstable feature `concat_bytes`](https://github.com/rust-lang/rust/issues/87555).
  Even though it is possible to use `concat!("...", "...").as_bytes()` or a `const fn` which concatenates all strings into a slice, it makes the code much shorter to be able to concatenate bytes (in [`ocinception_3_asm`](./ocinception_3_asm/src/main.rs#L34-L53)).
- Adding the option to build `core` to `.cargo/config.toml` (`build-std = ["core", "alloc"]` in section `[unstable]`) breaks `cargo test` and there is no way to override this setting on the command line (`-Zno-build-std` does not exist):

```console
$ cargo +nightly test
error[E0152]: duplicate lang item in crate `core` (which `std` depends on): `sized`
  |
  = note: the lang item is first defined in crate `core` (which `ocinception_2` depends on)
  = note: first definition in `core` loaded from /vagrant/ocinception_2_libc_nostd/target/debug/deps/libcore-32b1eff6ed7c25c4.rlib
  = note: second definition in `core` loaded from /home/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/lib/libcore-c4b9a47e748cccbc.rlib

For more information about this error, try `rustc --explain E0152`.
error: could not compile `ocinception_2` (bin "ocinception_2" test) due to 1 previous error
```

Anyway, this challenge was fun and the knowledge I learnt while solving it will be useful on several Rust projects I am interacting with, such as the [Rust SDK for Ledger device applications](https://github.com/LedgerHQ/ledger-device-rust-sdk), [Ledger Vanadium](https://github.com/LedgerHQ/vanadium), Solana Programs ([Anchor](https://github.com/solana-foundation/anchor), [Pinocchio](https://github.com/anza-xyz/pinocchio)...), various Zero-Knowledge cryptography projects ([arkworks](https://github.com/arkworks-rs), [RISC Zero](https://github.com/risc0/risc0)), etc.
