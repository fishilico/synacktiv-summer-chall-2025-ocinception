# Solution for Synacktiv's 2025 Summer Challenge: OCInception

This repository contains a solution of a challenge organized by Synacktiv in August 2025: [2025 Summer Challenge: OCInception](https://www.synacktiv.com/en/publications/2025-summer-challenge-ocinception).

There is a [write-up](./writeup.md) and 3 Rust projects:

- [`ocinception_1_rust_std`](./ocinception_1_rust_std) contains a solution which optimizes the score while not optimizing the size of the program at all (it uses Rust's standard library and few dependencies).
- [`ocinception_2_libc_nostd`](./ocinception_2_libc_nostd) tries to optimize the size of the program using some tricks (like removing the standard library) and can be seen as an intermediate step to the next project. It still uses a C library.
- [`ocinception_3_asm`](./ocinception_3_asm) contains a solution heavily optimized towards reducing the size of the program. Even though it is still Rust, most functions contain x86 assembly code.
  Moreover, it involves magical tricks with linker scripts and it produces an ELF file which is mostly invalid but still somehow accepted by the Linux kernel.

The first 2 projects were tested with Rust stable version 1.88.0 (2025-06-23) and the 3rd one with Rust nightly 1.91.0.

## Vagrant virtual machine

These projects were successfully built in a Debian 12 virtual machine.
To make my setup reproducible, I used [Vagrant](https://developer.hashicorp.com/vagrant) and this repository contains the [`Vagrantfile`](./Vagrantfile) I used.

Here is how this file can be used to compile and run the 3 projects:

```console
$ vagrant up
[...]

$ vagrant ssh
[...]

vagrant@bookworm:~$ cd /vagrant/ocinception_1_rust_std/
vagrant@bookworm:/vagrant/ocinception_1_rust_std$ ./test_features.sh
  2784 
  2784 tar-binary-size
  2784 never-use-arg-as-manifest-digest
  2323 merge-config-index
   408 gz
   423 gz,tar-binary-size
   411 gz,never-use-arg-as-manifest-digest
   411 gz,merge-config-index
   391 zstd
   409 zstd,tar-binary-size
   393 zstd,never-use-arg-as-manifest-digest
   403 zstd,merge-config-index

# Best score is 391

vagrant@bookworm:/vagrant/ocinception_1_rust_std$ cd ../ocinception_2_libc_nostd/
vagrant@bookworm:/vagrant/github/ocinception_2_libc_nostd$ ./test_all.py --quiet
Testing x86_64-unknown-linux-gnu (features='with-debug')
Testing x86_64-unknown-linux-gnu (features='')
Testing x86_64-unknown-linux-musl (features='with-debug')
Testing x86_64-unknown-linux-musl (features='')
Testing i686-unknown-linux-musl (features='with-debug')
Testing i686-unknown-linux-musl (features='')
64_musl_raw   : prog  12304 score  15888
64_musl_gzip  : prog  24592 score  12731 -> 12727
64_musl_zstd  : prog  12304 score   4496
32_musl_raw   : prog  12304 score  15888
32_musl_gzip  : prog  24592 score  12731 -> 12727
32_musl_zstd  : prog  12304 score   4496
64_nolibc_raw : prog   1440 score   5024
64_nolibc_gzip: prog  17328 score  10749 -> 10740
64_nolibc_zstd: prog   1744 score   2564
32_nolibc_raw : prog   1208 score   4792
32_nolibc_gzip: prog  16212 score  10432 -> 10433
32_nolibc_zstd: prog   1505 score   2356

vagrant@bookworm:/vagrant/github/ocinception_2_libc_nostd$ cd ../ocinception_3_asm/
vagrant@bookworm:/vagrant/github/ocinception_3_asm$ ./test_all.py --quiet
Testing i686-unknown-linux-musl (features='with-debug,gzip')
Testing i686-unknown-linux-musl (features='gzip')
32_none_zstd  : prog    855 score   1700
32_none_gzip  : prog  15648 score  10201 -> 10194
32_optim_zstd : prog    798 score   1655
32_optim_gzip : prog  15588 score  10192 -> 10189

# Best score is 1655 with a 798-byte program
```

the [Ultimate Test Script](./the_ultimate_test_script.sh) provided by the challenge authors can also be used to test the solution:

```console
vagrant@bookworm:~$ cd /vagrant/ocinception_1_rust_std/
vagrant@bookworm:/vagrant/github/ocinception_1_rust_std$ cargo run -r \
  --target x86_64-unknown-linux-musl --features zstd > ocinception_1.tar
[...]
vagrant@bookworm:/vagrant/github/ocinception_1_rust_std$ ../the_ultimate_test_script.sh 1 10
Loaded image: localhost/ocinception_1:latest
Loaded image: localhost/ocinception_1:93006d645386c884f7ec8008c23b961d4d074fc27172c3136a6d6058593004d1
Loaded image: localhost/ocinception_1:4a88a98380b82874a14300adc6ac0c06b6311eb40dbe8631b9623b2cffce36a9
Loaded image: localhost/ocinception_1:2cc6ec65344591798004c6c1d02bd2892baa66b7f95f23732c77cdf8e724bd7f
Loaded image: localhost/ocinception_1:218d50f13677c7afdcf06f7fd286a02bff99d81bf01e305decf99ef484a07533
Loaded image: localhost/ocinception_1:251c8e4a34a7af1d28229a754b46d1b6f19a97ffc140bb210dbc2f6f7af6b2a5
Loaded image: localhost/ocinception_1:ab443f8ebaa810e83a34b0b23c1220b0c2e880094c302ff1149a0ab1ffd34953
Loaded image: localhost/ocinception_1:42922c86375be450efc93311ce0726978dd39a40b7d8c803524a96891a8bcf2b
Loaded image: localhost/ocinception_1:f5ce4f100ef3a4e461df03f98702f6136296f558748a9f0e151f386d6c81e788
Loaded image: localhost/ocinception_1:adaf4b1a40d6c9d8dd592fd5d0a9ddf516997ee7cdb55677b4d63a8ce5ecad5c
Loaded image: localhost/ocinception_1:c0eb0cb429e8d1d8523eecad29f627945b6f31f0d8c2e3d7d56ecd7e88fbb48d
🦭 Well done little seal! Your score: 393 🦭
```
