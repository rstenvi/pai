# pai

Process Analyzer and Instrumenter

- [Documentation](https://docs.rs/pai/latest)
- [Crate](https://crates.io/crates/pai)

Recommended way to include the crate, even though API is not expected to be
stable until version `0.2.0`, is:

~~~
pai = { version = "0.1", features = ["syscalls"] }
~~~

The feature `syscalls` is only needed if you want to resolve the arguments of
system calls. So if you want to resolve the system call number to a name, an
argument to strings, etc.

There are some example of use under `examples/` more information will be written when the API is more stable.

## Standalone tools using pai

- [pai-strace](https://github.com/rstenvi/pai-strace) - strace-like tool

## Cross-compilation

For information about how cross-compilation of Rust programs work, see
[Cross-compilation](https://rust-lang.github.io/rustup/cross-compilation.html)
in the rustup book.

### Targets tested

- `x86_64-unknown-linux-gnu`
- `i686-unknown-linux-gnu`
- `aarch64-unkown-linux-gnu`
- `aarch64-linux-android`
- `armv7-unknown-linux-gnueabihf` - ARMv7-A Linux, hardfloat (kernel 3.2, glibc 2.17)
- `arm-unknown-linux-gnueabihf` - ARMv6 Linux, hardfloat (kernel 3.2, glibc 2.17)

### Targets we check build for

These targets are built, but there is no automatic testing for them

- `arm-unknown-linux-gnueabi` - ARMv6 Linux (kernel 3.2, glibc 2.17)
- `x86_64-linux-android`
- `i686-linux-android`

### Recommended method in Docker

The recommended way to cross-compile is to use [cross](https://github.com/cross-rs/cross)

Builds will then work as expected, but most test-targets will fail because the
testing method used doesn't support `ptrace`.

To run cross-architecture tests correctly see [testing.md](testing.md)