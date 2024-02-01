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

### Recommended method in Docker

The recommended way to cross-compile is to use [cross](https://github.com/cross-rs/cross)

Builds will then work as expected, but most test-targets will fail because the
testing method used doesn't support `ptrace`.

### Use host-compilers

To compile, `cargo` needs to know how to link the target:

- Ensure the `linker` in `.cargo/config.toml` is available in `$PATH`
	- Alternatively, you could change the linker used
- If you want to test the target, you may also need to change the `runner` variable

For `linux-gnu` targets, the linker is typically available through `apt`. For
android targets, they are available through [Android
NDK](https://developer.android.com/tools/sdk/ndk/index.html)

### Architecture-specific code

Most code in the crate is architecture-agnostic, but the actual tracing of the
process, gettings registers, reading memory, etc is obviously
architecture-specific. To support an architecture we need:

- An abstraction layer which allows us to get/set common register values, like
  instruction pointer, system call arguments, etc.
- Assembly snippets for injecting code, breakpoint, call trampoline, etc.
- Support in tracing crate [pete](https://github.com/rstenvi/pete)
  - The published version of `pete` only support `x86_64` and `Aarch64` and only on Linux
  - The git repo linked above includes my own modifications to support other
    targets, that repo will be used when building in this repo. That version of
    `pete` is not used when installing from `crates.io`.
  - I haven't tested the second point below, but I think:
    - If you cross-compile from `x86_64-linux-gnu` to
    `arm-unknown-linux-gnueabi` it should work
    - If you install from `crates.io` on `arm-unknown-linux-gnueabi`, it will
      **not** work (because when published on crates.io, the version of `pete`
      will be the one published on `crates.io`)
- Support in crate [libc](https://github.com/rstenvi/libc)
  - On some architectures/platforms, constants or structs are missing in `libc`
    crate
  - I therefore maintain my own fork for version `0.2` with the added structs
    and constants
  - This will hopefully be merged in the real crate at some point
- To verify correctness, we also build some programs located under `testdata/`
  - These programs are built with a C-compiler in `build.rs`
  - For the tests to run correctly, that script must be able to find out the
    proper C-compiler and the compiler must be in path.
    - If this is not the case, it will silently fail and the resulting test will fail.
	- A silent fail was chosen because then it will succeed on a non-test build

