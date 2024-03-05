# pai

Process Analyzer and Instrumenter

- [Documentation](https://docs.rs/pai/latest)
- [Crate](https://crates.io/crates/pai)

Recommended way to include the crate, even though API is not expected to be
stable until version `0.2.0`, is:

~~~{.toml}
pai = { version = "0.1", features = ["syscalls"] }
~~~

The feature `syscalls` is only needed if you want to resolve the arguments of
system calls. So if you want to resolve the system call number to a name, an
argument to strings, etc.

There are some example of use under `examples/` more information will be written
when the API is more stable.

## Standalone tools using pai

- [pai-strace](https://github.com/rstenvi/pai-strace) - strace-like tool
- [pai-inject-so](https://github.com/rstenvi/pai-inject-so) - inject SO-file into process

## Compilation

A regular build for native can be compiled with:

~~~{.bash}
cargo build --all-features
~~~

### Cross-compilation

The recommended way to cross-compile is to use
[cross](https://github.com/cross-rs/cross)

This is setup in [Makefile.toml](Makefile.toml), so you can build for all
desired targets with:

~~~{.bash}
cargo make build i686-unknown-linux-gnu x86_64-unknown-linux-gnu ...
~~~

Build output from `cross` will sometimes interfere with build output from
`cargo` so all `cross` builds will go to directory `output/`, leaving `target/`
for regular cargo commands.

Builds will then work as expected, but most test-targets will fail because the
testing method used doesn't support `ptrace`.

To run cross-architecture tests correctly see [testing.md](testing.md)

## Targets tested

We don't want to test all cross-combination of builds, but try to test all
platforms supported and all architectures supported.

- **platforms:** GNU, Android, Musl
- **architectures:** x86_64, x86, Aarch64, Aarch32

The [Makefile.toml](Makefile.toml) target `fulltest` is executed before new
versions are published.

## Known issues

- `PTRACE_SINGLESTEP` is not working correctly on `Aarch32` or `Riscv64`. This
  is a deliberate limitation of `Aarch32`, I'm unsure if the same is the case
  for `Riscv64`.
  - As a workaround, we insert a new breakpoint after the instruction to
    simulate a single-step.
  - This workaround is obviously flawed as the next instruction may be a branch.
    This is currently not detected and the step would then be missed completely.
  - This bug may appear even if you don't use single-stepping since
    single-stepping is used internally in those cases we need to redo something
    on the next instruction, like re-inserting a breakppoint.
