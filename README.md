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

- [pai-strace](https://github.com/rstenvi/pai-strace)
	- Strace-like tool
