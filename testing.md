# Testing

To run all available tests on host target run:

~~~{.bash}
cargo make test
~~~

## Cross-platform tests

Cross-platform tests are handled by
[scripts/test-runner.rs](scripts/test-runner.rs). For each architecture that
should be tested, a configuration entry has to be made in
[runner_config.toml](runner_config.toml).

### Native

The entry for native test is empty and it will just run the `cross test`
command.

~~~{.toml}
[host.x86_64-unknown-linux-gnu]

~~~

### SSH

Below is an example of a config to execute over SSH. The only necessary parts
for this to work is to have a server with the appropriate architecture and
generate SSH-keys.

~~~{.toml}
[ssh.aarch64-unknown-linux-gnu]
user = "pai"
host = "pai.testserver.local"
port = 22
identity = "/path/to/keys/pai_id_rsa"
~~~

### QEMU

Below is an example for running in QEMU using the script in
[scripts/qemu-runner.rs](scripts/qemu-runner.rs).

~~~{.toml}
user = "shell"
disk = "scripts/images/i686-linux-gnu/rootfs.qcow2"
kernel = "scripts/images/i686-linux-gnu/bzImage"
identity = "scripts/keys/qemu_id_rsa"
pubkey = "scripts/keys/qemu_id_rsa.pub"
arch = "x86"
~~~

For this to work, you need to do two things:

1. Generate SSH keys
    - `ssh-keygen -f scripts/keys/qemu_id_rsa`
    - You only need to do this once and then use same keys for all QEMU test
      targets
2. Generate buildroot images
    - See more details under
      [scripts/buildroot/README.md](scripts/buildroot/README.md)
