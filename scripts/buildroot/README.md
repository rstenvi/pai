# Buildroot images

Much of the cross-platform testing is done inside QEMU system emulation. For
this to work, we need to generate disk images and kernel for the architecture. 

The method I've used for this is to use [buildroot](https://buildroot.org/). To
use the default configs supplied here, please use git checkout `2023.11`.

You can build the custom config with:

~~~{.bash}
make O=out defconfig BR2_DEFCONFIG=pai_<arch>_defconfig
make O=out -j$(nproc)
~~~

The resulting image will be placed under `out/images`.

Boot the image once (using `start-qemu.sh`) to:

- Ensure the image boots
- Generate SSH-keys, which is time-consuming and we don't want to do everytime
  we run a test

To save some space, convert image to `qcow2` format:

~~~{.bash}
qemu-img convert -f raw -O qcow2 rootfs.ext2 rootfs.qcow2
~~~

You can now delete `rootfs.ext2` and the resulting disk image in `rootfs.qcow2`
can be used as an image when running tests.

## Tools in image

The configs provided has some useful debugging tools (the only requirement is an
SSH-server which works with `~/.ssh/authorized_keys`).

- `openssh-server`
- `rsync`
- `file`
- `strace`
- `gdbserver` and `gdb`

## Create image for new architecture

Below are the basic steps taken when creating image for a new architecture.

~~~{.bash}
make O=out/<arch> qemu_<board>_defconfig
# Make some changes, must at least add SSH server
make O=out/<arch> menuconfig
make O=out/<arch> savedefconfig BR2_DEFCONFIG=pai_<arch>_defconfig
make O=out/<arch> -j4
~~~

## Optional 1: Set up for manual testing

We don't import any SSH-keys into the image because we do each time we want to
run the tests and whenever we run tests in QEMU we include `-snapshot` so that
any changes made in VM are **not** persisted to disk.

If you're troubleshooting it is quite useful to have a QEMU image set up with
SSH credentials you can easily copy test binaries into. You can set this up with
the following command (just an example, modify to suit your needs):

~~~{.sh}
export ARCH=<arch>
# Backup image we want to run tests from later
cp scripts/images/${ARCH}/rootfs.qcow2 scripts/images/${ARCH}/rootfs.qcow2.bak

# Run qemu with `--no-snapshot` to persist changes
# This will boot, setup image for testing and power off
rust-script scripts/qemu-runner.rs -vvv --arch aarch64 --kernel scripts/images/${ARCH}/Image --disk scripts/images/${ARCH}/rootfs.qcow2 --identity scripts/keys/qemu_id_rsa --pubkey scripts/keys/qemu_id_rsa.pub --user shell id
~~~

Pay attention to a log entry which will say something like:

~~~
spawning "qemu-system-aarch64" "-nographic" "-smp" "4" "-m" "1G" "-kernel" "<kernel>" "-hda" "<disk>" "-net" "nic" "-machine" "virt" "-cpu" "max" "-append" "\'console=ttyAMA0 root=/dev/vda earlyprintk=serial page_alloc.shuffle selinux=0 nokaslr\'" "-net" "user,hostfwd=tcp::10023-:22"
~~~

Use this to launch the emulator, potentially adding `-snapshot` to avoid making
changes to new image.

After the image is created, you might want to take a copy of the disk so that
you don't have to do this step in the future.

## Optional 2: Set up SSH config

Below is the entry you can add to `~/.ssh/config` to login using `ssh pai`

~~~
Host pai
    IdentityFile ~/pai/scripts/keys/qemu_id_rsa
    Port 10023
    HostName 127.0.0.1
    User shell
    StrictHostKeyChecking no
~~~
