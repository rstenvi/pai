use pai::api::args::ArgsBuilder;
use pai::ctx;
fn main() -> anyhow::Result<()> {
	// Build up Args to control interception
	let args = ArgsBuilder::new();
	#[cfg(feature = "syscalls")]
	let args = args.intercept_all_syscalls();

	#[cfg(feature = "syscalls")]
	let args = args.transform_syscalls();

	let args = args.finish()?;

	let cmd = std::process::Command::new("true");
	let mut ctx: ctx::Main<(), pai::Error> = ctx::Main::new_spawn(cmd, ())?;

	// Register callback to be executed on every system call
	#[cfg(feature = "syscalls")]
	ctx.secondary_mut().set_generic_syscall_handler(|_cl, sys| {
		println!("{sys}");
		Ok(())
	});

	// We must also set the config
	ctx.secondary_mut().client_mut().set_config(args)?;

	ctx.loop_until_exit()?;
	Ok(())
}
