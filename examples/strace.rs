use pai::api::args::ArgsBuilder;
use pai::ctx;
fn main() -> anyhow::Result<()> {
	// Build up Args to control interception
	let args = ArgsBuilder::new()
		// Return control to us anytime a syscall is hit
		.intercept_all_syscalls()
		// Gather info about what type of syscall is hit
		.transform_syscalls()
		.finish()?;
	
	let cmd = std::process::Command::new("true");
	let mut ctx = ctx::Main::spawn(cmd, ())?;

	// Register callback to be executed on every system call
	ctx.secondary_mut().set_generic_syscall_handler(|_cl, sys| {
		println!("{sys}");
		Ok(())
	})?;

	// We must also set the config
	ctx
		.secondary_mut()
		.client_mut()
		.set_config(args)?;

	ctx.loop_until_exit()?;
	Ok(())
}