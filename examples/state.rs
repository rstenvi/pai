use pai::api::args::ArgsBuilder;
use pai::ctx;
fn main() -> anyhow::Result<()> {
	let args = ArgsBuilder::new()
		.intercept_all_syscalls()
		.transform_syscalls()
		.only_notify_syscall_exit()
		.finish()?;

	let cmd = std::process::Command::new("true");
	let mut ctx = ctx::Main::spawn(cmd, 0_usize)?;
	ctx.secondary_mut().set_generic_syscall_handler(|cl, sys| {
		assert!(sys.is_exit());
		*(cl.data_mut()) += 1;
		Ok(())
	})?;

	ctx.secondary_mut().client_mut().set_config(args)?;

	let count = ctx.loop_until_exit()?;
	println!("hit {count} syscalls");
	Ok(())
}
