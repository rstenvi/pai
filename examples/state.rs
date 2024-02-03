use pai::api::args::ArgsBuilder;
use pai::ctx;
fn main() -> anyhow::Result<()> {
	let args = ArgsBuilder::new();

	#[cfg(feature = "syscalls")]
	let args = args.intercept_all_syscalls();

	#[cfg(feature = "syscalls")]
	let args = args.transform_syscalls();

	let args = args.only_notify_syscall_exit().finish()?;

	let cmd = std::process::Command::new("true");
	let mut ctx: ctx::Main<usize, pai::Error> = ctx::Main::new_spawn(cmd, 0_usize)?;

	#[cfg(feature = "syscalls")]
	ctx.secondary_mut().set_generic_syscall_handler(|cl, sys| {
		assert!(sys.is_exit());
		*(cl.data_mut()) += 1;
		Ok(())
	});

	ctx.secondary_mut().client_mut().set_config(args)?;

	let (_, count) = ctx.loop_until_exit()?;
	println!("hit {count} syscalls");
	Ok(())
}
