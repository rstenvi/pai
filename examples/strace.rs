use pai::{api::messages::CbAction, ctx};
fn main() -> anyhow::Result<()> {
	let cmd = std::process::Command::new("true");
	let mut ctx: ctx::Main<(), pai::Error> = ctx::Main::new_spawn(cmd, ())?;

	// Register callback to be executed on every system call
	#[cfg(feature = "syscalls")]
	ctx.secondary_mut().set_generic_syscall_handler_exit(|_cl, sys| {
		println!("{sys}");
		Ok(CbAction::None)
	});
	#[cfg(not(feature = "syscalls"))]
	println!("program will do noting without 'syscalls' \
		feature enabled, run: cargo run --features=syscalls --example strace");
	
	ctx.loop_until_exit()?;
	Ok(())
}
