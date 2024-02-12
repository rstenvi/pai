use pai::{api::messages::CbAction, ctx};
fn main() -> anyhow::Result<()> {
	let cmd = std::process::Command::new("true");
	let mut ctx: ctx::Main<usize, pai::Error> = ctx::Main::new_spawn(cmd, 0_usize)?;
	let sec = ctx.secondary_mut();

	#[cfg(feature = "syscalls")]
	sec.set_generic_syscall_handler_entry(|cl, sys| {
		assert!(sys.is_entry());
		*(cl.data_mut()) += 1;
		Ok(CbAction::None)
	});
	#[cfg(not(feature = "syscalls"))]
	println!(
		"program will do noting without 'syscalls' \
		feature enabled, run: cargo run --features=syscalls --example state"
	);

	let (_, count) = ctx.loop_until_exit()?;
	println!("hit {count} syscalls");
	Ok(())
}
