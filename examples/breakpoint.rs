use pai::ctx;
fn main() -> anyhow::Result<()> {
	let cmd = std::process::Command::new("true");
	let mut ctx = ctx::Main::spawn(cmd, 0_usize)?;

	let tid = ctx.secondary_mut().get_first_stopped()?;
	let entry = ctx.secondary().resolve_entry()?;

	// Register callback to be executed on every system call
	ctx.secondary_mut()
		.register_breakpoint_handler(tid, entry, |cl, _tid, _addr| {
			*(cl.data_mut()) += 1;
			Ok(false) // disable breakpoint after this
		})?;

	let res = ctx.loop_until_exit()?;
	assert_eq!(res, 1); // Check that we've hit our breakpoint
	Ok(())
}
