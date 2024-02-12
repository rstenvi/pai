use pai::{api::Response, ctx};
fn main() -> anyhow::Result<()> {
	env_logger::init();
	let cmd = std::process::Command::new("true");
	let mut ctx: ctx::Main<usize, pai::Error> = ctx::Main::new_spawn(cmd, 0_usize)?;
	let sec = ctx.secondary_mut();

	// Run until we've hit entry
	let entry = sec.resolve_entry()?;
	let stopped = sec.run_until_entry()?;
	// Verify that entry was hit, this is just to check against bugs in pai
	assert_eq!(stopped.expect("didn't hit breakpoint"), entry);

	// Now we can resolve functions in libraries loaded
	let tid = sec.get_first_stopped()?;
	if let Some(getpid) = sec.lookup_symbol("getpid")? {
		log::info!("getpid {getpid:?}");
		let v = sec.call_func(tid, getpid.value, &[])?;
		assert!(v == tid.into());
	}
	let (r, _res) = ctx.loop_until_exit()?;
	assert_eq!(r, Response::TargetExit);
	Ok(())
}
