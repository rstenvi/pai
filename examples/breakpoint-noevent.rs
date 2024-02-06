use pai::{api::Response, ctx, utils::process::Tid};
fn main() -> anyhow::Result<()> {
	env_logger::init();
	let cmd = std::process::Command::new("true");
	let mut ctx: ctx::Main<usize, pai::Error> = ctx::Main::new_spawn(cmd, 0_usize)?;
	let sec = ctx.secondary_mut();
	let entry = sec.resolve_entry()?;
	let stopped = sec.run_until_entry()?;
	assert_eq!(stopped.expect("didn't hit breakpoint"), entry);
	let tid = sec.get_first_stopped()?;
	if let Some(getpid) = sec.lookup_symbol("getpid")? {
		log::info!("getpid {getpid:?}");
		let v = sec.call_func(tid, getpid.value, &[])?;
		assert!(v as Tid == tid);
	}
	let (r, _res) = ctx.loop_until_exit()?;
	assert_eq!(r, Response::TargetExit);
	Ok(())
}
