use pai::{api::Response, ctx};
fn main() -> anyhow::Result<()> {
	env_logger::init();
	let cmd = std::process::Command::new("true");
	let mut ctx = ctx::Main::spawn(cmd, 0_usize)?;
	let sec = ctx.secondary_mut();
	let entry = sec.resolve_entry()?;
	let stopped = sec.run_until_entry()?;
	assert_eq!(stopped.expect("didn't hit breakpoint"), entry);
	let (r, _res) = ctx.loop_until_exit()?;
	assert_eq!(r, Response::TargetExit);
	Ok(())
}
