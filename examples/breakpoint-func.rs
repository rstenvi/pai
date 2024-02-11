use pai::{api::Response, ctx};
fn main() -> anyhow::Result<()> {
	env_logger::init();
	let cmd = std::process::Command::new("testdata/sleep");
	let mut ctx: ctx::Main<usize, pai::Error> = ctx::Main::new_spawn(cmd, 0_usize)?;
	let sec = ctx.secondary_mut();
	let entry = sec.resolve_entry()?;
	let stopped = sec.run_until_entry()?;
	assert_eq!(stopped.expect("didn't hit breakpoint"), entry);

	let v = sec.lookup_symbol("sleep")?.expect("unable to find sleep");
	println!("{v:?}");
	let tid = sec.get_first_stopped()?;

	sec.register_function_hook_entry(tid, v.value, |cl, frame| {
		println!("hit func");
		Ok((false, Some(0.into())))
	})?;

	let (r, _res) = ctx.loop_until_exit()?;
	assert_eq!(r, Response::TargetExit);
	Ok(())
}
