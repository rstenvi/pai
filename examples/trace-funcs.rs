use pai::{api::{messages::CbAction, Response}, ctx};
fn main() -> anyhow::Result<()> {
	env_logger::init();
	let cmd = std::process::Command::new("testdata/sleep");
	let mut ctx: ctx::Main<usize, pai::Error> = ctx::Main::new_spawn(cmd, 0_usize)?;
	let sec = ctx.secondary_mut();
	let entry = sec.resolve_entry()?;
	let stopped = sec.run_until_entry()?;
	assert_eq!(stopped.expect("didn't hit breakpoint"), entry);
	let tid = sec.get_first_stopped()?;

	let libc = sec.try_find_libc_so()?;
	let sleep = sec.resolve_symbol(&libc, "sleep")?.expect("unable to find strlen");
	log::info!("sleep {sleep:?}");
	sec.register_function_hook(tid, sleep.value, |cl, frame| {
		log::info!("sleep({:x})", frame.arg(0, cl.client_mut())?.as_usize());

		// Will only be called once and exit will not be called
		// Ok(CbAction::Remove)

		// Just keep everything as-is
		// Ok(CbAction::None)

		// Return early, exit function will still be called, but it's just a
		// fake we implemented to maintain consistency.
		Ok(CbAction::EarlyRet { ret: 0.into() })
	}, |_cl, frame| {
		let v = frame.retval()?.as_i32();
		log::info!("sleep() -> {v}");
		Ok(CbAction::None)
	})?;

	let geteuid = sec.resolve_symbol(&libc, "geteuid")?.expect("unable to find geteuid");
	sec.register_function_hook_entry(tid, geteuid.value, |_cl, _frame| {
		// We are root, kinda...
		Ok(CbAction::EarlyRet { ret: 0.into() })
	})?;

	let (r, _res) = ctx.loop_until_exit()?;
	assert_eq!(r, Response::TargetExit);
	Ok(())
}
