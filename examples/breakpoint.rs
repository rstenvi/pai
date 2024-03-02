use pai::{api::messages::BpRet, ctx};
fn main() -> anyhow::Result<()> {
	env_logger::init();
	let cmd = std::process::Command::new("true");
	let mut ctx: ctx::Main<usize, pai::Error> = ctx::Main::new_spawn(cmd, 0_usize)?;

	// Get a handle to secondary context, for more concise code.
	let sec = ctx.secondary_mut();

	// Some commands require a target thread id to interact with, the target has
	// stopped, so just get the first thread id which is stopped.
	let tid = sec.get_first_stopped()?;

	// Program has not executed any code yet, so resolve ELF entry and run until
	// we hit it.
	let entry = sec.resolve_entry()?;

	// Register callback to be executed on entry point.
	sec.register_breakpoint_handler(tid, entry, |cl, tid, _addr| {
		*(cl.data_mut()) += 1; // So we can check afterwards

		// With libraries loaded, we can resolve `getpid` and call it
		if let Some(getpid) = cl.lookup_symbol_in_any("getpid")? {
			log::info!("getpid {getpid:?}");
			let v = cl.call_func(tid, getpid.value, &[]).unwrap();
			log::info!("getpid -> {v}");

			// The thread id we get when hitting the BP should be the same as
			// when injection function call to `getpid`
			assert!(v == tid.into());
		}
		Ok(BpRet::Keep) // keep breakpoint, is never hit again
	})?;

	let (_, res) = ctx.loop_until_exit()?;
	assert_eq!(res, 1); // Check that we've hit our breakpoint
	Ok(())
}
