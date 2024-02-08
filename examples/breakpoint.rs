use pai::{ctx, utils::process::Tid};
fn main() -> anyhow::Result<()> {
	env_logger::init();
	let cmd = std::process::Command::new("true");
	let mut ctx: ctx::Main<usize, pai::Error> = ctx::Main::new_spawn(cmd, 0_usize)?;

	let sec = ctx.secondary_mut();
	let tid = sec.get_first_stopped()?;
	let entry = sec.resolve_entry()?;

	// Register callback to be executed on breakpoint
	ctx.secondary_mut()
		.register_breakpoint_handler(tid, entry, |cl, _tid, _addr| {
			*(cl.data_mut()) += 1;
			if let Some(getpid) = cl.lookup_symbol("getpid")? {
				log::info!("getpid {getpid:?}");
				let tid = cl.get_first_stopped()?;
				let v = cl.call_func(tid, getpid.value, &[]).unwrap();
				log::info!("getpid -> {v}");
				assert!(v == tid.into());
			}
			Ok(true) // keep breakpoint, is never hit again
		})?;

	let (_, res) = ctx.loop_until_exit()?;
	assert_eq!(res, 1); // Check that we've hit our breakpoint
	Ok(())
}
