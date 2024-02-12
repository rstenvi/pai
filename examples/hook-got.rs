use std::path::PathBuf;

use pai::{api::{messages::CbAction, Response}, ctx};
fn main() -> anyhow::Result<()> {
	env_logger::init();
	let cmd = std::process::Command::new("testdata/sleep");
	let mut ctx: ctx::Main<usize, pai::Error> = ctx::Main::new_spawn(cmd, 0_usize)?;
	let sec = ctx.secondary_mut();
	let _stopped = sec.run_until_entry()?;

	let pbuf = PathBuf::from("testdata/sleep");

	let tid = sec.get_first_stopped()?;
	sec.hook_got_entry(tid, &pbuf, "sleep", |cl, frame| {
		log::info!("sleep({:x})", frame.arg(0, cl.client_mut())?.as_usize());
		Ok(CbAction::EarlyRet { ret: 1.into() })
		// Ok(CbAction::None)
	})?;

	let (r, _res) = ctx.loop_until_exit()?;
	assert_eq!(r, Response::TargetExit);
	Ok(())
}
