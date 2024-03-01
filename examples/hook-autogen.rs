use pai::{
	api::{messages::CbAction, Response},
	ctx,
};

/// Procedural macro to generate callback function is in a separate crate
///
/// Use `cargo expand --example hook-autogen` to see the generated code, will
/// look something like this:
/// ```
/// fn opendir<T>(
///   ctx: &mut pai::ctx::Secondary<T, pai::Error>,
///   frame: &pai::api::CallFrame,
/// ) -> pai::Result<CbAction> {
///   let dir = frame.arg(0usize, ctx.client_mut())?.read_ptr_as_str(ctx.client_mut())?;
/// ...
/// }
/// ```
#[pai_macros::pai_hook]
fn opendir(dir: String) -> pai::Result<CbAction> {
	log::error!("opendir('{dir}')");
	Ok(CbAction::None)
}

fn main() -> anyhow::Result<()> {
	env_logger::init();
	// The dir we give here should match what we read in `opendir`
	let dir = env!("CARGO_MANIFEST_DIR");
	let mut cmd = std::process::Command::new("/usr/bin/ls");
	cmd.arg(dir);

	// Actually set up everything
	let mut ctx: ctx::Main<usize, pai::Error> = ctx::Main::new_spawn(cmd, 0_usize)?;
	let sec = ctx.secondary_mut();
	let _stopped = sec.run_until_entry()?;
	let pbuf = sec.proc.exe_path()?;

	let tid = sec.get_first_stopped()?;
	sec.hook_got_entry(tid, &pbuf, "opendir", opendir)?;

	let (r, _res) = ctx.loop_until_exit()?;
	assert_eq!(r, Response::TargetExit);
	Ok(())
}
