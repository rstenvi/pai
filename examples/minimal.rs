use pai::ctx;
fn main() -> anyhow::Result<()> {
	// We need something to run, so just spawn a program
	let cmd = std::process::Command::new("true");

	// To start, one would typically use ctx::Main::new_{spawn|attach|main]
	let ctx: ctx::Main<(), pai::Error> = ctx::Main::new_spawn(cmd, ())?;

	// Here we would typically register callback(s)

	// Run until program finishes or we are detached.
	ctx.loop_until_exit()?;
	Ok(())
}
