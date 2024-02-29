use pai::ctx;
use pai::api::messages::{LogOutput, LogFormat, CbAction};

fn main() -> anyhow::Result<()> {
	env_logger::init();
	// We need something to run, so just spawn a program
	let cmd = std::process::Command::new("true");

	// To start, one would typically use ctx::Main::new_{spawn|attach|main]
	let mut ctx: ctx::Main<(), pai::Error> = ctx::Main::new_spawn(cmd, ())?;
	let sec = ctx.secondary_mut();

	let f = LogOutput::file("logging.txt");
	sec.client_mut().add_logger(LogFormat::Json, f)?;

	#[cfg(feature = "syscalls")]
	sec.set_generic_syscall_handler_exit(|_cl, sys| {
		println!("{sys}");
		Ok(CbAction::None)
	});

	// Here we would typically register callback(s)

	// Run until program finishes or we are detached.
	ctx.loop_until_exit()?;
	Ok(())
}
