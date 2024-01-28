use crate::{
	api::{
		messages::{Event, EventInner, RegEvent},
		ArgsBuilder, Client, Command, Response,
	},
	ctx,
	plugin::Plugin,
	utils, Result, TargetPtr,
};

#[derive(Default)]
pub struct Prctl;

impl Prctl {
	fn new() -> Self {
		Self
	}
	pub fn dependecies() -> Vec<Plugin> {
		vec![Plugin::Files]
	}
	pub fn init(client: Client<Command, Response>) -> Result<ctx::Secondary<Self>> {
		log::error!("read plugin is not finished and will not give expected results");
		let data = Self::new();

		let mut ctx = ctx::Secondary::new_second(client, data)?;

		let read = ctx.client.resolve_syscall("read")?;
		let pread = ctx.client.resolve_syscall("pread");
		let pread64 = ctx.client.resolve_syscall("pread64");
		let readv = ctx.client.resolve_syscall("readv");
		let preadv = ctx.client.resolve_syscall("preadv");
		let preadv2 = ctx.client.resolve_syscall("preadv2");

		let mut args = ArgsBuilder::new()
			.push_registered(RegEvent::Files)
			.push_syscall_traced(read)
			.only_notify_syscall_exit()
			.transform_syscalls();

		if let Ok(n) = pread {
			args = args.push_syscall_traced(n)
		}
		if let Ok(n) = pread64 {
			args = args.push_syscall_traced(n)
		}
		if let Ok(n) = readv {
			args = args.push_syscall_traced(n)
		}
		if let Ok(n) = preadv {
			args = args.push_syscall_traced(n)
		}
		if let Ok(n) = preadv2 {
			args = args.push_syscall_traced(n)
		}

		let args = args.finish()?;

		ctx.client.set_config(args)?;

		ctx.set_specific_syscall_handler(read, |_cl, _sys| Ok(()));

		Ok(ctx)
	}
}
