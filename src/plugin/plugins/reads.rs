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
pub struct Reads;

impl Reads {
	fn new() -> Self {
		Self
	}
	pub fn dependecies() -> Vec<Plugin> {
		vec![Plugin::Files]
	}
	pub fn init(client: Client<Command, Response>) -> Result<ctx::Secondary<Self, crate::Error>> {
		log::error!("read plugin is not finished and will not give expected results");
		let data = Self::new();

		let mut ctx = ctx::Secondary::new_second(client, data)?;
		let client = ctx.client_mut();

		let read = client.resolve_syscall("read")?;
		let pread = client.resolve_syscall("pread");
		let pread64 = client.resolve_syscall("pread64");
		let readv = client.resolve_syscall("readv");
		let preadv = client.resolve_syscall("preadv");
		let preadv2 = client.resolve_syscall("preadv2");

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

		client.set_config(args)?;

		ctx.set_specific_syscall_handler(read, |_cl, _sys| Ok(()));

		Ok(ctx)
	}
}
