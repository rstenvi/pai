use crate::{
	api::{
		messages::{Event, EventInner, RegEvent},
		ArgsBuilder, Client, Command, Response,
	}, ctx, plugin::Plugin, syscalls::SyscallItem, utils, Result, TargetPtr
};

#[derive(Default)]
pub struct Mmap;

impl Mmap {
	fn new() -> Self {
		Self
	}
	pub fn dependecies() -> &'static [Plugin] {
		&[]
	}
	fn gen_mmap(sys: &SyscallItem, istwo: bool) -> Result<Event> {
		let addr = sys.args[0].raw_value();
		let size = sys.args[1].raw_value();
		let prot = sys.args[2].raw_value();
		let flags = sys.args[3].raw_value();
		let fd = sys.args[4].raw_value();
		let mut offset = sys.args[5].raw_value();
		if istwo {
			offset *= 4096;
		}
		let evt = EventInner::Mmap {
			addr,
			size,
			prot,
			flags,
			fd,
			offset,
		};
		let evt = Event::new_attached(sys.tid, evt);
		Ok(evt)
	}
	pub fn init(client: Client<Command, Response>) -> Result<ctx::Secondary<Self>> {
		let data = Self::new();

		let mut ctx = ctx::Secondary::new_second(client, data)?;

		let mmap = ctx.client_mut().resolve_syscall("mmap")?;
		let mmap2 = ctx.client_mut().resolve_syscall("mmap2");

		let mut args = ArgsBuilder::new()
			.push_registered(RegEvent::Files)
			.push_syscall_traced(mmap)
			.only_notify_syscall_exit()
			.transform_syscalls();

		if let Ok(n) = mmap2 {
			args = args.push_syscall_traced(n);
			ctx.set_specific_syscall_handler(n, |cl, sys| {
				debug_assert!(sys.is_exit());
				let event = Self::gen_mmap(&sys, true)?;
				cl.client_mut().send_event(event)?;
				Ok(())
			});
		}

		let args = args.finish()?;

		ctx.client_mut().set_config(args)?;

		ctx.set_specific_syscall_handler(mmap, |cl, sys| {
			debug_assert!(sys.is_exit());
			let event = Self::gen_mmap(&sys, true)?;
			cl.client_mut().send_event(event)?;
			Ok(())
		});
		Ok(ctx)
	}
}
