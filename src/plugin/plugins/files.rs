use crate::{
	api::{
		messages::{Event, EventInner, RegEvent},
		ArgsBuilder, Client, Command, Response,
	},
	ctx,
	plugin::Plugin,
	utils, Error, Result, TargetPtr,
};
use std::collections::HashMap;

#[derive(Default)]
pub struct Files {
	opened: HashMap<isize, String>,
}
impl Files {
	fn new() -> Self {
		let opened = HashMap::new();
		Self { opened }
	}
	pub fn dependecies() -> &'static [Plugin] {
		&[]
	}
	pub fn init(client: crate::Client) -> Result<ctx::Secondary<Files, Error>> {
		log::info!("plugin Files started");
		let data = Self::new();
		let mut ctx = ctx::Secondary::new_second(client, data)?;
		let client = ctx.client_mut();

		let openat = client.resolve_syscall("openat")?;
		let close = client.resolve_syscall("close")?;
		let args = ArgsBuilder::new()
			.push_syscall_traced(openat)
			.push_syscall_traced(close)
			.transform_syscalls()
			.only_notify_syscall_exit()
			.finish()?;

		client.set_config(args)?;
		ctx.set_specific_syscall_handler(openat, |cl, sys| {
			debug_assert!(sys.is_exit());
			let fname = sys.args[1].raw_value();
			let fname = cl.client_mut().read_c_string(sys.tid, fname)?;
			let fd = sys.output_as_raw();
			let fd = utils::twos_complement(fd);
			if fd > 0 {
				log::debug!("'{fname}' -> {fd}");
				cl.data_mut().opened.insert(fd, fname.clone());
				let tid = sys.tid;
				let event = EventInner::FileOpened { fname, fd };
				let event = Event::new_attached(tid, event);
				cl.client_mut().send_event(event)?;
			}
			Ok(())
		});

		ctx.set_specific_syscall_handler(close, |cl, sys| {
			debug_assert!(sys.is_exit());
			let fd = sys.args[0].raw_value();
			let fd = utils::twos_complement(fd);
			let close = cl.data_mut().opened.remove(&fd);
			if let Some(fname) = close {
				let tid = sys.tid;
				let event = EventInner::FileClosed { fname, fd };
				let event = Event::new_attached(tid, event);
				cl.client_mut().send_event(event)?;
			}
			Ok(())
		});

		Ok(ctx)
	}
}
