use crate::{
	api::{
		messages::{CbAction, Event, EventInner, RegEvent},
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

		ctx.set_syscall_hook_exit(openat, |cl, sys| {
			debug_assert!(sys.is_exit());
			let fname = sys.args[1].raw_value();
			let fname = cl.client_mut().read_c_string(sys.tid, fname)?;
			let fd = sys.output_as_raw();
			let fd = fd.as_isize();
			if fd > 0 {
				log::debug!("'{fname}' -> {fd}");
				cl.data_mut().opened.insert(fd, fname.clone());
				let tid = sys.tid;
				let event = EventInner::FileOpened { fname, fd };
				let event = Event::new_attached(tid, event);
				cl.client_mut().send_event(event)?;
			}
			Ok(CbAction::None)
		});

		ctx.set_syscall_hook_exit(close, |cl, sys| {
			debug_assert!(sys.is_exit());
			let fd = sys.args[0].raw_value();
			let fd = fd.as_isize();
			let close = cl.data_mut().opened.remove(&fd);
			if let Some(fname) = close {
				let tid = sys.tid;
				let event = EventInner::FileClosed { fname, fd };
				let event = Event::new_attached(tid, event);
				cl.client_mut().send_event(event)?;
			}
			Ok(CbAction::None)
		});

		Ok(ctx)
	}
}
