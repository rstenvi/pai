use crate::{
	api::{
		messages::{Event, EventInner, EventPrctl, RegEvent},
		ArgsBuilder, Client, Command, Response,
	},
	ctx,
	plugin::Plugin,
	utils, Error, Result, TargetPtr,
};

#[derive(Default)]
pub struct Prctl;

impl Prctl {
	fn new() -> Self {
		Self
	}
	pub fn dependecies() -> &'static [Plugin] {
		&[]
	}
	pub fn init(client: Client<Command, Response>) -> Result<ctx::Secondary<Self>> {
		let data = Self::new();

		let mut ctx = ctx::Secondary::new_second(client, data)?;
		let client = ctx.client_mut();

		let prctl = client.resolve_syscall("prctl")?;

		let args = ArgsBuilder::new()
			.push_registered(RegEvent::Files)
			.push_syscall_traced(prctl)
			.only_notify_syscall_exit()
			.transform_syscalls()
			.finish()?;

		client.set_config(args)?;

		ctx.set_specific_syscall_handler(prctl, |cl, sys| {
			if sys.args.len() < 5 {
				let msg = format!("too few arguments for prctl {:?}", sys.args);
				log::error!("{msg}");
				return Err(Error::msg(msg).into());
			}
			let tid = sys.tid;
			let option = sys.args[0].raw_value();
			let option = option as i32;
			let arg2 = sys.args[1].raw_value();
			let arg3 = sys.args[2].raw_value();
			let arg4 = sys.args[3].raw_value();
			let arg5 = sys.args[4].raw_value();

			let event = match option {
				libc::PR_SET_NAME => {
					let name = cl.client_mut().read_c_string(tid, arg2)?;
					EventPrctl::SetName { name }
				}
				libc::PR_GET_DUMPABLE => EventPrctl::GetDumpable,
				libc::PR_SET_VMA => {
					if arg2 as i32 == libc::PR_SET_VMA_ANON_NAME {
						let name = cl.client_mut().read_c_string(tid, arg5)?;
						EventPrctl::SetVmaAnonName {
							name,
							addr: arg3,
							size: arg4 as usize,
						}
					} else {
						EventPrctl::Unknown { option }
					}
				}
				_ => EventPrctl::Unknown { option },
			};
			let event = EventInner::Prctl { event };
			let event = Event::new_attached(sys.tid, event);
			log::trace!("sending {event:?}");
			cl.client_mut().send_event(event)?;
			Ok(())
		});
		Ok(ctx)
	}
}
