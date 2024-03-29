use crate::{
	api::{
		messages::{CbAction, Event, EventInner, EventPrctl, RegEvent},
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
	pub fn init(client: crate::Client) -> Result<ctx::Secondary<Self, crate::Error>> {
		let data = Self::new();

		let mut ctx = ctx::Secondary::new_second(client, data)?;
		let client = ctx.client_mut();

		let prctl = client.resolve_syscall("prctl")?;

		ctx.set_syscall_hook_exit(prctl, |cl, sys| {
			assert!(sys.is_exit());
			if sys.args.len() < 5 {
				let msg = format!("too few arguments for prctl {:?}", sys.args);
				return Err(Error::msg(msg));
			}
			let tid = sys.tid;
			let option = sys.args[0].raw_value();
			let option: i32 = option.into();
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
					if arg2 == libc::PR_SET_VMA_ANON_NAME.into() {
						let name = cl.client_mut().read_c_string(tid, arg5)?;
						EventPrctl::SetVmaAnonName {
							name,
							addr: arg3,
							size: arg4.into(),
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
			Ok(CbAction::None)
		});
		Ok(ctx)
	}
}
