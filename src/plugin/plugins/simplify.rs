

use crate::{Result, client::{api::{messages::{Command, Response, RegEvent, Event, Syscall, Fd, ParsedSyscall, RetVal, EventInner}, Client}, ctx::ctx::Secondary, args::ArgsBuilder}, plugin::Plugin, syscalls::SyscallItem};

#[derive(Default, Clone)]
pub struct Args {
	pub do_open: bool,
	pub do_access: bool,
	pub do_mmap: bool,
	pub do_stat: bool,
}

#[derive(Default)]
pub struct SimplyfySyscall {
	args: Args,
}

impl SimplyfySyscall {
	fn new() -> Self {
		Self::default()
	}
	pub fn dependecies() -> Vec<Plugin> { vec![] }
	fn sys_to_event(sys: &SyscallItem, syscall: Syscall) -> Event {
		let syscall = if sys.is_entry() {
			ParsedSyscall::Started { syscall }
		} else {
			let retval = RetVal::from_raw(sys.output_as_raw());
			ParsedSyscall::Exited { syscall, retval }
		};
		let event = EventInner::ParsedSyscall { syscall };
		Event::new_attached(sys.tid, event)
	}
	fn gen_open(ctx: &mut ctx::Secondary<Self>, sys: &SyscallItem, isat: bool, _iscreat: bool) -> Result<Event> {
		let _at = libc::AT_FDCWD;
		let (fname, _next) = if isat {
			let at = sys.args[0].as_i32();
			let name = sys.args[1].raw_value();
			let name = ctx.client.read_c_string(sys.tid, name)?;
			if at == libc::AT_FDCWD {
				log::info!("open is relative to CWD");
			} else {
				// Need to keep track of FDs
				todo!();
			}
			(name, 2)
		} else {
			let name = sys.args[0].raw_value();
			let name = ctx.client.read_c_string(sys.tid, name)?;
			(name, 1)
		};
		let syscall = Syscall::Open { fname };
		let evt = Self::sys_to_event(sys, syscall);
		Ok(evt)
	}
	fn gen_mmap(sys: &SyscallItem, istwo: bool) -> Result<Event> {
		let addr = sys.args[0].raw_value();
		let len = sys.args[1].raw_value();
		let prot = sys.args[2].raw_value();
		let flags = sys.args[3].raw_value();
		let fd = sys.args[4].raw_value();
		let mut offset = sys.args[5].raw_value();
		if istwo { offset *= 4096; }
		let syscall = Syscall::Mmap { addr, len, prot, flags, fd: Fd::from_raw(fd), offset };
		let evt = Self::sys_to_event(sys, syscall);
		Ok(evt)
	}
	fn do_mmap(ctx: &mut ctx::Secondary<Self>, mut args: ArgsBuilder) -> Result<ArgsBuilder> {
		let mmap = ctx.client.resolve_syscall("mmap");
		let mmap2 = ctx.client.resolve_syscall("mmap2");

		if let Ok(n) = mmap2 {
			args = args.push_syscall_traced(n);
			ctx.set_specific_syscall_handler(n, |cl, sys| {
				let event = Self::gen_mmap(&sys, true)?;
				cl.client.send_event(event)?;
				Ok(())
			});
		}

		if let Ok(n) = mmap {
			args = args.push_syscall_traced(n);
			ctx.set_specific_syscall_handler(n, |cl, sys| {
				let event = Self::gen_mmap(&sys, false)?;
				cl.client.send_event(event)?;
				Ok(())
			});
		}

		Ok(args)
	}
	fn do_open(ctx: &mut ctx::Secondary<Self>, mut args: ArgsBuilder) -> Result<ArgsBuilder> {
		let open = ctx.client.resolve_syscall("open");
		let openat = ctx.client.resolve_syscall("openat");
		let openat2 = ctx.client.resolve_syscall("openat2");
		let creat = ctx.client.resolve_syscall("creat");

		if let Ok(n) = open {
			args = args.push_syscall_traced(n);
			ctx.set_specific_syscall_handler(n, |cl, sys| {
				let event = Self::gen_open(cl, &sys, false, false)?;
				cl.client.send_event(event)?;
				Ok(())
			});
		}

		if let Ok(n) = openat {
			args = args.push_syscall_traced(n);
			ctx.set_specific_syscall_handler(n, |cl, sys| {
				let event = Self::gen_open(cl, &sys, true, false)?;
				cl.client.send_event(event)?;
				Ok(())
			});
		}
		if let Ok(n) = creat {
			args = args.push_syscall_traced(n);
			ctx.set_specific_syscall_handler(n, |cl, sys| {
				let event = Self::gen_open(cl, &sys, false, true)?;
				cl.client.send_event(event)?;
				Ok(())
			});
		}
		if let Ok(n) = openat2 {
			args = args.push_syscall_traced(n);
			ctx.set_specific_syscall_handler(n, |cl, sys| {
				let event = Self::gen_open(cl, &sys, true, false)?;
				cl.client.send_event(event)?;
				Ok(())
			});
		}
		Ok(args)
	}
	pub fn init(client: crate::Client) -> Result<ctx::Secondary<Self>> {
		log::error!("simplify plugin is not finished and will not give expected results");
		let data = Self::new();
		let inargs = data.args.clone();
		
		let mut ctx = ctx::Secondary::new_second(client, data)?;
		todo!();

		Ok(ctx)
	}
}