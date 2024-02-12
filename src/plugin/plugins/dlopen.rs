// Typical pattern is like this
// openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
// read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P\237\2\0\0\0\0\0"..., 832) = 832
// pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
// pread64(3, "\4\0\0\0 \0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0"..., 48, 848) = 48
// pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0 =\340\2563\265?\356\25x\261\27\313A#\350"..., 68, 896) = 68
// newfstatat(3, "", {st_mode=S_IFREG|0755, st_size=2216304, ...}, AT_EMPTY_PATH) = 0
// pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
// mmap(NULL, 2260560, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f76a9154000
// mmap(0x7f76a917c000, 1658880, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7f76a917c000
// mmap(0x7f76a9311000, 360448, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1bd000) = 0x7f76a9311000
// mmap(0x7f76a9369000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x214000) = 0x7f76a9369000
// mmap(0x7f76a936f000, 52816, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f76a936f000
// close(3)                                = 0

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

struct State {
	name: String,
	_fd: isize,
	mmapped: usize,
}
impl State {
	pub fn new(name: String, fd: isize) -> Self {
		Self {
			name,
			_fd: fd,
			mmapped: 0,
		}
	}
	// TODO: Need better pattern matching, or hook the read and check if \x7fELF
	// is there
	pub fn is_so(&self) -> bool {
		self.name.ends_with(".so")
			|| self.name.ends_with(".so.0")
			|| self.name.ends_with(".so.1")
			|| self.name.ends_with(".so.2")
			|| self.name.ends_with(".so.3")
			|| self.name.ends_with(".so.4")
			|| self.name.ends_with(".so.5")
			|| self.name.ends_with(".so.6")
			|| self.name.ends_with(".so.7")
			|| self.name.ends_with(".so.8")
			|| self.name.ends_with(".so.9")
	}
}

pub(crate) struct DlopenDetect {
	mmapped: HashMap<isize, State>,
}
impl DlopenDetect {
	fn new() -> Self {
		let mmapped = HashMap::new();
		Self { mmapped }
	}
	pub fn dependecies() -> &'static [Plugin] {
		&[Plugin::Files]
	}
	pub fn init(client: crate::Client) -> Result<ctx::Secondary<DlopenDetect, Error>> {
		let data = Self::new();

		let mut ctx = ctx::Secondary::new_second(client, data)?;
		let client = ctx.client_mut();

		let mmap = client.resolve_syscall("mmap")?;

		ctx.set_syscall_hook_entry(mmap, |cl, sys| {
			if sys.is_entry() {
				let fd = sys.args[4].raw_value();
				let fd = fd.as_isize();
				if let Some(r) = cl.data_mut().mmapped.get_mut(&fd) {
					r.mmapped += 1;
				}
			} else {
				// Could check if successful, but not really a point to it
			}
			Ok(CbAction::None)
		});

		ctx.set_event_handler(|cl, event| {
			match event.event {
				EventInner::FileOpened { fname, fd } => {
					let ins = State::new(fname, fd);
					if ins.is_so() {
						cl.data_mut().mmapped.insert(fd, ins);
					}
				}
				EventInner::FileClosed { fname, fd } => {
					if let Some(r) = cl.data_mut().mmapped.remove(&fd) {
						if r.mmapped > 0 {
							let tid = event.tid.unwrap_or(0);
							let event = EventInner::Dlopen { fname };
							let event = Event::new_attached(tid, event);
							log::debug!("sending dlopen event {event:?}");
							cl.client_mut().send_event(event)?;
						}
					}
				}
				_ => {}
			}
			Ok(())
		});

		Ok(ctx)
	}
}
