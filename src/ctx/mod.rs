//! Context object(s) the client should hold to control the traced process.
//! 


pub mod main;
pub mod secondary;

pub use main::Main;
pub use secondary::Secondary;

#[cfg(test)]
mod tests {
	use test::Bencher;

	use super::*;
	use crate::{
		api::{
			messages::{EventInner, RegEvent},
			ArgsBuilder,
		},
		exe::elf::SymbolType,
		plugin::Plugin,
		syscalls::{Direction, Syscalls},
		trace::Stop,
		utils::{self, process::Tid},
		Result, TargetPtr,
	};
	use std::{path::PathBuf, str::FromStr};

	fn _set_up<T>(cmd: std::process::Command, data: T) -> Result<Main<T>> {
		let mut ctx = Main::spawn(cmd, data)?;
		ctx.secondary_mut().client_mut().init_done()?;
		Ok(ctx)
	}

	fn set_up() -> Result<Main<()>> {
		let cmd = std::process::Command::new("true");
		_set_up(cmd, ())
	}

	/// Exec the program and trace, but no
	#[bench]
	fn bench_trace_outer(b: &mut Bencher) {
		clientmgr_basic();
		b.iter(move || clientmgr_basic())
	}

	#[bench]
	fn bench_trace_strace(b: &mut Bencher) {
		clientmgr_strace();
		b.iter(move || clientmgr_strace())
	}

	#[bench]
	fn bench_parsed_syscalls(b: &mut Bencher) {
		syscalls1();
		b.iter(|| syscalls1())
	}

	#[test]
	fn syscalls0() {
		let data = syzlang_data::linux::PARSED.read().unwrap();
		let syzarch = syzlang_parser::parser::Arch::X86_64;

		// This also runs in benchmark, so we can't take data from original
		// here, so we have to clone here. This results in worse times and not
		// the most realistic, but still ok for comparison.
		let mut parsed = data.clone();
		parsed.remove_virtual_functions();
		parsed.remove_func_no_sysno(&syzarch);
		parsed.remove_subfunctions();
		parsed.consts.filter_arch(&syzarch);
		let syscalls: Syscalls = (&parsed).try_into().unwrap();
		let _v = syscalls.resolve(1).unwrap();
	}

	#[test]
	fn syscalls1() {
		let data = syzlang_data::linux::PARSED.read().unwrap();
		let syzarch = syzlang_parser::parser::Arch::X86_64;

		// This also runs in benchmark, so we can't take data from original
		// here, so we have to clone here. This results in worse times and not
		// the most realistic, but still ok for comparison.
		let mut parsed = data.clone();
		parsed.remove_virtual_functions();
		parsed.remove_func_no_sysno(&syzarch);
		parsed.remove_subfunctions();
		parsed.consts.filter_arch(&syzarch);
		let syscalls: Syscalls = parsed.try_into().unwrap();
		let _v = syscalls.resolve(1).unwrap();
	}

	#[test]
	fn clientmgr_basic() {
		let ctx = set_up().unwrap();
		ctx.loop_until_exit().unwrap();
	}

	#[test]
	fn clientmgr_strace() {
		let args = ArgsBuilder::new()
			.intercept_all_syscalls()
			.transform_syscalls()
			.finish()
			.unwrap();

		let mut ctx = set_up().unwrap();
		let sec = ctx.secondary_mut();
		sec.set_generic_syscall_handler(|cl, mut sys| {
			if sys.is_exit() {
				format!("{sys}");
				sys.enrich_values().unwrap();
				format!("{sys}");
				sys.parse_deep(sys.tid, cl, Direction::InOut).unwrap();
				let _sys = format!("{sys}");
			}
			Ok(())
		})
		.unwrap();

		sec.client_mut().set_config(args).unwrap();
		ctx.loop_until_exit().unwrap();
	}

	#[test]
	fn clientmgr_strace_clone() {
		let args = ArgsBuilder::new()
			.intercept_all_syscalls()
			.transform_syscalls()
			.push_registered(RegEvent::Clone)
			.push_registered(RegEvent::Attached)
			.finish()
			.unwrap();
		let numclones = 20;
		let mut name = crate::tests::testdata_dir();
		name.push("waitpid");
		let mut cmd = std::process::Command::new(name);
		cmd.arg(format!("{numclones}"));
		let mut ctx = _set_up(cmd, 0_usize).unwrap();
		let sec = ctx.secondary_mut();
		sec.set_generic_syscall_handler(|_cl, sys| {
			if sys.is_exit() {
				format!("{}", sys.as_nice_str());
			}
			Ok(())
		})
		.unwrap();

		sec.client_mut().set_config(args).unwrap();

		sec.set_stop_handler(|cl, stopped| {
			let add = match stopped.stop {
				Stop::Attach => 11,
				Stop::Clone { pid: _ } => 7,
				_ => panic!("not supported"),
			};

			*(cl.data_mut()) += add;
			Ok(())
		});

		let r = ctx.loop_until_exit().unwrap();

		// Should get both clone and attach
		assert_eq!(r, (11 + 7) * numclones);
	}

	#[test]
	fn clientmgr_strace_fork() {
		let args = ArgsBuilder::new()
			.intercept_all_syscalls()
			.transform_syscalls()
			.push_registered(RegEvent::Attached)
			.push_registered(RegEvent::Fork)
			.finish()
			.unwrap();
		let numclones = 1;
		let mut name = crate::tests::testdata_dir();
		name.push("forkwait");
		let mut cmd = std::process::Command::new(name);
		cmd.arg(format!("{numclones}"));
		let mut ctx = _set_up(cmd, 0_usize).unwrap();
		let sec = ctx.secondary_mut();
		sec.set_generic_syscall_handler(|_cl, sys| {
			if sys.is_exit() {
				format!("{}", sys.as_nice_str());
			}
			Ok(())
		})
		.unwrap();

		sec.client_mut().set_config(args).unwrap();

		sec.set_stop_handler(|cl, stopped| {
			let add = match stopped.stop {
				Stop::Attach => 11,
				Stop::Fork { newpid: _ } => 7,
				_ => panic!("not supported"),
			};
			*(cl.data_mut()) += add;
			Ok(())
		});

		let r = ctx.loop_until_exit().unwrap();

		// Should get both clone and fork
		assert_eq!(r, (7 + 11) * numclones);
	}

	#[test]
	fn clientmgr_bp() {
		let mut ctx = Main::spawn(std::process::Command::new("true"), 0_usize).unwrap();
		let sec = ctx.secondary_mut();

		sec.client_mut().init_done().unwrap();
		let tid = sec.get_first_stopped().unwrap();
		let entry = sec.resolve_entry().unwrap();

		sec.register_breakpoint_handler(tid, entry, |cl, tid, addr| {
			let data = cl.client_mut().read_bytes(tid, addr, 4).unwrap();
			assert!(cl.client_mut().write_bytes(tid, addr, data).unwrap() == 4);

			if let Some(getpid) = cl.lookup_symbol("getpid")? {
				let pid = cl.client_mut().call_func(tid, getpid.value, [])?;
				assert_eq!(pid as Tid, tid);
			} else {
				panic!("unable to find 'getpid'");
			}

			let _v = cl.client_mut().read_u32(tid, addr).unwrap();

			*(cl.data_mut()) += 1;
			Ok(false)
		})
		.unwrap();

		let res = ctx.loop_until_exit().unwrap();

		// Check that we actually hit our breakpoint
		assert_eq!(res, 1);
	}

	#[test]
	fn clientmgr_plugins() {
		let args = ArgsBuilder::new()
			.push_registered(RegEvent::Files)
			.push_registered(RegEvent::Prctl)
			.push_registered(RegEvent::Mmap)
			.push_registered(RegEvent::Dlopen)
			.finish()
			.unwrap();

		let mut ctx = Main::spawn(std::process::Command::new("true"), 0_usize).unwrap();
		let sec = ctx.secondary_mut();

		sec.new_plugin(&Plugin::Files, false).unwrap();
		sec.new_plugin(&Plugin::DlopenDetect, false).unwrap();
		sec.new_plugin(&Plugin::Mmap, false).unwrap();
		sec.new_plugin(&Plugin::Prctl, false).unwrap();

		sec.set_event_handler(|_cl, event| {
			log::trace!("{event}");
			let tid = event.tid.unwrap_or(0);
			match event.event {
				EventInner::FileClosed { fname, fd } => log::info!("{tid}:close({fd} <{fname}>)"),
				EventInner::FileOpened { fname, fd } => log::info!("{tid}:open({fname}) -> {fd}"),
				EventInner::Dlopen { fname } => log::info!("{tid}:dlopen({fname})"),
				EventInner::Mmap {
					addr,
					size,
					prot,
					flags,
					fd,
					offset,
				} => log::info!(
					"{tid}:mmap({addr:x}, {size:x}, {prot:x}, {flags:x} {fd:x} {offset:x})"
				),
				EventInner::Prctl { event } => log::info!("{tid}:prctl({event})"),
				_ => panic!("unsupported event {event:?}"),
			}
			Ok(())
		});
		let client = sec.client_mut();
		client.init_done().unwrap();
		client.set_config(args).unwrap();
		let _res = ctx.loop_until_exit().unwrap();
	}

	#[test]
	fn clientmgr_do_stuff() {
		let args = ArgsBuilder::new()
			.push_registered(RegEvent::Files)
			.finish()
			.unwrap();

		let mut ctx = Main::spawn(std::process::Command::new("true"), 0_usize).unwrap();
		let sec = ctx.secondary_mut();
		let tid = sec.get_first_stopped().unwrap();
		{
			let client = sec.client_mut();
			client.init_done().unwrap();

			client.get_config().unwrap();
			assert!(client.get_config_thread(0).unwrap().is_none());

			client.get_libc_regs(tid).unwrap();
			client.get_tids().unwrap();
			let write = "Hello World";
			let addr1 = client.write_scratch_string(tid, write).unwrap();
			let read = client.read_c_string(tid, addr1).unwrap();
			assert_eq!(read, write);

			let bytes = vec![1, 2, 3, 4];
			let addr2 = client.write_scratch_bytes(tid, bytes.as_slice()).unwrap();
			let read = client.read_bytes(tid, addr2, 4).unwrap();
			assert_eq!(bytes, read);

			// Check that we didn't overwrite the previous one
			let read = client.read_c_string(tid, addr1).unwrap();
			assert_eq!(read, write);

			let vint = client.read_u32(tid, addr2).unwrap();
			assert_eq!(vint, 0x04030201);

			client.free_scratch_addr(tid, addr1).unwrap();
			client.free_scratch_addr(tid, addr2).unwrap();

			// Try double free
			assert!(client.free_scratch_addr(tid, addr2).is_err());

			assert!(client.write_bytes(tid, 0x42, vec![0x00]).is_err());

			let r = client.exec_raw_syscall(tid, u64::MAX, vec![0x00]).unwrap();
			let code = utils::twos_complement(r) as i32;
			assert_eq!(-code, libc::ENOSYS);

			client.set_config(args).unwrap();
		}

		let mut mods = sec.proc.proc_modules().unwrap();
		let last = mods.pop().unwrap();

		assert!(sec
			.get_module(&PathBuf::from_str("dsdsadasd").unwrap())
			.is_err());
		let m = sec.get_module(last.path().unwrap()).unwrap();
		let _funcs = sec
			.symbols_of_type(m.path().unwrap(), SymbolType::Func)
			.unwrap();

		let r = sec.client_mut().call_func(tid, 0x00, []);
		if let Err(e) = r {
			log::debug!("error call @0 {e}");
		} else {
			panic!("did not recieve error can calling@0");
		}

		let _res = ctx.loop_until_exit().unwrap();
	}
}
