pub mod master;
pub mod secondary;

pub use master::Master;
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

	fn _set_up<T>(cmd: std::process::Command, data: T) -> Result<Master<T>> {
		let mut ctx = Master::spawn(cmd, data)?;
		ctx.ctx.client.init_done()?;
		Ok(ctx)
	}

	fn set_up() -> Result<Master<()>> {
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
		ctx.ctx
			.set_generic_syscall_handler(|cl, mut sys| {
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

		ctx.ctx.client.set_config(args).unwrap();
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
		ctx.ctx
			.set_generic_syscall_handler(|_cl, sys| {
				if sys.is_exit() {
					format!("{}", sys.as_nice_str());
				}
				Ok(())
			})
			.unwrap();

		ctx.ctx.client.set_config(args).unwrap();

		ctx.ctx.set_stop_handler(|cl, stopped| {
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
		ctx.ctx
			.set_generic_syscall_handler(|_cl, sys| {
				if sys.is_exit() {
					format!("{}", sys.as_nice_str());
				}
				Ok(())
			})
			.unwrap();

		ctx.ctx.client.set_config(args).unwrap();

		ctx.ctx.set_stop_handler(|cl, stopped| {
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
		let mut ctx = Master::spawn(std::process::Command::new("true"), 0_usize).unwrap();

		ctx.ctx.client.init_done().unwrap();
		let tid = ctx.ctx.get_first_stopped().unwrap();
		let entry = ctx.ctx.resolve_entry().unwrap();

		ctx.ctx
			.register_breakpoint_handler(tid, entry, |cl, tid, addr| {
				let data = cl.client.read_bytes(tid, addr, 4).unwrap();
				assert!(cl.client.write_bytes(tid, addr, data).unwrap() == 4);

				if let Some(getpid) = cl.lookup_symbol("getpid")? {
					let pid = cl.client.call_func(tid, getpid.value, [])?;
					assert_eq!(pid as Tid, tid);
				} else {
					panic!("unable to find 'getpid'");
				}

				let _v = cl.client.read_u32(tid, addr).unwrap();

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

		let mut ctx = Master::spawn(std::process::Command::new("true"), 0_usize).unwrap();

		ctx.ctx.new_plugin(&Plugin::Files, false).unwrap();
		ctx.ctx.new_plugin(&Plugin::DlopenDetect, false).unwrap();
		ctx.ctx.new_plugin(&Plugin::Mmap, false).unwrap();
		ctx.ctx.new_plugin(&Plugin::Prctl, false).unwrap();

		ctx.ctx.client.init_done().unwrap();

		ctx.ctx.set_event_handler(|_cl, event| {
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

		ctx.ctx.client.set_config(args).unwrap();
		let _res = ctx.loop_until_exit().unwrap();
	}

	#[test]
	fn clientmgr_do_stuff() {
		let args = ArgsBuilder::new()
			.push_registered(RegEvent::Files)
			.finish()
			.unwrap();

		let mut ctx = Master::spawn(std::process::Command::new("true"), 0_usize).unwrap();

		ctx.ctx.client.init_done().unwrap();

		ctx.ctx.client.get_config().unwrap();
		assert!(ctx.ctx.client.get_config_thread(0).unwrap().is_none());
		let tid = ctx.ctx.get_first_stopped().unwrap();
		ctx.ctx.client.get_libc_regs(tid).unwrap();
		ctx.ctx.client.get_tids().unwrap();

		let write = "Hello World";
		let addr1 = ctx.ctx.client.write_scratch_string(tid, write).unwrap();
		let read = ctx.ctx.client.read_c_string(tid, addr1).unwrap();
		assert_eq!(read, write);

		let bytes = vec![1, 2, 3, 4];
		let addr2 = ctx
			.ctx
			.client
			.write_scratch_bytes(tid, bytes.as_slice())
			.unwrap();
		let read = ctx.ctx.client.read_bytes(tid, addr2, 4).unwrap();
		assert_eq!(bytes, read);

		// Check that we didn't overwrite the previous one
		let read = ctx.ctx.client.read_c_string(tid, addr1).unwrap();
		assert_eq!(read, write);

		let vint = ctx.ctx.client.read_u32(tid, addr2).unwrap();
		assert_eq!(vint, 0x04030201);

		ctx.ctx.client.free_scratch_addr(tid, addr1).unwrap();
		ctx.ctx.client.free_scratch_addr(tid, addr2).unwrap();

		// Try double free
		assert!(ctx.ctx.client.free_scratch_addr(tid, addr2).is_err());

		assert!(ctx.ctx.client.write_bytes(tid, 0x42, vec![0x00]).is_err());

		let r = ctx
			.ctx
			.client
			.exec_raw_syscall(tid, u64::MAX, vec![0x00])
			.unwrap();
		let code = utils::twos_complement(r) as i32;
		assert_eq!(-code, libc::ENOSYS);

		let mut mods = ctx.ctx.proc.proc_modules().unwrap();
		let last = mods.pop().unwrap();

		assert!(ctx
			.ctx
			.get_module(&PathBuf::from_str("dsdsadasd").unwrap())
			.is_err());
		let m = ctx.ctx.get_module(last.path().unwrap()).unwrap();
		let _funcs = ctx
			.ctx
			.symbols_of_type(m.path().unwrap(), SymbolType::Func)
			.unwrap();

		let r = ctx.ctx.client.call_func(tid, 0x00, []);
		if let Err(e) = r {
			log::debug!("error call @0 {e}");
		} else {
			panic!("did not recieve error can calling@0");
		}

		ctx.ctx.client.set_config(args).unwrap();
		let _res = ctx.loop_until_exit().unwrap();
	}
}
