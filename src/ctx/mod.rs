//! Context object(s) the client should hold to control the traced process.
//!

mod main;
mod secondary;

pub use main::Main;
pub use secondary::Secondary;

#[cfg(test)]
mod tests {
	use crate::api::messages::CbAction;
	use serial_test::serial;

	#[cfg(target_arch = "x86_64")]
	use test::Bencher;

	#[cfg(feature = "syscalls")]
	use crate::api::args::Enrich;
	use crate::api::messages::BpRet;
	#[cfg(feature = "syscalls")]
	use crate::syscalls::Syscalls;

	#[cfg(all(feature = "syscalls", feature = "plugins"))]
	use crate::api::messages::EventInner;

	use super::*;
	use crate::{
		api::{
			messages::{RegEvent, Stop, SymbolType},
			ArgsBuilder, Response,
		},
		exe::elf::Elf,
		utils::{self, process::Tid},
		Result, TargetPtr,
	};
	use std::{path::PathBuf, str::FromStr};

	fn __set_up<T>(cmd: std::process::Command, data: T) -> Result<Main<T, crate::Error>> {
		let mut ctx = Main::new_spawn(cmd, data)?;
		ctx.secondary_mut().client_mut().init_done()?;
		Ok(ctx)
	}

	// Regular set is to have an int as the state, this allows us to modify the
	// int and test the int's value after the program exits.
	fn set_up_int(init: usize) -> Result<Main<usize, crate::Error>> {
		let cmd = std::process::Command::new("true");
		__set_up(cmd, init)
	}
	fn set_up() -> Result<Main<usize, crate::Error>> {
		let cmd = std::process::Command::new("true");
		__set_up(cmd, 0)
	}
	// fn set_up_cmd(cmd: std::process::Command) -> Result<Main<usize, crate::Error>> {
	// 	__set_up(cmd, 0)
	// }

	#[cfg(target_arch = "x86_64")]
	#[bench]
	fn bench_trace_outer(b: &mut Bencher) {
		clientmgr_basic();
		b.iter(move || {
			clientmgr_basic();
			std::hint::black_box(())
		})
	}

	#[cfg(target_arch = "x86_64")]
	#[bench]
	fn bench_trace_strace_raw(b: &mut Bencher) {
		clientmgr_strace_raw();
		b.iter(move || {
			clientmgr_strace_raw();
			std::hint::black_box(())
		})
	}
	#[cfg(all(feature = "syscalls", target_arch = "x86_64"))]
	#[bench]
	fn bench_trace_strace_basic(b: &mut Bencher) {
		clientmgr_strace_basic();
		b.iter(move || {
			clientmgr_strace_basic();
			std::hint::black_box(())
		})
	}
	#[cfg(all(feature = "syscalls", target_arch = "x86_64"))]
	#[bench]
	fn bench_trace_strace_full(b: &mut Bencher) {
		clientmgr_strace_full();
		b.iter(move || {
			clientmgr_strace_full();
			std::hint::black_box(())
		})
	}

	//#[cfg(all(feature = "syscalls", target_arch = "x86_64"))]
	//#[bench]
	//fn bench_parsed_syscalls(b: &mut Bencher) {
	//	syscalls0();
	//	b.iter(|| {
	//		syscalls0();
	//		std::hint::black_box(())
	//	})
	//}

	// Disabled on arm just because it's so slow in the emulator
	//#[cfg(all(feature = "syscalls", not(target_arch = "arm")))]
	//#[test]
	//fn syscalls0() {
	//	let data = syzlang_data::linux::PARSED.read().unwrap();
	//	let syzarch = crate::syzarch();

	//	// This also runs in benchmark, so we can't take data from original
	//	// here, so we have to clone here. This results in worse times and not
	//	// the most realistic, but still ok for comparison.
	//	let mut parsed = data.clone();
	//	parsed.remove_virtual_functions();
	//	parsed.remove_func_no_sysno(&syzarch);
	//	parsed.remove_subfunctions();
	//	parsed.consts.filter_arch(&syzarch);
	//	let syscalls: Syscalls = (&parsed).try_into().unwrap();
	//	let _v = syscalls.resolve(1).unwrap();
	//}

	#[test]
	fn clientmgr_basic() {
		let ctx = set_up_int(0).unwrap();
		ctx.loop_until_exit().unwrap();
	}

	#[test]
	fn clientmgr_strace_raw() {
		let mut ctx = set_up_int(0).unwrap();
		let sec = ctx.secondary_mut();

		sec.set_raw_syscall_handler(|_cl, tid, entry| {
			let _sys = format!("[{tid}]: {entry}");
			// log::error!("{sys}");
			Ok(())
		});
		ctx.loop_until_exit().unwrap();
	}
	#[cfg(feature = "syscalls")]
	#[test]
	fn clientmgr_strace_basic() {
		let mut ctx = set_up_int(0).unwrap();
		let sec = ctx.secondary_mut();
		sec.args_builder_mut().set_only_notify_syscall_exit(true);
		sec.set_generic_syscall_handler_exit(|_cl, sys| {
			assert!(sys.is_exit());
			let _sys = format!("{sys}");
			// log::error!("{sys}");
			Ok(CbAction::None)
		});
		sec.enrich_syscalls(Enrich::Basic);

		ctx.loop_until_exit().unwrap();
	}

	#[cfg(feature = "syscalls")]
	#[test]
	fn clientmgr_strace_full() {
		let mut ctx = set_up_int(0).unwrap();
		let sec = ctx.secondary_mut();
		sec.set_generic_syscall_handler_exit(|_cl, sys| {
			assert!(sys.is_exit());
			let _sys = format!("{sys}");
			// log::error!("{sys}");
			Ok(CbAction::None)
		});
		sec.enrich_syscalls(Enrich::Basic);

		ctx.loop_until_exit().unwrap();
	}

	#[test]
	fn clientmgr_step0() {
		let mut ctx = set_up_int(0).unwrap();

		let tid = ctx.secondary_mut().get_first_stopped().unwrap();

		// We haven't registered for the step, so, we will take a step
		// (hopefully), but we don't get any indication.
		ctx.secondary_mut().client_mut().step_ins(tid, 1).unwrap();
		let (rsp, _) = ctx.loop_until_exit().unwrap();
		assert_eq!(rsp, Response::TargetExit);
	}

	#[cfg(not(any(target_arch = "arm", target_arch = "riscv64")))]
	#[test]
	fn clientmgr_step1() {
		let mut ctx = set_up_int(42).unwrap();

		let tid = ctx.secondary_mut().get_first_stopped().unwrap();
		ctx.secondary_mut().set_step_handler(|cl, tid, _pc| {
			let c = cl.data_mut();
			if *c > 0 {
				*c -= 1;

				// We must notify about step each time
				cl.client_mut().step_ins(tid, 1).unwrap();
			}
			Ok(())
		});
		let client = ctx.secondary_mut().client_mut();
		client.step_ins(tid, 1).unwrap();

		// Finally run until exit
		let (rsp, cnt) = ctx.loop_until_exit().unwrap();
		log::debug!("rsp {rsp:?} {cnt}");
		assert_eq!(rsp, Response::TargetExit);

		// Ensure that we hit the expected number of steps
		assert_eq!(cnt, 0);
	}

	#[cfg(feature = "syscalls")]
	#[test]
	fn clientmgr_strace0() {
		use crate::api::messages::Direction;

		let mut ctx = set_up_int(0).unwrap();
		let sec = ctx.secondary_mut();
		sec.set_generic_syscall_handler_exit(|cl, sys| {
			log::debug!("hit cb handler");
			let mut sys = sys.clone();
			format!("{sys}");
			sys.enrich_values().unwrap();
			format!("{sys}");
			sys.parse_deep::<crate::api::Command>(sys.tid, cl.client_mut(), Direction::InOut)
				.unwrap();
			let _sys = format!("{sys}");
			*(cl.data_mut()) += 1;
			Ok(CbAction::None)
		});

		let (_rsp, count) = ctx.loop_until_exit().unwrap();

		// We don't know how many we will hit, but should always hit some
		assert!(count > 0);
	}

	#[cfg(not(target_arch = "arm"))]
	#[test]
	fn clientmgr_early_ret_func() {
		let numsleep = 3;
		let mut files = crate::tests::get_all_tar_files().unwrap();
		let sleep = files
			.remove("sleep")
			.expect("sleep not present in testdata");
		let pargs = vec![format!("{numsleep}")];
		let mut ctx: Main<usize, crate::Error> =
			Main::spawn_in_mem("sleep", sleep.clone(), pargs, 0_usize).unwrap();
		let sec = ctx.secondary_mut();

		let entry = sec.resolve_entry().unwrap();
		let stopped = sec.run_until_entry().unwrap();
		assert_eq!(stopped.expect("didn't hit breakpoint"), entry);

		let v = sec
			.lookup_symbol_in_any("sleep")
			.unwrap()
			.expect("unable to find sleep");
		let tid = sec.get_first_stopped().unwrap();

		sec.register_function_hook_entry(tid, v.value, |cl, frame| {
			let secs = frame.arg(0, cl.client_mut())?.as_i32();
			log::debug!("was supposed to sleep for {secs:x} seconds");
			assert_eq!(secs, 1);
			*(cl.data_mut()) += 1;
			Ok(CbAction::EarlyRet { ret: 1.into() })
		})
		.unwrap();

		let (r, res) = ctx.loop_until_exit().unwrap();
		assert_eq!(r, Response::TargetExit);
		assert_eq!(res, numsleep);
	}

	#[cfg(not(target_arch = "arm"))]
	#[test]
	fn clientmgr_strace_clone() {
		let numclones = 2; // This is hard-coded in program
		let mut files = crate::tests::get_all_tar_files().unwrap();
		let threads = files
			.remove("threads")
			.expect("threads not present in testdata");

		let mut ctx: Main<usize, crate::Error> =
			Main::spawn_in_mem("threads", threads, &[], 0_usize).unwrap();
		let sec = ctx.secondary_mut();

		let args = sec
			.take_args_builder()
			.push_registered(RegEvent::Clone)
			.push_registered(RegEvent::Attached);
		sec.set_args_builder(args);

		sec.set_stop_handler(|cl, stopped| {
			let add = match stopped.stop {
				Stop::Attach => 11,
				Stop::Clone { pid: _ } => 7,
				_ => panic!("not supported"),
			};

			*(cl.data_mut()) += add;
			Ok(())
		});

		let (_r, r) = ctx.loop_until_exit().unwrap();

		// Should get both clone and attach
		assert_eq!(r, (11 + 7) * numclones);
	}

	#[cfg(not(target_arch = "arm"))]
	#[serial]
	#[test]
	fn clientmgr_strace_fork() {
		let numclones = 1;
		let mut files = crate::tests::get_all_tar_files().unwrap();
		let forkwait = files
			.remove("forkwait")
			.expect("forkwait not present in testdata");
		let pargs = vec![format!("{numclones}")];
		let mut ctx: Main<usize, crate::Error> =
			Main::spawn_in_mem("forkwait", forkwait, pargs, 0_usize).unwrap();
		let sec = ctx.secondary_mut();

		let args = sec
			.take_args_builder()
			.push_registered(RegEvent::Attached)
			.push_registered(RegEvent::Fork);
		sec.set_args_builder(args);

		sec.set_stop_handler(|cl, stopped| {
			let add = match stopped.stop {
				Stop::Attach => 11,
				Stop::Fork { newpid: _ } => 7,
				_ => panic!("not supported"),
			};
			*(cl.data_mut()) += add;
			Ok(())
		});

		let (_r, r) = ctx.loop_until_exit().unwrap();

		// Should get both clone and fork
		assert_eq!(r, (7 + 11) * numclones);
	}

	// Insert single breakpoint at entry and verify that we hit it
	#[test]
	fn clientmgr_bp0() {
		let mut ctx = set_up().unwrap();
		let sec = ctx.secondary_mut();

		sec.client_mut().init_done().unwrap();
		let tid = sec.get_first_stopped().unwrap();
		let entry = sec.resolve_entry().unwrap();

		sec.register_breakpoint_handler(tid, entry, |cl, _tid, _addr| {
			*(cl.data_mut()) += 1;
			Ok(BpRet::Remove)
		})
		.unwrap();

		let (rsp, res) = ctx.loop_until_exit().unwrap();
		assert_eq!(rsp, Response::TargetExit);
		assert_eq!(res, 1);
	}

	// Insert bp at entry and re-insert after we continue, it will never be hit
	// again (hopefully), but tests that insertion again doesn't cause problems.
	#[test]
	fn clientmgr_bp1() {
		let mut ctx = set_up().unwrap();
		let sec = ctx.secondary_mut();

		let tid = sec.get_first_stopped().unwrap();
		let entry = sec.resolve_entry().unwrap();
		sec.register_breakpoint_handler(tid, entry, |cl, _tid, _addr| {
			*(cl.data_mut()) += 1;
			Ok(BpRet::Keep)
		})
		.unwrap();

		let (rsp, res) = ctx.loop_until_exit().unwrap();
		assert_eq!(rsp, Response::TargetExit);
		assert_eq!(res, 1);
	}

	// Insert BP at entry, when hit we resolve a function and insert breakpoint
	// at that function. Verifies that all breakpoints are hit the correct
	// number of times. We call exec and replace after, so must run until exec
	// and resolve entry then
	#[cfg(any())]
	#[test]
	fn clientmgr_bp2() {
		let count = 2;
		let mut files = crate::tests::get_all_tar_files().unwrap();
		let getpid = files
			.remove("getpid")
			.expect("getpid not present in testdata");
		let pargs = vec![format!("{count}")];
		let mut ctx: Main<usize, crate::Error> =
			Main::spawn_in_mem("getpid", getpid, pargs, 0_usize).unwrap();

		// let mut cmd = std::process::Command::new("./testdata/getpid");
		// cmd.arg(format!("{count}"));
		// let mut ctx = set_up_cmd(cmd).unwrap();
		let sec = ctx.secondary_mut();

		let tid = sec.get_first_stopped().unwrap();
		let entry = sec.resolve_entry().unwrap();
		log::error!("entry = {entry:x}");
		sec.register_breakpoint_handler(tid, entry, |cl, tid, _addr| {
			*(cl.data_mut()) += 3;
			if let Some(sym) = cl.lookup_symbol("getpid")? {
				cl.register_breakpoint_handler(tid, sym.value, |cl, _tid, addr| {
					log::trace!("hit our bp {addr:x}");
					*(cl.data_mut()) += 7;
					Ok(true)
				})?;
			}
			Ok(true)
		})
		.unwrap();

		let (rsp, res) = ctx.loop_until_exit().unwrap();
		assert_eq!(rsp, Response::TargetExit);
		assert_eq!(res, 3 + (count * 7));
	}

	// Breakpoint at entry and call a function when bp is hit
	#[test]
	fn clientmgr_bp3() {
		let mut ctx = set_up().unwrap();
		let sec = ctx.secondary_mut();

		sec.client_mut().init_done().unwrap();
		let tid = sec.get_first_stopped().unwrap();
		let entry = sec.resolve_entry().unwrap();

		sec.register_breakpoint_handler(tid, entry, |cl, tid, addr| {
			let data = cl.client_mut().read_bytes(tid, addr, 4).unwrap();
			assert!(cl.client_mut().write_bytes(tid, addr, data).unwrap() == 4);

			let libc = cl.try_find_libc_so().unwrap();
			if let Some(getpid) = cl.resolve_symbol_in_mod(&libc, "getpid")? {
				log::debug!("resolved getpid {getpid:?}");
				let pid = cl.call_func(tid, getpid.value, &[])?;
				assert_eq!(pid, tid.into());
			} else {
				panic!("unable to find 'getpid'");
			}
			let _v = cl.client_mut().read_u32(tid, addr).unwrap();
			*(cl.data_mut()) += 1;
			Ok(BpRet::Keep)
		})
		.unwrap();

		let (_, res) = ctx.loop_until_exit().unwrap();

		// Check that we actually hit our breakpoint
		assert_eq!(res, 1);
	}

	#[cfg(all(feature = "syscalls", feature = "plugins"))]
	#[test]
	fn clientmgr_plugins() {
		use crate::plugin::Plugin;

		let mut ctx: Main<usize, crate::Error> =
			Main::new_spawn(std::process::Command::new("true"), 0_usize).unwrap();
		let sec = ctx.secondary_mut();
		let args = sec
			.take_args_builder()
			.push_registered(RegEvent::Files)
			.push_registered(RegEvent::Prctl)
			.push_registered(RegEvent::Mmap)
			.push_registered(RegEvent::Dlopen);
		sec.set_args_builder(args);

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
		// client.set_config(args).unwrap();
		let _res = ctx.loop_until_exit().unwrap();
	}

	#[test]
	fn clientmgr_do_stuff() {
		let pargs = vec![];
		let mut ctx: Main<usize, crate::Error> =
			Main::new_main(false, "true".to_string(), pargs, 0_usize).unwrap();
		let sec = ctx.secondary_mut();
		let args = sec.take_args_builder().push_registered(RegEvent::Files);
		sec.set_args_builder(args);
		let tid = sec.get_first_stopped().unwrap();
		{
			let client = sec.client_mut();
			client.init_done().unwrap();

			client.get_config().unwrap();
			assert!(client.get_config_thread(0).unwrap().is_none());

			client.get_registers(tid).unwrap();
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

			assert!(client.write_bytes(tid, 0x42.into(), vec![0x00]).is_err());

			// This is returning SIGILL on arm
			let r = client.exec_raw_syscall(tid, usize::MAX, vec![0x00.into()]);

			#[cfg(target_arch = "arm")]
			{
				assert!(r.is_err())
			}
			#[cfg(not(target_arch = "arm"))]
			{
				let r = r.unwrap();
				let code = r.as_i32();
				assert_eq!(-code, libc::ENOSYS);
			}
		}

		let mut mods = sec.proc.proc_modules().unwrap();
		let last = mods.pop().unwrap();

		assert!(sec
			.get_memory_map_exact(&PathBuf::from_str("dsdsadasd").unwrap())
			.is_err());
		let m = sec.get_memory_map_exact(last.path().unwrap()).unwrap();
		let _funcs = sec
			.enumerate_symbols_of_type(m.path().unwrap(), SymbolType::Func)
			.unwrap();

		let r = sec.call_func(tid, 0x00.into(), &[]);
		if let Err(e) = r {
			log::debug!("error call @0 {e}");
		} else {
			panic!("did not recieve error can calling@0");
		}

		let _res = ctx.loop_until_exit().unwrap();
	}
}
