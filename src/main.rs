//!Acid testing program
#![feature(core_intrinsics, let_chains, thread_local)]

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::hash::Hasher;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::thread::JoinHandleExt;
use std::process::Command;
use std::sync::atomic::{compiler_fence, AtomicUsize, Ordering};
use std::sync::Barrier;
use std::thread;
use std::time::{Duration, Instant};
use std::{env, process};

use libc::c_int;
use thread::PAGE_SIZE;
use thread::{
    Map, MapFlags, ADDRSPACE_OP_MMAP, ADDRSPACE_OP_MUNMAP, O_CLOEXEC, O_CREAT, O_DIRECTORY,
    O_RDONLY, O_RDWR,
};

use anyhow::{bail, Result};

// (rust-analyzer uses cfg(test) but doesn't need symbols, which cargo check would need)
#[cfg(any(test, target_os = "redox"))]
mod scheme_call;

mod arch;
mod daemon;
mod fdtbl;
mod memory;
mod proc;
mod thread;
mod uds;

fn main() {
    let mut tests: HashMap<&'static str, fn()> = HashMap::new();
    #[cfg(target_arch = "x86_64")]
    tests.insert("avx2", arch::avx2);
    tests.insert("create_test", create_test);
    tests.insert("channel", channel_test);
    // tests.insert("page_fault", page_fault_test); // TODO
    tests.insert("sleep_granularity", sleep_granularity_test);
    #[cfg(target_arch = "x86_64")]
    tests.insert("switch", switch_test);
    tests.insert("thread", thread_test);
    tests.insert("tls", tls_test);
    #[cfg(any(test, target_os = "redox"))]
    {
        tests.insert("cross_scheme_link", cross_scheme_link::cross_scheme_link);
    }
    tests.insert("efault", efault_test);
    #[cfg(target_arch = "x86_64")]
    tests.insert("direction_flag_sc", arch::direction_flag_syscall);
    #[cfg(target_arch = "x86_64")]
    tests.insert("direction_flag_int", arch::direction_flag_interrupt);
    tests.insert("pipe", pipe_test);
    #[cfg(any(test, target_os = "redox"))]
    {
        tests.insert(
            "scheme_data_leak_proc",
            scheme_data_leak::scheme_data_leak_test_proc,
        );
        tests.insert(
            "scheme_data_leak_thread",
            scheme_data_leak::scheme_data_leak_test_thread,
        );
    }
    tests.insert("relibc_leak", relibc_leak::test);
    tests.insert("clone_grant_using_fmap", clone_grant_using_fmap_test);
    tests.insert(
        "clone_grant_using_fmap_lazy",
        clone_grant_using_fmap_lazy_test,
    );
    // TODO: FIX openat_test
    // tests.insert("openat", openat_test);
    tests.insert("anonymous_map_shared", anonymous_map_shared);
    //tests.insert("tlb", tlb_test); // TODO
    tests.insert("file_mmap", file_mmap_test);
    #[cfg(target_arch = "x86_64")]
    tests.insert("redoxfs_range_bookkeeping", redoxfs_range_bookkeeping);
    //tests.insert("eintr", eintr::eintr); // TODO
    tests.insert("syscall_bench", syscall_bench::bench);
    tests.insert("scheme_call_bench", syscall_bench::scheme_call_bench);
    tests.insert("filetable_leak", filetable_leak);
    #[cfg(target_os = "redox")]
    tests.insert("scheme_call", scheme_call::scheme_call);
    tests.insert("fork_tree_bench", proc::fork_tree_bench::<false>);
    tests.insert("fork_serial_bench", proc::fork_serial_bench::<false>);
    tests.insert("fork_exec_serial_bench", proc::fork_serial_bench::<true>);
    tests.insert("fork_exec_tree_bench", proc::fork_tree_bench::<true>);
    tests.insert("stop_orphan_pgrp", proc::stop_orphan_pgrp);
    tests.insert("setpgid", proc::setpgid);
    tests.insert("setsid", proc::setsid);
    tests.insert("reparenting", proc::reparenting);
    tests.insert("waitpid_setpgid_echild", proc::waitpid_setpgid_echild);
    tests.insert("thread_reap", proc::thread_reap);
    tests.insert("orphan_exit_sighup", proc::orphan_exit_sighup::<false>);
    tests.insert(
        "orphan_exit_sighup_session",
        proc::orphan_exit_sighup::<true>,
    );
    tests.insert(
        "wcontinued_sigcont_catching",
        proc::wcontinued_sigcont_catching,
    );
    tests.insert("using_signal_hook", proc::using_signal_hook);
    tests.insert("waitpid_esrch", proc::waitpid_esrch);
    tests.insert("waitpid_status_discard", proc::waitpid_status_discard);
    tests.insert("waitpid_transitive_queue", proc::waitpid_transitive_queue);
    tests.insert("pgrp_lifetime", proc::pgrp_lifetime);
    tests.insert("waitpid_eintr", proc::waitpid_eintr);
    tests.insert("raise_correct_sig_group", proc::raise_correct_sig_group);
    tests.insert("sigkill_fail_code", proc::sigkill_fail_code);

    // TODO: unpack these UDS tests
    tests.insert("uds_dgram", uds::dgram_tests::run_all);
    tests.insert("uds_stream", uds::stream_tests::run_all);
    tests.insert("uds_dgram_msghdr", uds::dgram_msghdr_tests::run_all);
    tests.insert("uds_stream_msghdr", uds::stream_msghdr_tests::run_all);
    tests.insert("fdtbl", fdtbl::run_all);

    let mut ran_test = false;
    for arg in env::args().skip(1) {
        if let Some(test) = tests.get(&arg.as_str()) {
            ran_test = true;

            let time = Instant::now();
            test();
            let elapsed = time.elapsed();
        } else {
            println!("acid: {}: not found", arg);
            process::exit(1);
        }
    }

    if !ran_test {
        for test in tests {
            println!("{}", test.0);
        }
    }
}
