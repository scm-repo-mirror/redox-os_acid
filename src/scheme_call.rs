use redox_scheme::scheme::SchemeSync;
use redox_scheme::wrappers::ReadinessBased;
use redox_scheme::{CallerCtx, OpenResult, RequestKind, SignalBehavior, Socket};
use std::cell::RefCell;
use std::io::Read;
use std::os::fd::{FromRawFd, RawFd};
use std::time::Duration;
use syscall::error::*;
use syscall::error::{Error, Result};
use syscall::error::{EINVAL, ENOENT};
use syscall::flag::{MapFlags, O_CLOEXEC, O_RDWR};
use syscall::scheme::{OpenResult, SchemeMut};
use syscall::schemev2::NewFdFlags;
use syscall::CallerCtx;
use syscall::{CallFlags, Result};

use crate::daemon::Daemon;

//
// SCHEME CALL
//
struct SchemeTestCall {}
impl SchemeSync for SchemeTestCall {
    fn open(&mut self, _path: &str, _flags: usize, _ctx: &CallerCtx) -> Result<OpenResult> {
        println!("CALLED SYS_OPEN");
        Ok(OpenResult::ThisScheme {
            number: 0,
            flags: NewFdFlags::empty(),
        })
    }
    fn call(&mut self, id: usize, payload: &mut [u8], metadata: &[u64]) -> Result<usize> {
        println!("CALLED SYS_CALL, ID {id} payload {payload:?} metadata {metadata:?}");
        payload[0] += metadata[0] as u8;
        Ok(1337)
    }
}

pub fn scheme_call() {
    Daemon::new(move |ready| {
        let sock = Socket::create("test-scheme").unwrap();
        let mut scheme = SchemeTestCall {};
        ready.ready().unwrap();

        loop {
            let Some(req) = sock.next_request(SignalBehavior::Restart).unwrap() else {
                break;
            };
            let RequestKind::Call(req) = req.kind() else {
                continue;
            };
            let res = req.handle_sync(&mut scheme);
            let _ = sock.write_response(res, SignalBehavior::Restart).unwrap();
        }
        std::process::exit(0);
    })
    .unwrap();

    let fd = syscall::open("/scheme/test-scheme/file", 0).unwrap();

    let mut data_buf: [u8; 1] = [3];
    let metadata_buf: [u64; 1] = [7];

    let code = unsafe {
        syscall::syscall5(
            syscall::SYS_CALL,
            fd,
            data_buf.as_mut_ptr() as usize,
            data_buf.len(),
            metadata_buf.len(),
            metadata_buf.as_ptr() as usize,
        )
        .unwrap()
    };
    assert_eq!(code, 1337);
    assert_eq!(data_buf[0], 10);
}

//
// SCHEME HEAD TAIL
//

struct SchemeTestHeadTail(Case);

impl SchemeSync for SchemeTestHeadTail {
    fn open(&mut self, _: &str, _: usize, _ctx: &CallerCtx) -> Result<OpenResult> {
        Ok(OpenResult::ThisScheme {
            number: 0,
            flags: Default::default(),
        })
    }
    fn read(
        &mut self,
        _: usize,
        buf: &mut [u8],
        _off: u64,
        _fl: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        if matches!(self.0, Case::Process) {
            verify_head_tail(buf, 0, 0, 0xD7, 0, 0, Some(0xBA), Some(0xAD));
        } else {
            // TODO: Verify what can be verified
        }
        buf.fill(0xF1);

        Ok(buf.len())
    }
    fn write(
        &mut self,
        _: usize,
        buf: &[u8],
        _off: u64,
        _fl: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        if matches!(self.0, Case::Process) {
            verify_head_tail(buf, 0, 0xDA, 0xDA, 0xDA, 0, None, None);
        } else {
            // TODO: Verify what can be verified
        }

        Ok(buf.len())
    }
}

fn verify_head_tail(
    buf: &[u8],
    before: u8,
    head_valid: u8,
    middle: u8,
    tail_valid: u8,
    after: u8,
    write_to_head: Option<u8>,
    write_to_tail: Option<u8>,
) {
    let head = unsafe {
        core::slice::from_raw_parts_mut(
            ((buf.as_ptr() as usize) / 4096 * 4096) as *mut u8,
            (buf.as_ptr() as usize) % 4096,
        )
    };
    let tail = unsafe {
        let end = buf.as_ptr().add(buf.len());
        core::slice::from_raw_parts_mut(end as *mut u8, (4096 - (end as usize % 4096)) % 4096)
    };
    let (head_valid_slice, aligned_slice) = buf.split_at((4096 - head.len()) % 4096);
    let (middle_slice, tail_valid_slice) =
        aligned_slice.split_at(aligned_slice.len() / 4096 * 4096);

    assert_eq!(aligned_slice.as_ptr() as usize % 4096, 0);
    assert_eq!(middle_slice.len() % 4096, 0);
    assert_eq!(head_valid_slice.len() + head.len(), 4096);
    assert_eq!(tail_valid_slice.len() + tail.len(), 4096);
    assert_eq!(
        buf.len(),
        middle_slice.len() + head_valid_slice.len() + tail_valid_slice.len()
    );

    assert_eq!(head, &*vec![before; head.len()]);
    assert_eq!(head_valid_slice, &*vec![head_valid; head_valid_slice.len()]);
    assert_eq!(middle_slice, &*vec![middle; middle_slice.len()]);
    assert_eq!(tail_valid_slice, &*vec![tail_valid; tail_valid_slice.len()]);
    assert_eq!(tail, &*vec![after; tail.len()]);

    if let Some(write) = write_to_head {
        head.fill(write);
    }
    if let Some(write) = write_to_tail {
        tail.fill(write);
    }
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Process,
    Thread,
}

fn scheme_data_leak_test_inner(case: Case) {
    let _guard;
    let scheme = move |daemon: Option<Daemon>| {
        let sock = Socket::create("schemeleak").unwrap();
        if let Some(d) = daemon {
            d.ready().unwrap();
        }
        let mut b = ReadinessBased::new(&sock, 16);
        let scheme = RefCell::new(SchemeTestHeadTail(case));
        loop {
            b.read_requests().unwrap();
            b.process_requests(|| scheme.borrow_mut());
            b.write_responses().unwrap();
        }
    };
    match case {
        Case::Process => {
            crate::daemon::Daemon::new(move |daemon| scheme(Some(daemon))).unwrap();
        }
        Case::Thread => {
            _guard = std::thread::spawn(move || {
                scheme(None);
            });
            // TODO: better sync
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    let buf = unsafe {
        let addr = syscall::fmap(
            !0,
            &syscall::Map {
                offset: 0,
                size: 16384,
                address: 0,
                flags: MapFlags::PROT_WRITE | MapFlags::PROT_READ,
            },
        )
        .unwrap();

        core::slice::from_raw_parts_mut(addr as *mut u8, 16384)
    };
    let fd = syscall::open("schemeleak:", O_CLOEXEC).unwrap();

    buf[..SPLIT].fill(0xBE);
    buf[SPLIT..][..LEN].fill(0xDA);
    buf[SPLIT + LEN..].fill(0xAF);

    let _ = syscall::write(fd, &buf[SPLIT..][..LEN]).unwrap();

    buf[..SPLIT].fill(0xBF);
    buf[SPLIT..4096].fill(0xDE);
    buf[4096..12288].fill(0xD7);
    buf[12288..4096 + LEN].fill(0xAF);
    buf[4096 + LEN..].fill(0xAD);

    let _ = syscall::read(fd, &mut buf[SPLIT..][..LEN]).unwrap();

    assert_eq!(&buf[..SPLIT], vec![0xBF; SPLIT]); // untouched by the kernel
    assert_eq!(&buf[SPLIT..][..LEN], vec![0xF1; LEN]); // copied from scheme
    assert_eq!(&buf[4096 + LEN..], vec![0xAD; buf.len() - 4096 - LEN]); // untouched by the kernel

    std::fs::remove_file(":schemeleak").unwrap();
}

const SPLIT: usize = 3057;
const LEN: usize = 1256 + 8192;
pub fn scheme_data_leak_test_proc() {
    scheme_data_leak_test_inner(Case::Process)
}

pub fn scheme_data_leak_test_thread() {
    scheme_data_leak_test_inner(Case::Thread)
}

//
// CROSS SCHEME LINK
//

struct RedirectScheme;

impl SchemeMut for RedirectScheme {
    fn xopen(&mut self, path: &str, flags: usize, _ctx: &CallerCtx) -> Result<OpenResult> {
        syscall::open(path, flags | O_CLOEXEC).map(|fd| OpenResult::OtherScheme { fd })
    }
}
struct DupScheme;
impl SchemeMut for DupScheme {
    fn open(&mut self, path: &str, _flags: usize, _uid: u32, _gid: u32) -> Result<usize> {
        if !path.is_empty() {
            return Err(Error::new(ENOENT));
        }
        Ok(0)
    }
    fn xdup(&mut self, _old_id: usize, buf: &[u8], _ctx: &CallerCtx) -> Result<OpenResult> {
        syscall::open(
            std::str::from_utf8(buf).map_err(|_| Error::new(EINVAL))?,
            O_RDWR,
        )
        .map(|fd| OpenResult::OtherScheme { fd })
    }
    fn close(&mut self, _id: usize) -> Result<usize> {
        Ok(0)
    }
}

pub fn cross_scheme_link() {
    println!("Testing cross scheme links");
    crate::daemon::scheme("cross_scheme_link_redirect", "redirect", RedirectScheme).unwrap();
    crate::daemon::scheme("cross_scheme_link_dup", "dup", DupScheme).unwrap();
    println!("Started scheme daemons");

    // Open an event queue through the redirect scheme. Unless the kernel is trying to trick us by
    // renaming `event:`, it will never work without cross scheme links;

    let path = "file:/tmp/cross_scheme_link.tmp";
    let data = "some data";

    std::fs::write(path, data).unwrap();

    let mut file2 = unsafe {
        std::fs::File::from_raw_fd(
            syscall::open(format!("redirect:{path}"), O_RDWR | O_CLOEXEC).unwrap() as RawFd,
        )
    };

    let mut file3 = unsafe {
        let dup_handle = syscall::open("dup:", O_CLOEXEC).unwrap();
        let fd = syscall::dup(dup_handle, path.as_bytes()).unwrap();
        let _ = syscall::close(dup_handle);
        std::fs::File::from_raw_fd(fd as RawFd)
    };
    let mut buf1 = String::new();
    let mut buf2 = String::new();
    file2.read_to_string(&mut buf1).unwrap();
    file3.read_to_string(&mut buf2).unwrap();

    assert_eq!(buf1, data);
    assert_eq!(buf2, data);

    let _ = syscall::unlink(":redirect");
    let _ = syscall::unlink(":dup");
}

//
// misc tests
//

pub fn libc_call() {
    // getppid is not currently cached, but TODO this is perhaps not relibc-future-proof for
    // benchmarking

    // Same number with sys_call of arch/syscall.rs
    const N: usize = 1 << 24;

    for i in 0..N {
        assert_ne!(unsafe { libc::getppid() }, -1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[bench]
    fn bench_libc_call() {
        libc_call()
    }

    #[bench]
    fn test_scheme_calll() {
        scheme_call()
    }
}
