use std::{fs::OpenOptions, os::fd::IntoRawFd};

use syscall::{Map, MapFlags, PAGE_SIZE};

// TODO: Probably this is arch-independent test
pub fn redoxfs_range_bookkeeping() {
    // Number of pages
    const P: usize = 128;

    let mut chunks = vec![false; P];

    // Number of operations
    const N: usize = 10000;

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open("tmp")
        .unwrap();
    file.set_len((P * PAGE_SIZE) as u64).unwrap();
    let fd = file.into_raw_fd() as usize;

    fn rand() -> usize {
        let ret: usize;
        unsafe {
            core::arch::asm!("rdrand {}", out(reg) ret);
        }
        ret
    }

    for _ in 0..N {
        let n = rand();
        let insert_not_remove = n & (1 << (usize::BITS - 1)) != 0;
        let idx = n % P;

        if insert_not_remove {
            let Some((first_unused, _)) = chunks
                .iter()
                .copied()
                .enumerate()
                .filter(|&(_, c)| !c)
                .nth(idx)
            else {
                continue;
            };
            chunks[first_unused] = true;

            unsafe {
                let _ = syscall::fmap(
                    fd,
                    &Map {
                        address: 0xDEADB000 + first_unused * PAGE_SIZE,
                        offset: first_unused * PAGE_SIZE,
                        flags: MapFlags::PROT_READ
                            | MapFlags::PROT_WRITE
                            | MapFlags::MAP_SHARED
                            | MapFlags::MAP_FIXED,
                        size: PAGE_SIZE,
                    },
                )
                .expect("failed to fmap");
            }
        } else {
            let Some((first_used, _)) = chunks
                .iter()
                .copied()
                .enumerate()
                .filter(|&(_, c)| c)
                .nth(idx)
            else {
                continue;
            };
            chunks[first_used] = false;

            unsafe {
                syscall::funmap(0xDEADB000 + first_used * PAGE_SIZE, PAGE_SIZE)
                    .expect("failed to funmap");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_redoxfs_range_bookkeeping(b: &mut Bencher) {
        redoxfs_range_bookkeeping()
    }
}
