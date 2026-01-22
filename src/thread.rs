#![allow(static_mut_refs)]

use std::thread;

pub fn context_switch() {
    let switch_thread = thread::spawn(|| -> usize {
        let mut j = 0;
        while j < 10000 {
            thread::yield_now();
            j += 1;
        }
        j
    });

    let mut i = 0;
    while i < 10000 {
        thread::yield_now();
        i += 1;
    }

    switch_thread.join().unwrap();
}

pub fn thread_spawn() {
    // Same loop count with context_switch
    for _ in 1..10000 {
        let mut thread_list = vec![];
        for j in 1..5 {
            thread_list.push(std::thread::spawn(move || outer_runner(j)));
        }
        while thread_list.iter().any(|t| !t.is_finished()) {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

fn outer_runner(threadnum: usize) {
    // eprintln!("outer_runner {}", threadnum);
    inner_runner(threadnum);
    // eprintln!("outer_runner {} exiting", threadnum);
}

fn inner_runner(_threadnum: usize) {
    // eprintln!("start runner {}", threadnum);
    std::thread::sleep(std::time::Duration::from_millis(1));
    // eprintln!("end runner {}", threadnum);
}

pub fn channel() {
    let mut threads = Vec::new();
    let (tx, mut rx) = std::sync::mpsc::channel();
    for i in 0..256 {
        eprintln!("spawn thread {}", i);
        let (next_tx, next_rx) = std::sync::mpsc::channel();
        threads.push(thread::spawn(move || {
            let value = rx.recv().unwrap();
            eprintln!("thread {i} received {value:#x}");
            next_tx.send(value).unwrap();
        }));
        rx = next_rx;
    }

    let value = 0xCAFE;
    eprintln!("send value {value:#x} to threads");
    tx.send(value).unwrap();

    for thread in threads {
        thread.join().unwrap();
    }
}

pub fn sleep_granularity() {
    use std::time::{Duration, Instant};
    let mut threads = Vec::new();
    for &sleep in &[
        Duration::from_micros(1),
        Duration::from_micros(10),
        Duration::from_micros(100),
        Duration::from_millis(1),
        Duration::from_millis(10),
        Duration::from_millis(100),
    ] {
        threads.push(thread::spawn(move || {
            let mut min = Duration::default();
            let mut max = Duration::default();
            let mut total = Duration::default();
            let mut times = 0;
            let timer = Instant::now();
            while timer.elapsed().as_secs() < 10 {
                let instant = Instant::now();
                thread::sleep(sleep);
                let elapsed = instant.elapsed();
                if times == 0 {
                    min = elapsed;
                    max = elapsed;
                } else {
                    min = min.min(elapsed);
                    max = max.max(elapsed);
                }
                total += elapsed;
                times += 1;
            }
            println!(
                "sleep {:?} times {} min {:?} max {:?} average {:?}",
                sleep,
                times,
                min,
                max,
                total / times
            );
        }));
    }

    for thread in threads {
        thread.join().unwrap();
    }
}

/// Test of zero values in thread BSS
#[thread_local]
static mut TBSS_TEST_ZERO: usize = 0;
/// Test of non-zero values in thread data.
#[thread_local]
static mut TDATA_TEST_NONZERO: usize = usize::max_value();

pub fn tls() {
    thread::spawn(|| unsafe {
        assert_eq!(TBSS_TEST_ZERO, 0);
        TBSS_TEST_ZERO += 1;
        assert_eq!(TBSS_TEST_ZERO, 1);
        assert_eq!(TDATA_TEST_NONZERO, usize::max_value());
        TDATA_TEST_NONZERO -= 1;
        assert_eq!(TDATA_TEST_NONZERO, usize::max_value() - 1);
    })
    .join()
    .unwrap();

    unsafe {
        assert_eq!(TBSS_TEST_ZERO, 0);
        TBSS_TEST_ZERO += 1;
        assert_eq!(TBSS_TEST_ZERO, 1);
        assert_eq!(TDATA_TEST_NONZERO, usize::max_value());
        TDATA_TEST_NONZERO -= 1;
        assert_eq!(TDATA_TEST_NONZERO, usize::max_value() - 1);
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;
    use test::Bencher;

    #[test]
    fn test_tls() {
        tls()
    }

    #[test]
    fn test_channel() {
        channel()
    }

    #[test]
    fn test_sleep_granularity() {
        sleep_granularity()
    }

    #[bench]
    fn bench_context_switch(b: &mut Bencher) {
        b.iter(|| context_switch())
    }

    // hang
    // #[bench]
    // fn bench_thread_leak(b: &mut Bencher) {
    //     b.iter(|| thread_spawn())
    // }
}
