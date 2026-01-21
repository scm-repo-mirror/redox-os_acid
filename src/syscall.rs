pub fn scheme_call() {
    // getppid is not currently cached, but TODO this is perhaps not relibc-future-proof for
    // benchmarking

    // Same number with sys_call of arch/syscall.rs
    const N: usize = 1 << 24;

    for i in 0..N {
        assert_ne!(unsafe { libc::getppid() }, -1);
    }
}

fn context_switch() {
    let switch_thread = thread::spawn(|| -> usize {
        let mut j = 0;
        while j < 500 {
            thread::yield_now();
            j += 1;
        }
        j
    });

    let mut i = 0;
    while i < 500 {
        thread::yield_now();
        i += 1;
    }

    let j = switch_thread.join().unwrap();
}

fn thread_spawn() {
    // Same loop count with context_switch
    for i in 1..100 {
        let mut thread_list = vec![];
        for j in 1..5 {
            thread_list.push(std::thread::spawn(move || outer_runner(j)));
        }
        while thread_list.iter().any(|t| !t.is_finished()) {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[bench]
    fn bench_scheme_call() {
        scheme_call()
    }

    #[bench]
    fn bench_context_switch() {
        context_switch()
    }

    #[bench]
    fn bench_thread_leak() {
        thread_spawn()
    }
}
