pub fn avx2() {
    let mut a: [u8; 32] = [0x41; 32];
    let mut b: [u8; 32] = [0x42; 32];
    unsafe {
        core::arch::asm!("
            vpxor ymm0, ymm0, ymm0
            vpcmpeqb ymm1, ymm1, ymm1

            mov eax, {SYS_YIELD}
            syscall

            vmovdqu [r12], ymm0
            vmovdqu [r13], ymm1
        ", in("r12") a.as_mut_ptr(), in("r13") b.as_mut_ptr(), out("ymm0") _, out("ymm1") _, SYS_YIELD = const syscall::SYS_YIELD);
    }
    assert_eq!(a, [0x00; 32]);
    assert_eq!(b, [0xff; 32]);
}

#[cfg(test)]
mod tests {
    extern crate test;
    use super::*;

    #[test]
    fn test_avx2() {
        avx2()
    }
}
