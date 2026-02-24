//! RFLAGS bit positions and helpers.

pub const CF:  u64 = 1 << 0;   // Carry
pub const PF:  u64 = 1 << 2;   // Parity
pub const AF:  u64 = 1 << 4;   // Auxiliary carry
pub const ZF:  u64 = 1 << 6;   // Zero
pub const SF:  u64 = 1 << 7;   // Sign
pub const TF:  u64 = 1 << 8;   // Trap
pub const IF:  u64 = 1 << 9;   // Interrupt enable
pub const DF:  u64 = 1 << 10;  // Direction
pub const OF:  u64 = 1 << 11;  // Overflow
pub const IOPL:u64 = 3 << 12;  // I/O privilege level (mask)
pub const NT:  u64 = 1 << 14;  // Nested task
pub const RF:  u64 = 1 << 16;  // Resume
pub const VM:  u64 = 1 << 17;  // Virtual 8086 mode
pub const AC:  u64 = 1 << 18;  // Alignment check
pub const VIF: u64 = 1 << 19;  // Virtual interrupt flag
pub const VIP: u64 = 1 << 20;  // Virtual interrupt pending
pub const ID:  u64 = 1 << 21;  // CPUID available

/// Reserved bit 1 is always 1.
pub const RESERVED_1: u64 = 1 << 1;

/// Initial RFLAGS value: IF=1, reserved bit 1=1.
pub const RFLAGS_INIT: u64 = IF | RESERVED_1;

// ── Flag computation helpers ──────────────────────────────────────────────────

/// Compute parity flag from the lowest byte of `result`.
pub fn parity(result: u64) -> bool {
    (result as u8).count_ones() % 2 == 0
}

/// Set/clear individual flags in `rflags`.
pub fn set_flag(rflags: &mut u64, flag: u64, val: bool) {
    if val { *rflags |= flag; } else { *rflags &= !flag; }
}

pub fn get_flag(rflags: u64, flag: u64) -> bool { rflags & flag != 0 }

/// Update SF, ZF, PF from `result` with `width` bits (8/16/32/64).
pub fn update_szp(rflags: &mut u64, result: u64, width: u8) {
    let sign_bit = 1u64 << (width - 1);
    set_flag(rflags, SF, result & sign_bit != 0);
    let masked = result & mask_for(width);
    set_flag(rflags, ZF, masked == 0);
    set_flag(rflags, PF, parity(masked));
}

/// Mask for `width` bits.
pub fn mask_for(width: u8) -> u64 {
    match width {
        8  => 0xff,
        16 => 0xffff,
        32 => 0xffff_ffff,
        64 => u64::MAX,
        _  => panic!("invalid width {width}"),
    }
}

/// Compute CF and OF for addition: `a + b (+ carry_in)`.
pub fn add_flags(rflags: &mut u64, a: u64, b: u64, carry_in: u64, width: u8) -> u64 {
    let mask    = mask_for(width);
    let result  = a.wrapping_add(b).wrapping_add(carry_in);
    let sign    = 1u64 << (width - 1);
    let cf      = (a & mask).checked_add(b & mask).and_then(|v| v.checked_add(carry_in)).map_or(true, |v| v > mask);
    let of      = ((!(a ^ b)) & (a ^ result)) & sign != 0;
    set_flag(rflags, CF, cf);
    set_flag(rflags, OF, of);
    update_szp(rflags, result, width);
    set_flag(rflags, AF, (a ^ b ^ result) & 0x10 != 0);
    result & mask
}

/// Compute CF and OF for subtraction: `a - b (- borrow_in)`.
/// CF = 1 when unsigned borrow occurs (a < b + borrow_in).
pub fn sub_flags(rflags: &mut u64, a: u64, b: u64, borrow_in: u64, width: u8) -> u64 {
    let mask   = mask_for(width);
    let a_m    = a & mask;
    let b_m    = b & mask;
    let result = a_m.wrapping_sub(b_m).wrapping_sub(borrow_in) & mask;
    // CF: unsigned borrow (x86 CF=1 when a < b + borrow_in).
    let cf = (a_m as u128) < (b_m as u128) + (borrow_in as u128);
    // OF: signed overflow in subtraction.
    let sign = 1u64 << (width - 1);
    let of   = ((a_m ^ b_m) & (a_m ^ result)) & sign != 0;
    set_flag(rflags, CF, cf);
    set_flag(rflags, OF, of);
    update_szp(rflags, result, width);
    set_flag(rflags, AF, (a_m ^ b_m ^ result) & 0x10 != 0);
    result
}
