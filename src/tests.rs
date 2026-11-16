use core::array;
use std::vec;
use std::vec::Vec;

use crate::keccak;
use crate::*;

/// The inputs of the test vectors.
fn pattern(len: usize, multiplier: usize, offset: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((multiplier * i + offset) % 251) as u8)
        .collect()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// A sponge function without its padding: `message` is made of whole blocks of `rate` bytes.
fn sponge(rate: usize, rounds: usize, message: &[u8]) -> [u8; 200] {
    let mut state = [0; 200];
    for block in message.chunks_exact(rate) {
        for (s, b) in state.iter_mut().zip(block) {
            *s ^= b;
        }
        let mut lanes: [u64; 25] = array::from_fn(|i| u64::from_le_bytes(state.as_chunks().0[i]));
        keccak::permute(&mut lanes, rounds);
        for (bytes, lane) in state.as_chunks_mut().0.iter_mut().zip(lanes) {
            *bytes = lane.to_le_bytes();
        }
    }
    state
}

fn duplex_against_sponge<V: Variant>() {
    let rho = V::BLOCK_LEN;
    // Block length, trailer, and that trailer once the duplex has appended its bit (1 for a full block).
    // The first call is the one that absorbs the key.
    let calls = [
        (5, 0b1, 0b10),
        (0, 0b1, 0b10),
        (rho, 0b111111, 0b1111111),
        (1, 0b10, 0b100),
        (rho - 1, 0b11111, 0b101111),
        (rho, 0b1, 0b11),
    ];

    // What the sponge has to absorb to return the same thing as the duplex.
    let mut message = Vec::new();
    let mut expected = vec![0; rho];
    let mut duplex = None;

    for (i, (len, trailer, sponge_trailer)) in calls.into_iter().enumerate() {
        let input = pattern(len, 3, i);
        let mut block = input.clone();
        if len < rho {
            block.push(0x01);
            block.resize(rho, 0);
        }
        // Overwriting the state with a block is like XORing in the block and the previous output.
        message.extend(block.iter().zip(&expected).map(|(b, z)| b ^ z));
        message.extend([sponge_trailer, 0, 0, 0, 0, 0, 0, V::PADDING]);
        expected = sponge(rho + 8, V::ROUNDS, &message)[..rho].to_vec();

        let Some(duplex) = &mut duplex else {
            duplex = Some(OverwriteDuplex::<V>::new(&input).unwrap());
            continue;
        };
        let trailer = DuplexTrailer::new(trailer).unwrap();
        let mut out = vec![0; rho];
        duplex.clone_compact().duplex(&input, trailer, &mut out);
        assert_eq!(out, expected);

        // The same output in three pieces.
        out.fill(0);
        let (first, rest) = out.split_at_mut(10);
        let (second, third) = rest.split_at_mut(43);
        duplex.duplex(&input, trailer, first);
        duplex.squeeze(second);
        duplex.xor(third);
        assert_eq!(out, expected);
    }
}

#[test]
fn duplex_against_shake_and_turboshake() {
    // SHAKE128 and TurboSHAKE128 of the empty string, to know that sponge() can be trusted.
    let mut block = [0; 168];
    block[0] = 0x1f;
    block[167] = 0x80;
    assert_eq!(
        sponge(168, 24, &block)[..32],
        hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
    );
    assert_eq!(
        sponge(168, 12, &block)[..32],
        hex("1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c")
    );

    duplex_against_sponge::<Shake128>();
    duplex_against_sponge::<Shake256>();
    duplex_against_sponge::<TurboShake128>();
    duplex_against_sponge::<TurboShake256>();
}

/// The message of the panic that `f` ends with.
#[cfg(panic = "unwind")]
fn panic_message(f: impl FnOnce() + std::panic::UnwindSafe) -> std::string::String {
    let panic = std::panic::catch_unwind(f).expect_err("it should have panicked");
    match panic.downcast::<std::string::String>() {
        Ok(message) => *message,
        Err(panic) => (*panic.downcast::<&str>().unwrap()).into(),
    }
}

#[cfg(panic = "unwind")]
#[test]
fn misuse_panics() {
    let new = || TurboShake256Duplex::new(b"key").unwrap();
    let used = move || {
        let mut duplex = new();
        duplex.duplex(b"block", DuplexTrailer::EMPTY, &mut [0; 100]);
        duplex
    };

    // Nothing to squeeze from a new duplex or from a compact clone, and no more than a block otherwise.
    let no_output = "per call to duplex()";
    assert!(panic_message(move || new().squeeze(&mut [0])).contains(no_output));
    assert!(panic_message(move || used().clone_compact().squeeze(&mut [0])).contains(no_output));
    assert!(panic_message(move || used().squeeze(&mut [0; 29])).contains(no_output));

    // These are caught before the state changes.
    let too_long = "at most 128 bytes long";
    let empty = DuplexTrailer::EMPTY;
    assert!(panic_message(move || new().duplex(&[0; 129], empty, &mut [])).contains(too_long));
    assert!(panic_message(move || new().duplex(b"", empty, &mut [0; 129])).contains(too_long));
}
