use core::array;
use core::cell::Cell;
use std::vec;
use std::vec::Vec;

use crate::keccak;
use crate::variant::test_variants::{Chunks327, OddChunks, OneBlockChunks};
use crate::*;

std::thread_local! {
    static MAX_PARALLELISM: Cell<usize> = const { Cell::new(usize::MAX) };
    static MAX_TIER: Cell<usize> = const { Cell::new(usize::MAX) };
}

/// The most states the current test wants processed at once.
pub(crate) fn max_parallelism() -> usize {
    MAX_PARALLELISM.get()
}

/// The best instruction set the current test wants used, on x86-64: 0 for SSE2, 1 for AVX2, 2 for AVX-512.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub(crate) fn max_tier() -> usize {
    MAX_TIER.get()
}

/// Every instruction set with every batch size, as (tier, states).
/// What the CPU doesn't have falls back to the best it has, and 8 states means as many as the tier can do.
const SETUPS: [(usize, usize); 7] = [(0, 1), (0, 8), (1, 2), (1, 8), (2, 2), (2, 4), (2, 8)];

fn set_up((tier, width): (usize, usize)) {
    MAX_TIER.set(tier);
    MAX_PARALLELISM.set(width);
}

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

    let deck = || TurboShake128FlightDeck::new(b"key").unwrap();
    assert!(panic_message(move || deck().squeeze(&mut [0])).contains("before squeezing"));
    assert!(panic_message(move || deck().xor(&mut [0])).contains("before squeezing"));
    let session = || TurboShake128Bo::<16>::new(b"key").unwrap();
    assert!(panic_message(move || session().squeeze(&mut [0])).contains("before squeezing"));
}

#[test]
fn keys_and_trailers() {
    assert_eq!(
        [TurboShake128FlightDeck::KEY_LEN, Shake256Bo::<16>::KEY_LEN],
        [16, 32]
    );
    assert!(TurboShake128FlightDeck::new(&[0; 160]).is_ok());
    assert_eq!(
        TurboShake128FlightDeck::new(&[0; 161]).unwrap_err(),
        InvalidKeyLength
    );
    assert!(TurboShake256Bo::<16>::new(&[0; 128]).is_ok());
    assert!(TurboShake256Bo::<16>::new(&[0; 129]).is_err());

    assert_eq!(Trailer::default(), Trailer::EMPTY);
    assert_eq!(Trailer::new(0), None);
    assert_eq!(Trailer::new(1), Some(Trailer::EMPTY));
    assert_eq!(Trailer::new(31).unwrap().get(), 31);
    assert_eq!(Trailer::new(32), None);
    assert_eq!(DuplexTrailer::new(63).unwrap().get(), 63);
    assert_eq!(DuplexTrailer::new(64), None);
    assert_eq!(Trailer::from_bits(&[]), Some(Trailer::EMPTY));
    assert_eq!(
        Trailer::from_bits(&[true, false, false, false]),
        Trailer::new(0b10001)
    );
    assert_eq!(Trailer::from_bits(&[false; 5]), None);
}

fn deck_test_vectors<V: Variant>(expected: [&str; 4]) {
    let key: [u8; 16] = array::from_fn(|i| i as u8);
    let alpha = V::CHUNK_LEN;

    for setup in SETUPS {
        set_up(setup);
        let mut deck = FlightDeck::<V>::new(&key).unwrap();
        // Four calls in a row. The last 32 bytes of each output are checked.
        let calls = [
            (0, 1, 32),
            (alpha + 1, 7, 32),
            (11 * alpha + alpha / 2 + 17, 31, 32),
            (1, 2, 50000),
        ];
        for (i, ((in_len, trailer, out_len), end)) in calls.into_iter().zip(expected).enumerate() {
            let mut out = vec![0; out_len];
            deck.duplex(
                &pattern(in_len, 1, 17 * i),
                Trailer::new(trailer).unwrap(),
                &mut out,
            );
            assert_eq!(out[out_len - 32..], hex(end), "call {i}, setup {setup:?}");
        }
    }
}

// Generated with XKCP, commit d20c8fc.
#[test]
fn deck_against_xkcp() {
    deck_test_vectors::<Shake128>([
        "46522d87bb182c09cb3894f631f0d2038ae9c519ee8a83d9889e9444d9cac055",
        "b8fdbf7c9ce6de5926f483d3727270e8da3e7c4cbe705d11b2aa04a227f531f0",
        "0e2866d9275fa42f13afa406b83dbf5217d3885a53eed1ec27f0fffc8cc38eea",
        "e30f7c5b3cb6c97665159f35d59238a3c1ae808ff381afb2edc77e6a10dc3bd7",
    ]);
    deck_test_vectors::<Shake256>([
        "48a3a3e770baa4b4ad1c8433a686033a66274d4b7557e58fefd889c65f6f13d5",
        "a240322bf03fa890d4b9804b574988bd1e224bd2b02e277068fa82ddcbb0ed67",
        "80646d3d6e1af65b3b3aefcc52af92c1ce607b429964d935da5149fe90f46bd6",
        "0de4155a80187d7967547300fe5033e2d2811fde27cfeaf0932e0076000f8b8d",
    ]);
    deck_test_vectors::<TurboShake128>([
        "7647c9011410b46aed34896b978d4cf7c6de2a2b02dde9cac3db2d9f0d2d4cd1",
        "42bf0b8604f465b3ed708904287b72af6d38a4b313ff7a43f2d6ebbf08a9ce56",
        "df4abd09ab62f58d3d417cd060c7b1125f12985ad7ff319042633e9685c89f59",
        "ad2ea7d74ee3216ceb8c1e7349aa7affe0a257219bbb8bee2aecc472eace57a1",
    ]);
    deck_test_vectors::<TurboShake256>([
        "3f28f4f4ed9df27113e56956de92c68fe0ca4d00c3ebc6201bb6e43079851b52",
        "eda592a2605bfc55d541b14849443c794a13c9d117b7d7da60942374ec8b0cb8",
        "7f5c22615c068bb10c36a2da08b85a07d64a1a2702fb0d1dd98548afba694d5b",
        "8661fa82d4652cfad8e26b7b5b2ecb464035b703b774f35b8bb1b3ba17d4833a",
    ]);
    // Chunks that don't end on a block boundary.
    deck_test_vectors::<Chunks327>([
        "7647c9011410b46aed34896b978d4cf7c6de2a2b02dde9cac3db2d9f0d2d4cd1",
        "38c74e9d5b7dffaaa5efb0509c559395cf6538994c61afd879c755d47b72ad2c",
        "81f25d44a7e6815d1fa656f37b3847ba687f5af3239a723e785e0c17635aa1df",
        "112e6271871e86acd00f79bde74e30701f6efcdd2b8f11bca27a102d071d50fb",
    ]);
}

/// FlightDeck as written in Algorithm 3 of the paper.
struct ReferenceFlightDeck<V: Variant> {
    d: OverwriteDuplex<V>,
    d_squeeze: OverwriteDuplex<V>,
    o: usize,
}

impl<V: Variant> ReferenceFlightDeck<V> {
    fn new(key: &[u8]) -> Self {
        let d = OverwriteDuplex::new(key).unwrap();
        Self {
            d_squeeze: d.clone(),
            d,
            o: 0,
        }
    }

    fn duplexing(&mut self, x: &[u8], e: Trailer, z: &mut [u8]) {
        let rho = V::BLOCK_LEN;
        let empty = DuplexTrailer::EMPTY;
        let mut chunks = x.chunks(V::CHUNK_LEN);

        let mut r = chunks.next().unwrap_or_default().to_vec();
        for mut y in chunks {
            let mut d_prime = self.d.clone_compact();
            while y.len() > rho {
                d_prime.duplex(&y[..rho], empty, &mut []);
                y = &y[rho..];
            }
            let mut cv = vec![0; V::CV_LEN];
            d_prime.duplex(y, DuplexTrailer::new(4).unwrap(), &mut cv);
            r.extend(cv);
        }
        let mut left = &r[..];
        while left.len() > rho {
            self.d.duplex(&left[..rho], empty, &mut []);
            left = &left[rho..];
        }
        // E||1
        let e = e.get();
        self.d.duplex(
            left,
            DuplexTrailer::new(e + (2 << e.ilog2())).unwrap(),
            &mut [],
        );
        self.o = 0;
        self.squeezing(z);
    }

    fn squeezing(&mut self, z: &mut [u8]) {
        let rho = V::BLOCK_LEN;
        let mut done = 0;
        if self.o <= rho {
            done = z.len().min(rho - self.o);
            self.d.squeeze(&mut z[..done]);
            self.o += done;
        }
        while done < z.len() {
            if self.o.is_multiple_of(rho) {
                let mut counter = vec![0; rho];
                counter[..8].copy_from_slice(&((self.o / rho) as u64).to_le_bytes());
                self.d_squeeze = self.d.clone_compact();
                self.d_squeeze
                    .duplex(&counter, DuplexTrailer::new(2).unwrap(), &mut []);
            }
            let n = (rho - self.o % rho).min(z.len() - done);
            self.d_squeeze.squeeze(&mut z[done..][..n]);
            self.o += n;
            done += n;
        }
    }
}

/// SplitMix64, to pick lengths and trailers.
struct Random(u64);

impl Random {
    fn up_to(&mut self, max: usize) -> usize {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^= z >> 31;
        (z % (max as u64 + 1)) as usize
    }
}

fn deck_against_reference<V: Variant>() {
    let alpha = V::CHUNK_LEN;
    let rho = V::BLOCK_LEN;

    let mut reference = ReferenceFlightDeck::<V>::new(b"key");
    let mut decks = SETUPS.map(|_| FlightDeck::<V>::new(b"key").unwrap());
    let input = pattern(18 * alpha + rho + 1, 5, 1);
    let mut expected = vec![0; 20 * rho];
    let mut out = vec![0; expected.len()];
    let mut random = Random(alpha as u64);

    // Lengths around every multiple of half a chunk: that's where the batching changes.
    for half_chunks in 0..37 {
        for extra in [0, 1, 2, rho + 1, rho + 2] {
            let x = &input[..(half_chunks * alpha / 2 + extra).saturating_sub(1)];
            let trailer = Trailer::new(1 + random.up_to(30) as u8).unwrap();
            let len = random.up_to(out.len());
            let second = random.up_to(len);
            let first = random.up_to(second);

            let expected = &mut expected[..len];
            reference.duplexing(x, trailer, expected);
            for (deck, setup) in decks.iter_mut().zip(SETUPS) {
                set_up(setup);
                // The same output in three pieces: two written over garbage, one XORed into zeros.
                let z = &mut out[..len];
                z[..second].fill(0xa5);
                z[second..].fill(0);
                deck.duplex(x, trailer, &mut z[..first]);
                deck.squeeze(&mut z[first..second]);
                deck.xor(&mut z[second..]);
                assert_eq!(
                    z,
                    expected,
                    "{} bytes in, {len} bytes out, setup {setup:?}",
                    x.len()
                );
            }
        }
    }
}

#[test]
fn deck_against_the_reference_algorithm() {
    deck_against_reference::<TurboShake128>();
    deck_against_reference::<OddChunks>();
    deck_against_reference::<OneBlockChunks>();
}

struct BoVectors {
    /// Ciphertext and tag of each message of a session.
    session: [&'static str; 4],
    /// End of the ciphertext of a long message, and its tag.
    long_ciphertext: &'static str,
    long_tag: &'static str,
}

fn bo_test_vectors<V: Variant>(expected: BoVectors) {
    let key: [u8; 32] = array::from_fn(|i| i as u8);

    for setup in SETUPS {
        set_up(setup);

        // Four messages, with and without associated data and plaintext.
        let mut sender = DeckBo::<V, 16>::new(&key[..16]).unwrap();
        let mut receiver = sender.clone();
        for (i, ((ad_len, m_len), c_and_tag)) in [(0, 0), (5, 0), (0, 5), (7, 40)]
            .into_iter()
            .zip(expected.session)
            .enumerate()
        {
            let ad = pattern(ad_len, 1, 17 * i);
            let m = pattern(m_len, 3, 29 * i);

            let mut buffer = m.clone();
            let tag = sender.encrypt_in_place(&ad, &mut buffer);
            assert_eq!([&buffer[..], &tag[..]].concat(), hex(c_and_tag));

            receiver.decrypt_in_place(&ad, &mut buffer, &tag).unwrap();
            assert_eq!(buffer, m);
        }

        // Many chunks of associated data and of plaintext.
        let ad = pattern(20000, 1, 0);
        let m = pattern(80000, 3, 0);
        let mut sender = DeckBo::<V, 32>::new(&key).unwrap();
        let mut receiver = sender.clone();
        let mut buffer = m.clone();
        let tag = sender.encrypt_in_place(&ad, &mut buffer);
        assert_eq!(buffer[buffer.len() - 32..], hex(expected.long_ciphertext));
        assert_eq!(tag[..], hex(expected.long_tag));

        receiver.decrypt_in_place(&ad, &mut buffer, &tag).unwrap();
        assert_eq!(buffer, m);
    }
}

// Generated with XKCP, commit d20c8fc.
#[test]
fn bo_against_xkcp() {
    bo_test_vectors::<TurboShake128>(BoVectors {
        session: [
            "1c106e7483215251a6d39d1b7ced5081",
            "a1ee10ab51029ad2520e746fa3616d10",
            "c0e75ee6dbd1815bace517f6e80e78c4fe8de69c68",
            "fd79fad9b021cf4e7d5e2f8a45a5fec28b5d267ff026b830e3636a05424870a0589dc31a036457f4b2ffa678aeb4742fcd8b280e257586cc",
        ],
        long_ciphertext: "448ad0859b25d898a569dbc54e9f10a7845a2085334be423dd62081236ef3477",
        long_tag: "bfea226043c96f981d2a87ec6b595fd7517fca51190b24c87aaa4b4f46285baf",
    });
    bo_test_vectors::<TurboShake256>(BoVectors {
        session: [
            "50a6969d91e4a3cf6cbab92862e5331d",
            "50ca4c773b1fae7dd184da8e1a57cb11",
            "aaa5df8bcbfdc6e371c38b184644023fe70204d650",
            "f045a1839d595957f5719040ee4ede0d6739e3661ff96bba0115410180fb8429c3b39f2085e9192d5b82af48bbc2ebc63f552116f9d440ff",
        ],
        long_ciphertext: "8f73baf8369dbd41a3b5d2d90952d136150794452602586aeb99e98c4af29c20",
        long_tag: "e531fa17ca00de8db462ddfe079be91e2e55d0b06ea72932f7ecffe19255c3aa",
    });
}

#[test]
fn bo_authentication_failure() {
    let m = b"a message";
    let ad = b"associated data";

    let mut sender = TurboShake128Bo::<16>::new(b"key").unwrap();
    let mut receiver = sender.clone();
    let mut c = *m;
    let tag = sender.encrypt_in_place(ad, &mut c);

    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    let mut buffer = c;
    assert_eq!(
        receiver.decrypt_in_place(ad, &mut buffer, &bad_tag),
        Err(AuthenticationError)
    );
    assert_eq!(buffer, [0; 9]);
    let mut buffer = c;
    buffer[0] ^= 1;
    assert!(receiver.decrypt_in_place(ad, &mut buffer, &tag).is_err());
    let mut buffer = c;
    assert!(
        receiver
            .decrypt_in_place(b"other data", &mut buffer, &tag)
            .is_err()
    );

    // The session didn't move: the message is still accepted, but only once.
    let mut buffer = c;
    receiver.decrypt_in_place(ad, &mut buffer, &tag).unwrap();
    assert_eq!(&buffer, m);
    let mut buffer = c;
    assert!(receiver.decrypt_in_place(ad, &mut buffer, &tag).is_err());

    // Without a message, only the comparison looks at the tag, so check every byte of it.
    let tag = sender.encrypt_in_place(ad, &mut []);
    for i in 0..tag.len() {
        for bit in [0x01, 0x80] {
            let mut bad_tag = tag;
            bad_tag[i] ^= bit;
            assert!(receiver.decrypt_in_place(ad, &mut [], &bad_tag).is_err());
        }
    }
    receiver.decrypt_in_place(ad, &mut [], &tag).unwrap();
}

#[test]
fn bo_absorb_and_squeeze() {
    let mut sender = TurboShake128Bo::<16>::new(b"key").unwrap();
    let mut receiver = sender.clone();

    // The squeezed bytes are the end of the tag a session with longer tags gives.
    let mut long_tags = TurboShake128Bo::<48>::new(b"key").unwrap();
    let long_tag = long_tags.encrypt_in_place(b"data", &mut []);
    sender.absorb(b"data");
    let mut squeezed = [0; 32];
    sender.squeeze(&mut squeezed[..5]);
    sender.squeeze(&mut squeezed[5..]);
    assert_eq!(squeezed, long_tag[16..]);

    // An absorb is an empty message, so the other side can check it.
    let tag = long_tag.first_chunk().unwrap();
    receiver.decrypt_in_place(b"data", &mut [], tag).unwrap();

    // Only the sender squeezed, and the next message still decrypts.
    // Both sides then squeeze the same bytes, and a message that's rejected doesn't change them.
    let mut c = *b"a message";
    let tag = sender.encrypt_in_place(b"", &mut c);
    receiver.decrypt_in_place(b"", &mut c, &tag).unwrap();
    let mut expected = [0; 400];
    sender.squeeze(&mut expected);
    let long_tag = long_tags.encrypt_in_place(b"", &mut b"a message".clone());
    assert_eq!(expected[..32], long_tag[16..]);

    let mut output = [0; 400];
    receiver.squeeze(&mut output[..170]);
    assert!(receiver.decrypt_in_place(b"", &mut c, &tag).is_err());
    receiver.squeeze(&mut output[170..]);
    assert_eq!(output, expected);
}

#[cfg(feature = "alloc")]
#[test]
fn bo_returning_vecs() {
    let mut sender = TurboShake256Bo::<32>::new(b"key").unwrap();
    let mut receiver = sender.clone();

    for m in [&b""[..], b"a message"] {
        let c = sender.encrypt(b"associated data", m);
        assert_eq!(c.len(), m.len() + 32);
        assert!(
            receiver
                .clone()
                .decrypt(b"associated data", &c[1..])
                .is_err()
        );
        assert_eq!(receiver.decrypt(b"associated data", &c).unwrap(), m);
    }
    // Too short to hold a tag.
    assert_eq!(receiver.decrypt(b"", &[0; 31]), Err(AuthenticationError));
}
