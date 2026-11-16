//! The FlightDeck and Deck-BO self-tests of XKCP, with their checksums.

use flightdeck::{
    DeckBo, FlightDeck, Shake128, Shake256, Trailer, TurboShake128, TurboShake256, Variant,
};

/// The pseudorandom generator of the XKCP tests.
fn arbitrary_material(buf: &mut [u8], seed: u32) {
    let mut s1 = seed;
    let mut s2 = buf.len() as u32;
    let mut mix = |s1: &mut u32| {
        *s1 = (s1.wrapping_mul(5).wrapping_add(s2).wrapping_add(1)).rotate_left(19);
        s2 = (s2 ^ *s1).rotate_left(14);
    };
    for _ in 0..6 {
        mix(&mut s1);
    }
    for (i, b) in buf.iter_mut().enumerate() {
        *b = s1 as u8;
        s1 ^= i as u32;
        mix(&mut s1);
    }
}

/// The checksum of the XKCP tests.
#[derive(Default)]
struct ArbitraryChecksum {
    s1: u32,
    s2: u32,
}

impl ArbitraryChecksum {
    fn mix(&mut self) {
        self.s1 = (self
            .s1
            .wrapping_mul(5)
            .wrapping_add(self.s2)
            .wrapping_add(1))
        .rotate_left(20);
        self.s2 = (self.s2 ^ self.s1).rotate_left(14);
    }

    fn absorb(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.s1 ^= u32::from(b);
            self.mix();
        }
    }

    fn squeeze(mut self) -> u32 {
        self.s1 ^= 0x100;
        for _ in 0..6 {
            self.mix();
        }
        self.s1
    }
}

fn trailer(n: usize) -> Trailer {
    Trailer::new((n % 31 + 1) as u8).unwrap()
}

/// Port of performTestFlightDeck().
fn flight_deck_checksum<V: Variant>() -> u32 {
    let rho = FlightDeck::<V>::KEY_LEN_MAX;
    let key_len = FlightDeck::<V>::KEY_LEN;

    let mut seed = 0xa894552e;
    let mut checksum = ArbitraryChecksum::default();
    let mut key = vec![0; rho];
    let mut input = vec![0; rho];
    let mut out = vec![0; rho];

    arbitrary_material(&mut key, seed);
    seed += 1;

    // Short inputs, squeezed then XORed.
    let mut deck = FlightDeck::<V>::new(&key[..key_len]).unwrap();
    for len in 0..=rho {
        arbitrary_material(&mut input[..len], seed);
        seed += 2;
        deck.duplex(&input[..len], trailer(len), &mut out);
        checksum.absorb(&out);
    }
    for len in 0..=rho {
        arbitrary_material(&mut input[..len], seed);
        arbitrary_material(&mut out, seed + 2);
        seed += 3;
        deck.duplex(&input[..len], trailer(len + 12), &mut []);
        deck.xor(&mut out);
        checksum.absorb(&out);
    }

    // A block of output in up to three pieces, the last one from a clone.
    arbitrary_material(&mut input, seed);
    seed += 1;
    let fresh = FlightDeck::<V>::new(&key[..key_len]).unwrap();
    let mut expected = vec![0; rho];
    fresh.clone().duplex(&input, Trailer::EMPTY, &mut expected);
    checksum.absorb(&expected);
    fresh
        .clone_compact()
        .duplex(&input, Trailer::EMPTY, &mut out);
    assert_eq!(out, expected);
    for len1 in 0..rho {
        for len2 in 0..=rho - len1 {
            let (first, rest) = out.split_at_mut(len1);
            let (second, third) = rest.split_at_mut(len2);
            let mut deck = fresh.clone();
            deck.duplex(&input, Trailer::EMPTY, first);
            deck.squeeze(second);
            deck.clone().squeeze(third);
            assert_eq!(out, expected);
        }
    }

    // Every key length.
    for len in 0..=rho {
        arbitrary_material(&mut key[..len], seed);
        seed += 1;
        let mut deck = FlightDeck::<V>::new(&key[..len]).unwrap();
        deck.duplex(b"", Trailer::EMPTY, &mut out);
        checksum.absorb(&out);
    }

    // Long inputs and long outputs.
    arbitrary_material(&mut key, seed);
    seed += 1;
    let mut deck = FlightDeck::<V>::new(&key[..key_len]).unwrap();
    let mut long_in = vec![0; 19 * 8192 + 1];
    let mut long_out = vec![0; 4000];

    let mut lengths = Vec::new();
    let mut len = 0;
    while len <= 155000 {
        lengths.push((len, 8));
        len += match len {
            0..200 => 1,
            200..1000 => 17,
            1000..10000 => 97,
            _ => 1333,
        };
    }
    len = 0;
    while len <= 4000 {
        lengths.push((0, len));
        len += match len {
            0..200 => 1,
            200..1000 => 19,
            _ => 87,
        };
    }
    for i in 1..20 {
        for j in 0..3 {
            lengths.push((i * 8192 + j - 1, i * rho + j - 1));
        }
    }
    for (in_len, out_len) in lengths {
        let x = &mut long_in[..in_len];
        let z = &mut long_out[..out_len];
        arbitrary_material(x, seed);
        deck.duplex(x, trailer(in_len + out_len + 1), z);
        checksum.absorb(z);
        arbitrary_material(z, seed + 1);
        seed += 2;
        deck.duplex(x, trailer(in_len + out_len + 2), &mut []);
        deck.xor(z);
        checksum.absorb(z);
    }
    checksum.squeeze()
}

#[test]
fn flight_deck() {
    assert_eq!(flight_deck_checksum::<Shake128>(), 0x5fffde4d);
    assert_eq!(flight_deck_checksum::<Shake256>(), 0x87f80d7c);
    assert_eq!(flight_deck_checksum::<TurboShake128>(), 0xb458b993);
    assert_eq!(flight_deck_checksum::<TurboShake256>(), 0x7812c1cf);
}

/// Port of testvectorsDeckBO().
fn deck_bo_checksum<V: Variant>() -> u32 {
    let key: [u8; 16] = std::array::from_fn(|i| i as u8);
    let mut ad = [0; 600];
    let mut m = [0; 600];
    arbitrary_material(&mut ad, 0x3df6bbf4);
    arbitrary_material(&mut m, 0x3df6bbf5);

    let mut checksum = ArbitraryChecksum::default();
    for ad_len in (0..ad.len()).step_by(4) {
        for m_len in (0..m.len()).step_by(4) {
            let mut sender = DeckBo::<V, 16>::new(&key).unwrap();
            let mut receiver = sender.clone();
            let mut buffer = m;
            let buffer = &mut buffer[..m_len];
            let tag = sender.encrypt_in_place(&ad[..ad_len], buffer);
            checksum.absorb(buffer);
            checksum.absorb(&tag);

            receiver
                .decrypt_in_place(&ad[..ad_len], buffer, &tag)
                .unwrap();
            assert_eq!(buffer, &m[..m_len]);
        }
    }
    checksum.squeeze()
}

#[test]
fn deck_bo() {
    assert_eq!(deck_bo_checksum::<Shake128>(), 0xc70e192f);
    assert_eq!(deck_bo_checksum::<Shake256>(), 0x857e62e0);
    assert_eq!(deck_bo_checksum::<TurboShake128>(), 0x709d96f8);
    assert_eq!(deck_bo_checksum::<TurboShake256>(), 0x3610bd4a);
}
