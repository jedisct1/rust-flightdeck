//! Throughput of the deck ciphers and of authenticated encryption, for a few message sizes.
//!
//! Run it with `cargo bench`, or `cargo bench -- TurboSHAKE128` to keep only some rows.
//! For WebAssembly, with Wasmer:
//!
//! ```sh
//! export CARGO_TARGET_WASM32_WASIP1_RUNNER="wasmer run --"
//! RUSTFLAGS="-C target-feature=+simd128" cargo bench --target wasm32-wasip1
//! ```

use benchmark_simple::{Bench, Options, black_box};
use flightdeck::{
    DeckBo, FlightDeck, Shake128, Shake256, Trailer, TurboShake128, TurboShake256, Variant,
};

const SIZES: [usize; 5] = [64, 1024, 8192, 65536, 1 << 20];

/// Print a row of the table: the throughput of `f` for each size, in MiB/s.
///
/// With an argument on the command line, only the rows whose name contains it are printed.
fn row(name: &str, bench: &Bench, mut f: impl FnMut(&mut [u8])) {
    let filter = std::env::args().skip(1).find(|arg| !arg.starts_with('-'));
    if filter.is_some_and(|filter| !name.contains(&filter)) {
        return;
    }
    let mut data = vec![0x5a; SIZES[SIZES.len() - 1]];
    print!("{name:<32}");
    for size in SIZES {
        let options = Options {
            iterations: (64 << 20) / size as u64,
            warmup_iterations: (4 << 20) / size as u64,
            min_samples: 5,
            max_samples: 10,
            max_rsd: 1.0,
            ..Default::default()
        };
        let throughput = bench
            .run(&options, || f(black_box(&mut data[..size])))
            .throughput_bytes(size as u128);
        print!("{:>10.0}", throughput.as_mib());
    }
    println!();
}

fn deck<V: Variant>(name: &str, bench: &Bench) {
    let mut tag = [0; 32];
    let mut deck = FlightDeck::<V>::new(&[0x42; 16]).unwrap();
    row(&format!("{name}-FlightDeck input"), bench, |data| {
        deck.duplex(data, Trailer::EMPTY, &mut tag);
    });
    row(&format!("{name}-FlightDeck output"), bench, |data| {
        deck.duplex(&tag, Trailer::EMPTY, &mut []);
        deck.xor(data);
    });
}

fn bo<V: Variant>(name: &str, bench: &Bench) {
    let mut session = DeckBo::<V, 16>::new(&[0x42; 16]).unwrap();
    row(&format!("{name}-BO encrypt"), bench, |data| {
        black_box(session.encrypt_in_place(b"", data));
    });
}

fn main() {
    let bench = Bench::new();

    print!("{:<32}", "MiB/s");
    for size in SIZES {
        print!("{size:>10}");
    }
    println!();

    deck::<TurboShake128>("TurboSHAKE128", &bench);
    deck::<TurboShake256>("TurboSHAKE256", &bench);
    deck::<Shake128>("SHAKE128", &bench);
    deck::<Shake256>("SHAKE256", &bench);
    bo::<TurboShake128>("TurboSHAKE128", &bench);
    bo::<TurboShake256>("TurboSHAKE256", &bench);
    bo::<Shake128>("SHAKE128", &bench);
    bo::<Shake256>("SHAKE256", &bench);
}
