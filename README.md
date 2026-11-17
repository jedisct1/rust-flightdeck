# FlightDeck for Rust

A Rust implementation of FlightDeck and Deck-BO for encrypting and authenticating data.

It's a port of the [Zig implementation](https://github.com/jedisct1/flightdeck-deckbo), with the same three layers and the same results.

It works with and without `std`, doesn't allocate unless you ask for it, and has only one small dependency (`cpufeatures`) to find out what the CPU can do.

## What's in there

- Duplex cipher: `Shake128Duplex`, `Shake256Duplex`, `TurboShake128Duplex`, `TurboShake256Duplex`.
- Deck cipher: `Shake128FlightDeck`, `Shake256FlightDeck`, `TurboShake128FlightDeck`, `TurboShake256FlightDeck`.
- Authenticated encryption: `Shake128Bo<TAG_LEN>`, `Shake256Bo<TAG_LEN>`, `TurboShake128Bo<TAG_LEN>`, `TurboShake256Bo<TAG_LEN>`.

Not sure which layer you need? Here's what each one does:

- Authenticated encryption is what you want to protect messages.
  You give it a key and a message, and it gives you back a ciphertext nobody can read, plus a tag that proves nobody tampered with it.
  If you just want to encrypt things, pick this one and ignore the rest.
- A deck cipher is the building block underneath.
  It mixes a key with any data you feed it, and gives you back as many random-looking bytes as you ask for.
  That's handy to authenticate data without encrypting it, to derive keys, or to build your own protocol.
- A duplex cipher does the same thing as a deck cipher, but only on small blocks, one at a time.
  The deck cipher is built with it, and unless you're building a mode of your own, you won't need it directly.

These names are aliases of three generic types: `OverwriteDuplex<V>`, `FlightDeck<V>` and `DeckBo<V, TAG_LEN>`, where `V` is one of `Shake128`, `Shake256`, `TurboShake128` and `TurboShake256`.

And SHAKE or TurboSHAKE?
The TurboSHAKE instances use 12 rounds of Keccak-p[1600] and are about twice as fast as the SHAKE ones, which use 24.
The 128 and 256 in the names are the security levels, in bits.

## Installing

```toml
[dependencies]
flightdeck = { git = "https://github.com/jedisct1/rust-flightdeck" }
```

There are two features:

- `std` is on by default. For now, all it does is turn `alloc` on.
- `alloc` adds the functions that return a `Vec`.

For a `no_std` build, turn the default features off:

```toml
flightdeck = { git = "https://github.com/jedisct1/rust-flightdeck", default-features = false }
```

On x86-64, SSE2, AVX2 or AVX-512 is picked when your program runs, and AArch64 uses NEON, so there's nothing to set up.

WebAssembly is the one target where you have to ask, because a module can't check what its runtime supports.
Build with `simd128` and long messages go through about 1.7 times as fast:

```sh
RUSTFLAGS="-C target-feature=+simd128" cargo build --release --target wasm32-wasip1
```

## Usage

Authenticated encryption works on sessions: the two sides share a key, and messages are decrypted in the order they were encrypted.

```rust
use flightdeck::TurboShake128Bo;

// 16 is the length of the tags, in bytes.
let mut sender = TurboShake128Bo::<16>::new(&key)?;
let mut receiver = TurboShake128Bo::<16>::new(&key)?;

// The ciphertext, followed by the tag.
let ciphertext = sender.encrypt(associated_data, message);
let decrypted = receiver.decrypt(associated_data, &ciphertext)?;
```

Without `alloc`, or to avoid copies, do it in place:

```rust
let tag = sender.encrypt_in_place(associated_data, &mut buffer);
receiver.decrypt_in_place(associated_data, &mut buffer, &tag)?;
```

Every message is authenticated along with all the messages that came before it in the session.
If something doesn't match, you get an error, the buffer is zeroed, and the session stays where it was.

There's no nonce. So if you encrypt the same message twice, at the same point of two sessions with the same key, you get the same ciphertext.

Besides the length of the message, that's all it reveals, but if it matters to you, put a nonce or a counter in the associated data.

The tag length is a parameter, in bytes.

A tag of twice the security level, so 32 bytes for the 128-bit instances, also commits to the key, the associated data and the plaintext at that security level.

Keys are normally `KEY_LEN` random bytes: 16 for the 128-bit instances and 32 for the 256-bit ones.

That said, any byte string of at most `KEY_LEN_MAX` bytes is accepted, which is 160 and 128 bytes respectively.
Longer than that, and `new()` returns an error.

A deck cipher takes strings of any length, and gives you back as many bytes as you want after each of them.
Those bytes depend on the key and on everything it was given so far.

```rust
use flightdeck::{Trailer, TurboShake128FlightDeck};

let mut deck = TurboShake128FlightDeck::new(&key)?;

// Absorb a string, get 32 bytes that depend on the key and on that string.
let mut mac = [0; 32];
deck.duplex(message, Trailer::EMPTY, &mut mac);

// Get more output from the same call.
let mut more = [0; 1000];
deck.squeeze(&mut more);

// Absorb another string. The output now depends on both strings.
// It can also be XORed into a buffer, to use it as a keystream.
deck.duplex(nonce, Trailer::EMPTY, &mut []);
deck.xor(&mut buffer);
```

That second argument of `duplex()` is a trailer: up to four bits you can use for domain separation.
Calls with different trailers give unrelated outputs, even on the same input.

`Trailer::from_bits(&[true, false])` makes one from its bits.
`Trailer::new(0b101)` makes the same one from its encoding: the bits, least significant first, followed by a final 1.
Both return `None` when there are too many bits.

Need a clone? `clone()` does it.
There's also `clone_compact()`, which gives you a clone that can only be used to absorb the next string.

One thing to remember: call `duplex()` before `squeeze()` or `xor()`.
There's nothing to squeeze before that, and they panic.

## Sessions

A session is a value like any other.
`new()` starts it, everything you encrypt, decrypt or absorb moves it forward, and you keep it around for as long as the conversation lasts, one on each side.

Encrypting a message and decrypting it leave a session in the same state.
So a single session can carry both directions, as long as the two sides take turns:

```rust
let mut alice = TurboShake128Bo::<16>::new(&key)?;
let mut bob = TurboShake128Bo::<16>::new(&key)?;

let ciphertext = alice.encrypt(b"", b"ping");
assert_eq!(bob.decrypt(b"", &ciphertext)?, b"ping");

let ciphertext = bob.encrypt(b"", b"pong");
assert_eq!(alice.decrypt(b"", &ciphertext)?, b"pong");
```

If both sides can send whenever they want, their messages can cross and the two sessions stop matching.
In that case, use two sessions, one for each direction, each with its own key. There's an example below.

`absorb()` mixes something into a session without sending a ciphertext: a session identifier, a nonce, the transcript of a handshake.
Both sides have to absorb the same thing at the same point.

`squeeze()` gives you bytes that depend on the key and on everything that happened in the session so far.
Both sides get the same ones, so that's how you make new keys out of a session.

```rust
alice.absorb(b"session 1234");
bob.absorb(b"session 1234");

let mut alice_key = [0; 32];
let mut bob_key = [0; 32];
alice.squeeze(&mut alice_key);
bob.squeeze(&mut bob_key);
assert_eq!(alice_key, bob_key);
```

All of this happens on the same state, in any order you like: encrypt, decrypt, absorb, squeeze.
The only rule is that the two sides go through the same messages and the same `absorb()` calls, in the same order.

Squeezing is not part of that, because it doesn't move the session: what comes next is the same whether you squeezed or not.
Squeeze again and you get the bytes that follow, not the same ones, until the next message or `absorb()`.
There has to be something in the session first: `squeeze()` panics on a brand new one.

An `absorb()` is just a message with an empty buffer, whose tag is thrown away.
If you'd rather have the other side check what it absorbed, send that tag instead:

```rust
let tag = alice.encrypt_in_place(b"session 1234", &mut []);
bob.decrypt_in_place(b"session 1234", &mut [], &tag)?;
```

What you squeeze comes after the tag of the last message, and never includes it.
So tags can travel in the clear and squeezed bytes can stay secret.

A few more things to know:

- A message that doesn't authenticate doesn't move the session.
  So a forged or damaged one does no harm: the real one still decrypts after it.
- A message that gets lost or comes out of order is another story: what was sent after it doesn't decrypt until it shows up.
  So sessions need a transport that delivers everything, in order.
- `clone()` copies a session, to save it or to try something on the side.
- Messages and `absorb()` are Deck-BO as the paper specifies it.
  `squeeze()` is an addition, so don't expect it from other implementations.

Back to the two directions that don't take turns.
Squeeze two keys from a session both sides share, and start one session for each direction.
Here's the client. The server does the same thing with the two keys swapped:

```rust
let mut keys = [0; 32];
handshake.squeeze(&mut keys);

let (client_to_server, server_to_client) = keys.split_at(16);
let mut sending = TurboShake128Bo::<16>::new(client_to_server)?;
let mut receiving = TurboShake128Bo::<16>::new(server_to_client)?;
```

## Hashing

A deck cipher doesn't need a secret key.
With an empty key, it's a hash function:

```rust
use flightdeck::{Trailer, TurboShake128FlightDeck};

let mut hasher = TurboShake128FlightDeck::new(b"")?;

let mut digest = [0; 32];
hasher.duplex(message, Trailer::EMPTY, &mut digest);

// A longer digest? Keep squeezing.
let mut more = [0; 32];
hasher.squeeze(&mut more);
```

Each call to `duplex()` adds a string, and the digest covers all of them, in order.
There's no way to mix up `"ab"` then `"c"` with `"a"` then `"bc"`, so you can hash a list of fields without length prefixes.

Ask for at least 32 bytes with the 128-bit instances, and 64 bytes with the 256-bit ones.
Finding two inputs with the same digest is then as hard as it is with SHAKE or TurboSHAKE: both papers prove it, even when the key is public.

A public string works as a key too.
Using the name of your application, for instance, keeps its digests apart from everybody else's.

Before you use it that way, know that:

- It's not a standard hash function. The digests don't match TurboSHAKE, KangarooTwelve or anything else, so use those if other software has to compute them.
- The FlightDeck paper mentions hashing without a key as future work.
  If that gets specified some day, the digests may not be the same as the ones you get here.
- Only collisions are covered by a proof.
- Authenticated encryption needs a secret key. Without one, anybody can decrypt.

## FlightDeck is fast!

Here's `TurboShake128FlightDeck` with an empty key next to [BLAKE3](https://github.com/BLAKE3-team/BLAKE3), each on a single thread, used in two ways:

- as a hash function: a 32-byte digest of an input of the given size;
- as a XOF: an output of the given size, from a 32-byte input.

The numbers are MiB/s, and every call starts from scratch.

### Apple M5 Max

| MiB/s            | 64 B | 1 KiB | 8 KiB | 64 KiB | 1 MiB | 16 MiB |
| ---------------- | ---: | ----: | ----: | -----: | ----: | -----: |
| FlightDeck, hash |  725 |  1942 |  3614 |   4571 |  4943 |   4950 |
| BLAKE3, hash     | 1321 |  1383 |  2502 |   2539 |  2540 |   2536 |
| FlightDeck, XOF  |  734 |  3353 |  4851 |   5174 |  5218 |   5224 |
| BLAKE3, XOF      | 1178 |  1466 |  1490 |   1494 |  1492 |   1492 |

Past a few hundred bytes, FlightDeck hashes up to twice as fast as BLAKE3, and makes output up to 3.5 times as fast.

### AMD Ryzen 7 7700, with AVX-512

| MiB/s            | 64 B | 1 KiB | 8 KiB | 64 KiB | 1 MiB | 16 MiB |
| ---------------- | ---: | ----: | ----: | -----: | ----: | -----: |
| FlightDeck, hash |  504 |  1431 |  2308 |   5855 |  6274 |   6243 |
| BLAKE3, hash     | 1051 |   936 |  4976 |   6325 |  6358 |   6305 |
| FlightDeck, XOF  |  494 |  2257 |  4986 |   6084 |  6187 |   6173 |
| BLAKE3, XOF      |  796 |  5606 |  6675 |   6745 |  6726 |   6720 |

### AMD Ryzen 7 7700, with AVX2 only

| MiB/s            | 64 B | 1 KiB | 8 KiB | 64 KiB | 1 MiB | 16 MiB |
| ---------------- | ---: | ----: | ----: | -----: | ----: | -----: |
| FlightDeck, hash |  357 |   924 |  1145 |   2879 |  3271 |   3273 |
| BLAKE3, hash     |  969 |   896 |  4137 |   4383 |  4379 |   4336 |
| FlightDeck, XOF  |  363 |  1254 |  2845 |   3091 |  3085 |   3071 |
| BLAKE3, XOF      |  708 |   993 |  1020 |   1020 |  1019 |   1018 |

### WebAssembly

Same M5 Max, with [Wasmer](https://wasmer.io), and `simd128` turned on for both.

With the LLVM backend:

| MiB/s            | 64 B | 1 KiB | 8 KiB | 64 KiB | 1 MiB | 16 MiB |
| ---------------- | ---: | ----: | ----: | -----: | ----: | -----: |
| FlightDeck, hash |  650 |  1794 |  1000 |   1312 |  1280 |   1279 |
| BLAKE3, hash     |  621 |   377 |  1221 |   1274 |  1281 |   1277 |
| FlightDeck, XOF  |  648 |  1182 |  1276 |   1279 |  1282 |   1272 |
| BLAKE3, XOF      |  349 |   618 |   631 |    638 |   639 |    638 |

With the Cranelift backend:

| MiB/s            | 64 B | 1 KiB | 8 KiB | 64 KiB | 1 MiB | 16 MiB |
| ---------------- | ---: | ----: | ----: | -----: | ----: | -----: |
| FlightDeck, hash |  594 |  1683 |  1545 |   2020 |  2003 |   2011 |
| BLAKE3, hash     | 1038 |   708 |  2294 |   2349 |  2313 |   2352 |
| FlightDeck, XOF  |  588 |  1714 |  2040 |   2079 |  2068 |   2085 |
| BLAKE3, XOF      |  618 |  1070 |  1101 |   1103 |  1090 |   1109 |

WebAssembly vectors are 128 bits wide and can't rotate, so they don't do much for Keccak.

Hashing long inputs is a tie with LLVM, and BLAKE3 is 15% faster with Cranelift.

FlightDeck makes output twice as fast either way.

And yes, on this machine the LLVM backend is the slower one, for both.

## Compared with XKCP

[XKCP](https://github.com/XKCP/XKCP), the code package of the Keccak team, has FlightDeck and Deck-BO too.

### Apple M5 Max

XKCP's `aarch64` target, with NEON code for two and four states.

| MiB/s         | 64 B | 1 KiB | 8 KiB | 64 KiB | 1 MiB | 16 MiB |
| ------------- | ---: | ----: | ----: | -----: | ----: | -----: |
| Rust, hash    |  730 |  1922 |  3524 |   4450 |  4785 |   4794 |
| XKCP, hash    |  282 |  1698 |  2376 |   2342 |  2293 |   2254 |
| Rust, XOF     |  729 |  3337 |  4736 |   5032 |  5039 |   5047 |
| XKCP, XOF     |  284 |  1192 |  1982 |   2115 |  2138 |   2135 |
| Rust, Deck-BO |  386 |  1233 |  1996 |   2344 |  2412 |   2410 |
| XKCP, Deck-BO |  210 |   764 |  1075 |   1079 |  1070 |   1066 |

This crate is 1.5 to 2.8 times as fast, except for hashing 1 KiB, where it's 13% ahead.

### AMD Ryzen 7 7700, with AVX-512

XKCP's `x86-64` target, which picks its AVX-512 code on this CPU.

| MiB/s         | 64 B | 1 KiB | 8 KiB | 64 KiB | 1 MiB | 16 MiB |
| ------------- | ---: | ----: | ----: | -----: | ----: | -----: |
| Rust, hash    |  492 |  1425 |  2310 |   5838 |  6247 |   6247 |
| XKCP, hash    |  117 |   650 |   862 |   2311 |  5134 |   5534 |
| Rust, XOF     |  504 |  2328 |  5050 |   6105 |  6180 |   6187 |
| XKCP, XOF     |  118 |   744 |  3499 |   5498 |  5775 |   5813 |
| Rust, Deck-BO |  271 |   887 |  1566 |   2933 |  3063 |   3066 |
| XKCP, Deck-BO |   87 |   388 |   710 |   1630 |  2687 |   2592 |

From 1 MiB on, this crate is 6 to 22% faster.

### WebAssembly

With the Cranelift backend:

| MiB/s         | 64 B | 1 KiB | 8 KiB | 64 KiB | 1 MiB | 16 MiB |
| ------------- | ---: | ----: | ----: | -----: | ----: | -----: |
| Rust, hash    |  581 |  1652 |  1507 |   1974 |  1983 |   1982 |
| XKCP, hash    |  300 |  1518 |  1943 |   2053 |  2058 |   2045 |
| Rust, XOF     |  590 |  1678 |  2005 |   2052 |  2059 |   2052 |
| XKCP, XOF     |  301 |  1100 |  1315 |   1351 |  1351 |   1344 |
| Rust, Deck-BO |  316 |   844 |   856 |    999 |  1005 |   1002 |
| XKCP, Deck-BO |  279 |   732 |   807 |    822 |   821 |    818 |

With Cranelift, XKCP hashes long inputs 3 to 4% faster, while this crate makes long outputs 1.5 times as fast, and encrypts long messages 1.2 times as fast.

## Running the tests

```sh
cargo test     # run the tests
cargo bench    # measure the throughput
```

To run them for WebAssembly, with [Wasmer](https://wasmer.io):

```sh
export CARGO_TARGET_WASM32_WASIP1_RUNNER="wasmer run --"
export RUSTFLAGS="-C target-feature=+simd128"
cargo test --target wasm32-wasip1
cargo bench --target wasm32-wasip1
```

## Papers

FlightDeck comes from ["Parallelizable modes for duplex-based authenticated encryption"](https://eprint.iacr.org/2026/2801) by Joan Daemen, Silvia Mella and Gilles Van Assche.

The overwrite duplex and Deck-BO come from ["Shaking up authenticated encryption"](https://eprint.iacr.org/2024/1618) by Joan Daemen, Seth Hoffert, Silvia Mella, Gilles Van Assche and Ronny Van Keer.
