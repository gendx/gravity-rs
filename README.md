# gravity-rs

[![Minimum Rust 1.85.0](https://img.shields.io/badge/rust-1.85.0%2B-orange.svg?logo=rust)](https://releases.rs/docs/1.85.0/)
[![Dependencies](https://deps.rs/repo/github/gendx/gravity-rs/status.svg)](https://deps.rs/repo/github/gendx/gravity-rs)
[![Build Status](https://github.com/gendx/gravity-rs/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/gendx/gravity-rs/actions/workflows/build.yml)
[![Test Status](https://github.com/gendx/gravity-rs/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/gendx/gravity-rs/actions/workflows/tests.yml)

A Rust implementation of the [Gravity-post-quantum](https://github.com/gravity-postquantum) signature schemes.

## Configuration

To configure the scheme's parameters (height of Merkle trees, number of subtrees, size of cache, etc.), modify them in the file `src/config.rs`.
There is currently no option to do this at runtime.

## Testing

Extensive unit tests are implemented to check the logic of the signature scheme.
High-level test vectors generated with the reference C implementation check the overall consistency.

You may want to use `cargo test --release`, because the implementation is quite slow in non-release mode.

## Disclaimer

The Gravity-SPHINCS signature scheme is still young and has not yet been independently audited, nor has this code.
For now, this is simply a proposal so don't use it in production!

## License

MIT

