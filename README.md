# gravity-rs [![Build Status](https://travis-ci.org/gendx/gravity-rs.svg?branch=master)](https://travis-ci.org/gendx/gravity-rs)

A Rust implementation of the [Gravity-post-quantum](https://github.com/gravity-postquantum) signature schemes.

## Configuration

To configure the scheme's parameters (height of Merkle trees, number of subtrees, size of cache, etc.), modify them in the file `src/config.rs`.
There is currently no option to do this at runtime.

## Testing

Extensive unit tests are implemented to check the logic of the signature scheme.
High-level test vectors generated with the reference C implementation check the overall consistency.

You may want to use `cargo test --release`, because the implementation is quite slow in non-release mode.

## License

MIT

