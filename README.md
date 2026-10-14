# gravity-rs

[![Minimum Rust 1.85.0](https://img.shields.io/badge/rust-1.85.0%2B-orange.svg?logo=rust)](https://releases.rs/docs/1.85.0/)
[![Lines of Code](https://www.aschey.tech/tokei/github/gendx/gravity-rs?category=code&branch=master)](https://github.com/gendx/gravity-rs)
[![Dependencies](https://deps.rs/repo/github/gendx/gravity-rs/status.svg)](https://deps.rs/repo/github/gendx/gravity-rs)
[![Codecov](https://codecov.io/gh/gendx/gravity-rs/branch/master/graph/badge.svg)](https://app.codecov.io/gh/gendx/gravity-rs/tree/master)
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

## References

Research papers:
- [SPHINCS: practical stateless hash-based signatures (2014)](https://eprint.iacr.org/2014/795)
- [Clarifying the subset-resilience problem (2017)](https://eprint.iacr.org/2017/909)
- [Improving Stateless Hash-Based Signatures (2017)](https://eprint.iacr.org/2017/933)
- [The SPHINCS+ Signature Framework (2019)](https://eprint.iacr.org/2019/1086)
- [Shorter Hash-Based Signatures Using Forced Pruning (2025)](https://eprint.iacr.org/2025/2069)
- [Shorter Hash-based Signatures via Bucket Thinning (2026)](https://eprint.iacr.org/2026/1328)

Standards:
- [FIPS 205 - Stateless Hash-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST SP 800-230 (Initial Public Draft) - Additional SLH-DSA Parameter Sets for Limited Signature Use Cases](https://csrc.nist.gov/pubs/sp/800/230/ipd)
- [SPHINCS+, Submission to the NIST post-quantum project, v.3.1](https://sphincs.org/data/sphincs+-r3.1-specification.pdf)

Related projects:
- https://github.com/MehdiAbri/PORS-FP
- https://github.com/sfluhrer/sphincs-param-set-search
