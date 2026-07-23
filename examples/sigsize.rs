use num::{BigInt, BigRational, ToPrimitive, Zero};
use std::fmt::Debug;
use std::iter::Sum;
use std::ops::{Add, AddAssign, Div, Mul, MulAssign};
use std::time::Instant;

fn main() {
    evaluate::<F64Log2>();
    evaluate::<BigRational>();
}

fn evaluate<T>()
where
    T: Arithmetic + Debug + Clone,
    for<'a> &'a T: Mul<&'a T, Output = T>,
    for<'a> &'a T: Div<&'a T, Output = T>,
{
    // Parameters from https://eprint.iacr.org/2026/1328, section 5.1.
    println!("- SLH-DSA-128s (BPORS+FP)");
    octopus_size_bpors_distribution(33 << 2, 4, 6, 5);
    println!("- SLH-DSA-128f (BPORS+FP)");
    octopus_size_bpors_complete_distribution(7, 5, 1, 8);
    println!("- SLH-DSA-192s (BPORS+FP)");
    octopus_size_bpors_complete_distribution(7, 5, 8, 6);
    println!("- SLH-DSA-192f (BPORS+FP)");
    octopus_size_bpors_distribution(7 << 4, 5, 3, 9);
    println!("- SLH-DSA-256s (BPORS+FP)");
    octopus_size_bpors_distribution(35 << 3, 5, 7, 7);
    println!("- SLH-DSA-256f (BPORS+FP)");
    octopus_size_bpors_distribution(29 << 3, 5, 3, 9);

    // Parameters from https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf, section 11.
    evaluate_slh_dsa("SLH-DSA-128s", 12, 14);
    evaluate_slh_dsa("SLH-DSA-128f", 6, 33);
    evaluate_slh_dsa("SLH-DSA-192s", 14, 17);
    evaluate_slh_dsa("SLH-DSA-192f", 8, 33);
    evaluate_slh_dsa("SLH-DSA-256s", 14, 22);
    evaluate_slh_dsa("SLH-DSA-256f", 9, 35);

    // Parameters from https://eprint.iacr.org/2025/2069.pdf, section 5.
    println!("- SLH-DSA-192s (PORS+FP)");
    octopus_size_distribution(65 << 12, 17);
    println!("- SLH-DSA-256s (PORS+FP)");
    octopus_size_distribution(43 << 13, 22);

    octopus_size_cutoff(65 << 12, 17, -11.0);
    octopus_size_cutoff(43 << 13, 22, -13.0);

    // Parameters from https://gendx.dev/assets/pdf/2017-07-master-thesis-endignoux-report.pdf,
    // section 7.2.1.
    evaluate_gravity_sphincs("GravitySmall", 16, 24);
    evaluate_gravity_sphincs("GravityMedium", 16, 32);
    evaluate_gravity_sphincs("GravityLarge", 16, 28);

    octopus_size_complete_cutoff(16, 24, -10.0);
    octopus_size_complete_cutoff(16, 32, -14.0);
    octopus_size_complete_cutoff(16, 28, -12.5);
}

fn evaluate_slh_dsa<T>(title: &str, h: u32, k: u32)
where
    T: Arithmetic + Debug + Clone,
    for<'a> &'a T: Mul<&'a T, Output = T>,
    for<'a> &'a T: Div<&'a T, Output = T>,
{
    println!("- {title}");
    octopus_size_distribution(k << h, k);
}

fn evaluate_gravity_sphincs<T>(title: &str, h: u32, k: u32)
where
    T: Arithmetic + Debug + Clone,
    for<'a> &'a T: Mul<&'a T, Output = T>,
    for<'a> &'a T: Div<&'a T, Output = T>,
{
    println!("- {title}");
    octopus_size_complete_distribution(h, k);
}

/// Computes the size distribution of a bucketized PORS Octopus (BPORS) as
/// described in https://eprint.iacr.org/2026/1328.
#[expect(non_snake_case)]
fn octopus_size_bpors_complete_distribution<T>(h: u32, k: u32, B: u32, K: u32)
where
    T: Arithmetic + Debug + Clone,
    for<'a> &'a T: Mul<&'a T, Output = T>,
{
    let start = Instant::now();
    let mut mem: MemoizedComplete<T> = MemoizedComplete::new(k as usize, h as usize);

    let mut baseline = Vec::new();
    let mut sum = T::zero();
    for m in 0..=k * h {
        let p = mem.size(h, k, m);
        sum += p;
        if !p.is_zero() {
            println!(
                "base size(2^{h}, {k}, {m}) = 2^{} | 2^{} | {}",
                p.to_f64_log2(),
                sum.to_f64_log2(),
                sum.to_f64(),
            );
            baseline.resize_with(m as usize, T::zero);
            baseline.push(p.clone());
        }
    }

    mem.debug();

    let distribution = convoluted_exponent(&baseline, K);
    let mut sum = T::zero();
    for (i, p) in distribution.iter().enumerate() {
        let m = i as u32 + K * B;
        sum += p;
        if !p.is_zero() {
            println!(
                "product size(2^{h}, {k}, {K}, {m}, {}) = 2^{} | 2^{} | {}",
                m + k * K,
                p.to_f64_log2(),
                sum.to_f64_log2(),
                sum.to_f64()
            );
        }
    }
    println!("Completed in {:?}", Instant::now().duration_since(start));
}

/// Computes the size distribution of a bucketized PORS Octopus (BPORS) as
/// described in https://eprint.iacr.org/2026/1328.
#[expect(non_snake_case)]
fn octopus_size_bpors_distribution<T>(t: u32, k: u32, B: u32, K: u32)
where
    T: Arithmetic + Debug + Clone,
    for<'a> &'a T: Mul<&'a T, Output = T>,
    for<'a> &'a T: Div<&'a T, Output = T>,
{
    let start = Instant::now();
    let mut mem: Memoized<T> = Memoized::new(k as usize, t as usize);

    let mut baseline = Vec::new();
    let mut sum = T::zero();
    for m in 0..=(k * t.next_power_of_two().ilog2()).min(t) {
        let p = mem.size(t, k, m);
        sum += &p;
        if !p.is_zero() {
            println!(
                "base size({t}, {k}, {m}) = 2^{} | 2^{} | {}",
                p.to_f64_log2(),
                sum.to_f64_log2(),
                sum.to_f64(),
            );
            baseline.resize_with(m as usize, T::zero);
            baseline.push(p.clone());
        }
    }

    mem.debug();

    let distribution = convoluted_exponent(&baseline, K);
    let mut sum = T::zero();
    for (i, p) in distribution.iter().enumerate() {
        let m = i as u32 + K * B;
        sum += p;
        if !p.is_zero() {
            println!(
                "product size({t}, {k}, {K}, {m}, {}) = 2^{} | 2^{} | {}",
                m + k * K,
                p.to_f64_log2(),
                sum.to_f64_log2(),
                sum.to_f64()
            );
        }
    }
    println!("Completed in {:?}", Instant::now().duration_since(start));
}

/// Computes the power of a probability distribution using fast exponentiation.
fn convoluted_exponent<T>(distribution: &[T], mut n: u32) -> Vec<T>
where
    T: Arithmetic + Clone,
    for<'a> &'a T: Mul<&'a T, Output = T>,
{
    let mut result = vec![T::one(); 1];
    let mut power: Vec<T> = distribution.to_vec();
    loop {
        if n & 1 == 1 {
            result = convolution(&result, &power);
        }
        n >>= 1;
        if n == 0 {
            break;
        }
        power = convolution(&power, &power);
    }
    result
}

/// Computes the convolution of two probability distributions.
fn convolution<T>(a: &[T], b: &[T]) -> Vec<T>
where
    T: Arithmetic + Clone,
    for<'a> &'a T: Mul<&'a T, Output = T>,
{
    let mut product = vec![T::zero(); a.len() + b.len() - 1];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            product[i + j] += x * y;
        }
    }
    product
}

/// Computes the size distribution of a PORS Octopus in a complete Merkle tree
/// of height `h` as described in https://eprint.iacr.org/2025/2069.
fn octopus_size_complete_distribution<T>(h: u32, k: u32)
where
    T: Arithmetic + Debug + Clone,
    for<'a> &'a T: Mul<&'a T, Output = T>,
{
    let start = Instant::now();
    let mut mem: MemoizedComplete<T> = MemoizedComplete::new(k as usize, h as usize);

    let mut sum = T::zero();
    for m in 0..=k * h {
        let p = mem.size(h, k, m);
        sum += p;
        if !p.is_zero() {
            println!(
                "size(2^{h}, {k}, {m}, {}) = 2^{} | 2^{} | {}",
                m + k,
                p.to_f64_log2(),
                sum.to_f64_log2(),
                sum.to_f64(),
            );
        }
    }

    mem.debug();
    println!("Completed in {:?}", Instant::now().duration_since(start));
}

fn octopus_size_complete_cutoff<T>(h: u32, k: u32, threshold: f64)
where
    T: Arithmetic + Debug + Clone,
    for<'a> &'a T: Mul<&'a T, Output = T>,
{
    let start = Instant::now();
    let mut mem: MemoizedComplete<T> = MemoizedComplete::new(k as usize, h as usize);

    let mut sum = T::zero();
    for m in 0..=k * h {
        let p = mem.size(h, k, m);
        sum += p;
        if sum.to_f64_log2() >= threshold {
            println!(
                "P(size(2^{h}, {k}) <= {m}) = 2^{} | {}",
                sum.to_f64_log2(),
                sum.to_f64()
            );
            break;
        }
    }

    mem.debug();
    println!("Completed in {:?}", Instant::now().duration_since(start));
}

/// Computes the size distribution of a PORS Octopus in an arbitrary Merkle tree
/// with `t` leaves as described in https://eprint.iacr.org/2025/2069.
fn octopus_size_distribution<T>(t: u32, k: u32)
where
    T: Arithmetic + Debug + Clone,
    for<'a> &'a T: Mul<&'a T, Output = T>,
    for<'a> &'a T: Div<&'a T, Output = T>,
{
    let start = Instant::now();
    let mut mem: Memoized<T> = Memoized::new(k as usize, t as usize);

    let mut sum = T::zero();
    for m in 0..=(k * t.next_power_of_two().ilog2()).min(t) {
        let p = mem.size(t, k, m);
        sum += &p;
        if !p.is_zero() {
            println!(
                "size({t}, {k}, {m}, {}) = 2^{} | 2^{} | {}",
                m + k,
                p.to_f64_log2(),
                sum.to_f64_log2(),
                sum.to_f64(),
            );
        }
    }

    mem.debug();
    println!("Completed in {:?}", Instant::now().duration_since(start));
}

fn octopus_size_cutoff<T>(t: u32, k: u32, threshold: f64)
where
    T: Arithmetic + Debug + Clone,
    for<'a> &'a T: Mul<&'a T, Output = T>,
    for<'a> &'a T: Div<&'a T, Output = T>,
{
    let start = Instant::now();
    let mut mem: Memoized<T> = Memoized::new(k as usize, t as usize);

    let mut sum = T::zero();
    for m in 0..=(k * t.next_power_of_two().ilog2()).min(t) {
        let p = mem.size(t, k, m);
        sum += p;
        if sum.to_f64_log2() >= threshold {
            println!(
                "P(size({t}, {k}) <= {m}) = 2^{} | {}",
                sum.to_f64_log2(),
                sum.to_f64()
            );
            break;
        }
    }

    mem.debug();
    println!("Completed in {:?}", Instant::now().duration_since(start));
}

struct MemoizedComplete<T> {
    zero: T,
    choose: Table2d<T>,
    choose_h: Table2d<T>,
    siblings: Table3d<T>,
    size: Table3d<T>,
}

impl<T: Arithmetic + Clone> MemoizedComplete<T> {
    fn new(k: usize, h: usize) -> Self {
        Self {
            zero: T::zero(),
            choose: Table2d::new([k + 1, k + 1]),
            choose_h: Table2d::new([k + 1, h + 1]),
            siblings: Table3d::new([h + 1, k + 1, k + 1]),
            size: Table3d::new([h + 1, k + 1, k * h + 1]),
        }
    }

    fn debug(&self) {
        debug_table(&self.choose, "choose");
        debug_table(&self.choose_h, "choose_h");
        debug_table(&self.siblings, "siblings");
        debug_table(&self.size, "size");
    }
}

impl<T> MemoizedComplete<T>
where
    T: Arithmetic,
    for<'a> &'a T: Mul<&'a T, Output = T>,
{
    fn size(&mut self, h: u32, k: u32, m: u32) -> &T {
        if m > h * k {
            &self.zero
        } else {
            Self::size_inner(
                &mut self.size,
                &mut self.siblings,
                &mut self.choose,
                &mut self.choose_h,
                h,
                k,
                m,
            )
        }
    }

    fn size_inner<'a>(
        size_table: &'a mut Table3d<T>,
        siblings_table: &mut Table3d<T>,
        choose_table: &mut Table2d<T>,
        choose_h_table: &mut Table2d<T>,
        h: u32,
        k: u32,
        m: u32,
    ) -> &'a T {
        let index = [h as usize, k as usize, m as usize];
        if size_table[index].is_none() {
            let value = Self::size_impl(
                size_table,
                siblings_table,
                choose_table,
                choose_h_table,
                h,
                k,
                m,
            );
            size_table[index] = Some(value);
        }
        size_table[index].as_ref().unwrap()
    }

    fn size_impl(
        size_table: &mut Table3d<T>,
        siblings_table: &mut Table3d<T>,
        choose_table: &mut Table2d<T>,
        choose_h_table: &mut Table2d<T>,
        h: u32,
        k: u32,
        m: u32,
    ) -> T {
        if h == 0 && k == 1 {
            if m == 0 {
                return T::one();
            } else {
                return T::zero();
            }
        }
        if m < h - k.next_power_of_two().ilog2() || m > k * (h - k.ilog2()) {
            return T::zero();
        }

        let start = k.saturating_sub(1 << (h - 1));
        let end = k / 2;

        (start..=end)
            .map(|s| {
                if m + 2 * s < k {
                    T::zero()
                } else {
                    Self::size_inner(
                        size_table,
                        siblings_table,
                        choose_table,
                        choose_h_table,
                        h - 1,
                        k - s,
                        (m + 2 * s) - k,
                    ) * Self::siblings_inner(siblings_table, choose_table, choose_h_table, h, k, s)
                }
            })
            .sum()
    }

    fn siblings_inner<'a>(
        siblings_table: &'a mut Table3d<T>,
        choose_table: &mut Table2d<T>,
        choose_h_table: &mut Table2d<T>,
        h: u32,
        k: u32,
        s: u32,
    ) -> &'a T {
        let index = [h as usize, k as usize, s as usize];
        if siblings_table[index].is_none() {
            let value = Self::siblings_impl(choose_table, choose_h_table, h, k, s);
            siblings_table[index] = Some(value);
        }
        siblings_table[index].as_ref().unwrap()
    }

    fn siblings_impl(
        choose_table: &mut Table2d<T>,
        choose_h_table: &mut Table2d<T>,
        h: u32,
        k: u32,
        s: u32,
    ) -> T {
        if k < 2 * s {
            T::zero()
        } else {
            T::from_log2(k - 2 * s)
                * Self::choose_h(choose_h_table, k - s, h - 1)
                * Self::choose(choose_table, s, k - s)
                / Self::choose_h(choose_h_table, k, h)
        }
    }

    fn choose(table: &mut Table2d<T>, n: u32, among: u32) -> &T {
        let x = &mut table[[n as usize, among as usize]];
        if x.is_none() {
            let value = choose_impl(n, among);
            *x = Some(value);
        }
        x.as_ref().unwrap()
    }

    fn choose_h(table: &mut Table2d<T>, n: u32, among_h: u32) -> &T {
        let x = &mut table[[n as usize, among_h as usize]];
        if x.is_none() {
            let value = choose_impl(n, 1 << among_h);
            *x = Some(value);
        }
        x.as_ref().unwrap()
    }
}

struct Memoized<T> {
    choose: SparseTable2d<T>,
    siblings: SparseTable3d<T>,
    size: SparseTable5d<T>,
}

impl<T: Clone> Memoized<T> {
    fn new(k: usize, t: usize) -> Self {
        let h = t.ilog2() as usize;
        Self {
            choose: SparseTable2d::with_hasher([k + 1, t + 1], Default::default()),
            siblings: SparseTable3d::with_hasher([t + 1, k + 1, k + 1], Default::default()),
            size: SparseTable5d::with_hasher(
                [h + 1, k + 1, k + 1, 3, (k * (h + 1)).min(t) + 1],
                Default::default(),
            ),
        }
    }

    fn debug(&self) {
        debug_sparse_table(&self.choose, "choose");
        debug_sparse_table(&self.siblings, "siblings");
        debug_sparse_table(&self.size, "size");
    }
}

impl<T: Clone> Memoized<T>
where
    T: Arithmetic,
    for<'a> &'a T: Mul<&'a T, Output = T>,
    for<'a> &'a T: Div<&'a T, Output = T>,
{
    /// See https://eprint.iacr.org/2025/2069, theorem 3.
    fn size(&mut self, t: u32, k: u32, m: u32) -> T {
        assert!(k <= t);
        let h = t.next_power_of_two().ilog2();

        if h == 0 && k == 1 {
            if m == 0 {
                return T::one();
            } else {
                return T::zero();
            }
        }
        if m + k.next_power_of_two().ilog2() < t.ilog2() || m > k * (h - k.ilog2()) {
            return T::zero();
        }

        let hh = 1 << (h - 1);
        let l = t - hh;
        let r = hh - l;
        let x = 2 * l;

        let sum = (0..=k.min(x))
            .map(|j| {
                let start = j.saturating_sub(l);
                let end = j / 2;
                let sum = (start..=end)
                    .map(|s| {
                        if m + 2 * s < j {
                            T::zero()
                        } else {
                            Self::size_h_inner(
                                &mut self.size,
                                &mut self.siblings,
                                &mut self.choose,
                                h - 1,
                                l,
                                r,
                                j - s,
                                k - j,
                                0,
                                m + 2 * s - j,
                            ) * Self::siblings_inner(&mut self.siblings, &mut self.choose, x, j, s)
                        }
                    })
                    .sum::<T>();
                sum * Self::choose(&mut self.choose, j, x)
                    * Self::choose(&mut self.choose, k - j, t - x)
            })
            .sum::<T>();
        sum / Self::choose(&mut self.choose, k, t)
    }

    #[expect(clippy::too_many_arguments)]
    fn size_h_inner<'a>(
        size_table: &'a mut SparseTable5d<T>,
        siblings_table: &mut SparseTable3d<T>,
        choose_table: &mut SparseTable2d<T>,
        h: u32,
        l: u32,
        r: u32,
        kl: u32,
        kr: u32,
        c: i32,
        m: u32,
    ) -> &'a T {
        // Note: for a given height h, l and r are always the same.
        let index = [
            h as usize,
            kl as usize,
            kr as usize,
            (c + 1) as usize,
            m as usize,
        ];
        // TODO: read the map only once on success when the Polonius borrow checker is
        // implemented.
        if size_table.get(index).is_none() {
            let value = Self::size_h_impl(
                size_table,
                siblings_table,
                choose_table,
                h,
                l,
                r,
                kl,
                kr,
                c,
                m,
            );
            return size_table.entry(index).or_insert(value);
        }
        size_table.get(index).unwrap()
    }

    /// See https://eprint.iacr.org/2025/2069, appendix A.
    #[expect(clippy::too_many_arguments)]
    fn size_h_impl(
        size_table: &mut SparseTable5d<T>,
        siblings_table: &mut SparseTable3d<T>,
        choose_table: &mut SparseTable2d<T>,
        h: u32,
        l: u32,
        r: u32,
        kl: u32,
        kr: u32,
        c: i32,
        m: u32,
    ) -> T {
        if h == 0 {
            // A tree of height 0 always needs 0 authentication nodes.
            if m == 0 { T::one() } else { T::zero() }
        } else if l % 2 == 0 {
            Self::size_h_even(
                size_table,
                siblings_table,
                choose_table,
                h,
                l,
                r,
                kl,
                kr,
                c,
                m,
            )
        } else {
            Self::size_h_odd(
                size_table,
                siblings_table,
                choose_table,
                h,
                l,
                r,
                kl,
                kr,
                c,
                m,
            )
        }
    }

    /// See https://eprint.iacr.org/2025/2069, appendix A.1.
    #[expect(clippy::too_many_arguments)]
    fn size_h_even(
        size_table: &mut SparseTable5d<T>,
        siblings_table: &mut SparseTable3d<T>,
        choose_table: &mut SparseTable2d<T>,
        h: u32,
        l: u32,
        r: u32,
        kl: u32,
        kr: u32,
        c: i32,
        m: u32,
    ) -> T {
        let ll = l / 2;
        let rr = r / 2;

        match c {
            0 => (0..=(kl / 2))
                .map(|sl| {
                    let sum = (0..=(kr / 2))
                        .map(|sr| {
                            if m + 2 * (sl + sr) < kl + kr {
                                T::zero()
                            } else {
                                Self::size_h_inner(
                                    size_table,
                                    siblings_table,
                                    choose_table,
                                    h - 1,
                                    ll,
                                    rr,
                                    kl - sl,
                                    kr - sr,
                                    0,
                                    m + 2 * (sl + sr) - (kl + kr),
                                ) * Self::siblings_inner(siblings_table, choose_table, r, kr, sr)
                            }
                        })
                        .sum::<T>();
                    sum * Self::siblings_inner(siblings_table, choose_table, l, kl, sl)
                })
                .sum(),
            1 => {
                if kr > r {
                    return T::zero();
                }

                let sum = (0..=(kl / 2))
                    .map(|sl| {
                        let sum = (0..=1.min(kr - 1))
                            .map(|y| {
                                let sum = (0..=((kr - 1 - y) / 2))
                                    .map(|srr| {
                                        let sr = srr + y;
                                        if m + 2 * (sl + sr) < kl + kr {
                                            T::zero()
                                        } else {
                                            Self::size_h_inner(
                                                size_table,
                                                siblings_table,
                                                choose_table,
                                                h - 1,
                                                ll,
                                                rr,
                                                kl - sl,
                                                kr - sr,
                                                1,
                                                m + 2 * (sl + sr) - (kl + kr),
                                            ) * Self::siblings_inner(
                                                siblings_table,
                                                choose_table,
                                                r - 2,
                                                kr - 1 - y,
                                                srr,
                                            )
                                        }
                                    })
                                    .sum::<T>();
                                sum * Self::choose(choose_table, kr - 1 - y, r - 2)
                            })
                            .sum::<T>();
                        sum * Self::siblings_inner(siblings_table, choose_table, l, kl, sl)
                    })
                    .sum::<T>();
                sum / Self::choose(choose_table, kr - 1, r - 1)
            }
            -1 => {
                if kr >= r {
                    return T::zero();
                }

                let sum = (0..=(kl / 2))
                    .map(|sl| {
                        let sum = (0..=1.min(kr))
                            .map(|y| {
                                let sum = (0..=((kr - y) / 2))
                                    .map(|sr| {
                                        if m + 2 * (sl + sr) < kl + kr {
                                            T::zero()
                                        } else {
                                            Self::size_h_inner(
                                                size_table,
                                                siblings_table,
                                                choose_table,
                                                h - 1,
                                                ll,
                                                rr,
                                                kl - sl,
                                                kr - sr,
                                                2 * y as i32 - 1,
                                                m + 2 * (sl + sr) - (kl + kr),
                                            ) * Self::siblings_inner(
                                                siblings_table,
                                                choose_table,
                                                r - 2,
                                                kr - y,
                                                sr,
                                            )
                                        }
                                    })
                                    .sum::<T>();
                                sum * Self::choose(choose_table, kr - y, r - 2)
                            })
                            .sum::<T>();
                        sum * Self::siblings_inner(siblings_table, choose_table, l, kl, sl)
                    })
                    .sum::<T>();
                sum / Self::choose(choose_table, kr, r - 1)
            }
            _ => panic!("Invalid value for c = {c}"),
        }
    }

    /// See https://eprint.iacr.org/2025/2069, appendix A.2.
    #[expect(clippy::too_many_arguments)]
    fn size_h_odd(
        size_table: &mut SparseTable5d<T>,
        siblings_table: &mut SparseTable3d<T>,
        choose_table: &mut SparseTable2d<T>,
        h: u32,
        l: u32,
        r: u32,
        kl: u32,
        kr: u32,
        c: i32,
        m: u32,
    ) -> T {
        let ll = l / 2;
        let rr = r.div_ceil(2);

        if r == 0 || kl > l {
            return T::zero();
        }

        match c {
            0 => {
                if kr > r {
                    return T::zero();
                }

                let sum = (0..=1.min(kl))
                    .map(|xl| {
                        let sum = (0..=1.min(kr))
                            .map(|xr| {
                                let cc = 2 * (xl | xr) as i32 - 1;
                                let sum = (0..=((kl - xl) / 2))
                                    .map(|sl| {
                                        let sum = (0..=((kr - xr) / 2))
                                            .map(|sr| {
                                                if m + 2 * (sl + sr + xl * xr) < kl + kr {
                                                    T::zero()
                                                } else {
                                                    Self::size_h_inner(
                                                        size_table,
                                                        siblings_table,
                                                        choose_table,
                                                        h - 1,
                                                        ll,
                                                        rr,
                                                        kl - xl - sl,
                                                        kr - xr - sr + (xl | xr),
                                                        cc,
                                                        m + 2 * (sl + sr + xl * xr) - (kl + kr),
                                                    ) * Self::siblings_inner(
                                                        siblings_table,
                                                        choose_table,
                                                        r - 1,
                                                        kr - xr,
                                                        sr,
                                                    )
                                                }
                                            })
                                            .sum::<T>();
                                        sum * Self::siblings_inner(
                                            siblings_table,
                                            choose_table,
                                            l - 1,
                                            kl - xl,
                                            sl,
                                        )
                                    })
                                    .sum::<T>();
                                sum * Self::choose(choose_table, kr - xr, r - 1)
                            })
                            .sum::<T>();
                        sum * Self::choose(choose_table, kl - xl, l - 1)
                    })
                    .sum::<T>();
                sum / Self::choose(choose_table, kl, l) / Self::choose(choose_table, kr, r)
            }
            1 => {
                let sum = (0..=1.min(kl))
                    .map(|xl| {
                        let sum = (0..=((kl - xl) / 2))
                            .map(|sl| {
                                let sum = (0..=((kr - 1) / 2))
                                    .map(|sr| {
                                        if m + 2 * (sl + sr + xl) < kl + kr {
                                            T::zero()
                                        } else {
                                            Self::size_h_inner(
                                                size_table,
                                                siblings_table,
                                                choose_table,
                                                h - 1,
                                                ll,
                                                rr,
                                                kl - xl - sl,
                                                kr - sr,
                                                1,
                                                m + 2 * (sl + sr + xl) - (kl + kr),
                                            ) * Self::siblings_inner(
                                                siblings_table,
                                                choose_table,
                                                r - 1,
                                                kr - 1,
                                                sr,
                                            )
                                        }
                                    })
                                    .sum::<T>();
                                sum * Self::siblings_inner(
                                    siblings_table,
                                    choose_table,
                                    l - 1,
                                    kl - xl,
                                    sl,
                                )
                            })
                            .sum::<T>();
                        sum * Self::choose(choose_table, kl - xl, l - 1)
                    })
                    .sum::<T>();
                sum / Self::choose(choose_table, kl, l)
            }
            -1 => {
                let sum = (0..=1.min(kl))
                    .map(|xl| {
                        let cc = 2 * xl as i32 - 1;
                        let sum = (0..=((kl - xl) / 2))
                            .map(|sl| {
                                let sum = (0..=(kr / 2))
                                    .map(|sr| {
                                        if m + 2 * (sl + sr) < kl + kr {
                                            T::zero()
                                        } else {
                                            Self::size_h_inner(
                                                size_table,
                                                siblings_table,
                                                choose_table,
                                                h - 1,
                                                ll,
                                                rr,
                                                kl - xl - sl,
                                                kr - sr + xl,
                                                cc,
                                                m + 2 * (sl + sr) - (kl + kr),
                                            ) * Self::siblings_inner(
                                                siblings_table,
                                                choose_table,
                                                r - 1,
                                                kr,
                                                sr,
                                            )
                                        }
                                    })
                                    .sum::<T>();
                                sum * Self::siblings_inner(
                                    siblings_table,
                                    choose_table,
                                    l - 1,
                                    kl - xl,
                                    sl,
                                )
                            })
                            .sum::<T>();
                        sum * Self::choose(choose_table, kl - xl, l - 1)
                    })
                    .sum::<T>();
                sum / Self::choose(choose_table, kl, l)
            }
            _ => panic!("Invalid value for c = {c}"),
        }
    }

    fn siblings_inner<'a>(
        siblings_table: &'a mut SparseTable3d<T>,
        choose_table: &mut SparseTable2d<T>,
        x: u32,
        k: u32,
        s: u32,
    ) -> &'a T {
        let index = [x as usize, k as usize, s as usize];
        siblings_table
            .entry(index)
            .or_insert_with(|| Self::siblings_impl(choose_table, x, k, s))
    }

    fn siblings_impl(choose_table: &mut SparseTable2d<T>, x: u32, k: u32, s: u32) -> T {
        assert!(x % 2 == 0);
        if k < 2 * s || k > x || 2 * s > x {
            T::zero()
        } else {
            T::from_log2(k - 2 * s)
                * Self::choose(choose_table, k - s, x / 2)
                * Self::choose(choose_table, s, k - s)
                / Self::choose(choose_table, k, x)
        }
    }

    fn choose(table: &mut SparseTable2d<T>, n: u32, among: u32) -> &T {
        let index = [n as usize, among as usize];
        table.entry(index).or_insert_with(|| choose_impl(n, among))
    }
}

fn choose_impl<T: Arithmetic>(n: u32, among: u32) -> T {
    if n > among {
        return T::zero();
    }
    let mut res = T::one();
    for i in 0..n {
        res *= T::from(among - i) / T::from(i + 1);
    }
    res
}

trait Arithmetic:
    Mul<Output = Self>
    + Div<Output = Self>
    + AddAssign
    + MulAssign
    + Sum
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> Div<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
{
    fn zero() -> Self;

    fn one() -> Self;

    fn is_zero(&self) -> bool;

    fn from(x: u32) -> Self;

    fn from_log2(x: u32) -> Self;

    #[cfg(test)]
    fn from_ratio(num: u32, denom: u32) -> Self {
        Self::from(num) / Self::from(denom)
    }

    fn to_f64(&self) -> f64;

    fn to_f64_log2(&self) -> f64;
}

#[derive(Debug, Clone, Copy)]
struct F64Log2(f64);

impl Div for F64Log2 {
    type Output = Self;

    #[expect(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        F64Log2(self.0 - rhs.0)
    }
}

impl Div for &F64Log2 {
    type Output = F64Log2;

    #[expect(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        F64Log2(self.0 - rhs.0)
    }
}

impl Div<&Self> for F64Log2 {
    type Output = Self;

    #[expect(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: &Self) -> Self::Output {
        F64Log2(self.0 - rhs.0)
    }
}

impl Mul for F64Log2 {
    type Output = Self;

    #[expect(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: Self) -> Self::Output {
        F64Log2(self.0 + rhs.0)
    }
}

impl Mul for &F64Log2 {
    type Output = F64Log2;

    #[expect(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: Self) -> Self::Output {
        F64Log2(self.0 + rhs.0)
    }
}

impl Mul<&Self> for F64Log2 {
    type Output = Self;

    #[expect(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: &Self) -> Self::Output {
        F64Log2(self.0 + rhs.0)
    }
}

impl Add for F64Log2 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        if self.0 < rhs.0 {
            rhs + self
        } else if rhs.0 == f64::NEG_INFINITY {
            self
        } else {
            F64Log2(self.0 + 2.0_f64.powf(rhs.0 - self.0).ln_1p() / std::f64::consts::LN_2)
        }
    }
}

impl AddAssign for F64Log2 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl AddAssign<&Self> for F64Log2 {
    fn add_assign(&mut self, rhs: &Self) {
        *self = *self + *rhs;
    }
}

impl MulAssign for F64Log2 {
    #[expect(clippy::suspicious_op_assign_impl)]
    fn mul_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl Sum for F64Log2 {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = Self>,
    {
        iter.fold(Self::zero(), |acc, x| acc + x)
    }
}

impl Arithmetic for F64Log2 {
    fn zero() -> Self {
        F64Log2(f64::NEG_INFINITY)
    }

    fn one() -> Self {
        F64Log2(0.0)
    }

    fn is_zero(&self) -> bool {
        self.0 == f64::NEG_INFINITY
    }

    fn from(x: u32) -> Self {
        F64Log2((x as f64).log2())
    }

    fn from_log2(x: u32) -> Self {
        F64Log2(x as f64)
    }

    fn to_f64(&self) -> f64 {
        2.0_f64.powf(self.0)
    }

    fn to_f64_log2(&self) -> f64 {
        self.0
    }
}

impl Arithmetic for BigRational {
    fn zero() -> Self {
        BigRational::from_integer(BigInt::from(0))
    }

    fn one() -> Self {
        BigRational::from_integer(BigInt::from(1))
    }

    fn is_zero(&self) -> bool {
        Zero::is_zero(self)
    }

    fn from(x: u32) -> Self {
        BigRational::from_integer(BigInt::from(x))
    }

    fn from_log2(x: u32) -> Self {
        BigRational::from_integer(BigInt::from(1) << x)
    }

    fn to_f64(&self) -> f64 {
        ToPrimitive::to_f64(self).unwrap()
    }

    fn to_f64_log2(&self) -> f64 {
        Arithmetic::to_f64(self).log2()
    }
}

type Table2d<T> = ndtable::Table2d<Option<T>>;
type Table3d<T> = ndtable::Table3d<Option<T>>;

type SparseTable2d<T> = ndtable::SparseTable2d<T, rustc_hash::FxBuildHasher>;
type SparseTable3d<T> = ndtable::SparseTable3d<T, rustc_hash::FxBuildHasher>;
type SparseTable5d<T> = ndtable::SparseTable5d<T, rustc_hash::FxBuildHasher>;

fn debug_table<T, const N: usize>(table: &ndtable::TableNd<Option<T>, N>, title: &str) {
    eprintln!(
        "cache({title}) = {} ({:.02}%) / {} = {:?}",
        table.len(),
        100.0 * table.len() as f64 / table.capacity() as f64,
        table.capacity(),
        table.size(),
    );
}

fn debug_sparse_table<T, const N: usize, S>(table: &ndtable::SparseTableNd<T, N, S>, title: &str) {
    eprintln!(
        "cache({title}) = {} ({:.02}%) / {} = {:?}",
        table.len(),
        100.0 * table.len() as f64 / table.capacity() as f64,
        table.capacity(),
        table.size(),
    );
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_distribution(k: u32, t: u32, expected: &[u32], denom: u32) {
        assert_eq!(expected.len(), t as usize + 1);

        let mut mem: Memoized<BigRational> = Memoized::new(k as usize, t as usize);
        for m in 0..=t {
            assert_eq!(
                mem.size(t, k, m),
                BigRational::from_ratio(expected[m as usize], denom),
                "t={t} k={k} m={m}"
            );
        }
    }

    #[test]
    fn test_known_distributions() {
        test_distribution(1, 1, &[1, 0], 1);

        test_distribution(1, 2, &[0, 1, 0], 1);
        test_distribution(2, 2, &[1, 0, 0], 1);

        test_distribution(1, 3, &[0, 1, 2, 0], 3);
        test_distribution(2, 3, &[0, 1, 0, 0], 1);
        test_distribution(3, 3, &[1, 0, 0, 0], 1);

        test_distribution(1, 4, &[0, 0, 1, 0, 0], 1);
        test_distribution(2, 4, &[0, 1, 2, 0, 0], 3);
        test_distribution(3, 4, &[0, 1, 0, 0, 0], 1);
        test_distribution(4, 4, &[1, 0, 0, 0, 0], 1);

        test_distribution(1, 5, &[0, 0, 3, 2, 0, 0], 5);
        test_distribution(2, 5, &[0, 1, 5, 4, 0, 0], 10);
        test_distribution(3, 5, &[0, 1, 4, 0, 0, 0], 5);
        test_distribution(4, 5, &[0, 1, 0, 0, 0, 0], 1);
        test_distribution(5, 5, &[1, 0, 0, 0, 0, 0], 1);
    }

    #[test]
    fn test_compare_distributions() {
        for h in 0..=5 {
            let t = 1 << h;
            for k in 1..=t {
                let mut mem: Memoized<BigRational> = Memoized::new(k as usize, t as usize);
                let mut mem_complete: MemoizedComplete<BigRational> =
                    MemoizedComplete::new(k as usize, h as usize);
                for m in 0..=t {
                    assert_eq!(
                        &mem.size(t, k, m),
                        mem_complete.size(h, k, m),
                        "size({t}, {k}, {m}) != size({h}, {k}, {m})"
                    );
                }
            }
        }
    }

    #[test]
    fn test_one_leaf() {
        for t in 1u32..=32 {
            let k = 1;
            let mut mem: Memoized<BigRational> = Memoized::new(k as usize, t as usize);

            let h = t.next_power_of_two().ilog2();
            let right = (1 << h) - t;
            let left = t - right;

            println!("{t} of height {h} = {left} + {right}");

            let p_left = mem.size(t, k, h);
            assert_eq!(
                p_left,
                BigRational::from_ratio(left, t),
                "size_left({t}, {k}, {}) = {p_left} != {left}/{t}",
                h
            );
            let p_right = mem.size(t, k, h - 1);
            assert_eq!(
                p_right,
                BigRational::from_ratio(right, t),
                "size_right({t}, {k}, {}) = {p_right} != {right}/{t}",
                h - 1
            );
        }
    }

    #[test]
    fn test_complete_distributions_are_full() {
        for h in 0..=7 {
            let t = 1 << h;
            for k in 1..=t {
                let mut mem: MemoizedComplete<BigRational> =
                    MemoizedComplete::new(k as usize, h as usize);
                let mut sum = <BigRational as Arithmetic>::zero();
                for m in 0..=t {
                    let p = mem.size(h, k, m);
                    println!("size(2^{h}, {k}, {m}) = {p}");
                    sum += p;
                }
                assert_eq!(sum, BigRational::one(), "sum(2^{h}, {k}) = {sum} != 1");
            }
        }
    }

    #[test]
    fn test_distributions_are_full() {
        for t in 1..=32 {
            for k in 1..=t {
                let mut mem: Memoized<BigRational> = Memoized::new(k as usize, t as usize);
                let mut sum = <BigRational as Arithmetic>::zero();
                for m in 0..=t {
                    let p = mem.size(t, k, m);
                    println!("size({t}, {k}, {m}) = {p}");
                    sum += p;
                }
                assert_eq!(sum, BigRational::one(), "sum({t}, {k}) = {sum} != 1");
            }
        }
    }
}
