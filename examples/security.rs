use num::bigint::Sign;
use num::{BigInt, BigRational, BigUint, One, ToPrimitive, Zero};
use std::fmt::Debug;
use std::iter::Sum;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub};

fn main() {
    let mut mem: Memoized<F64Log2, F64Log2> =
        Memoized::new(/* max(r) */ 50, /* max(B) */ 20);
    mem.evaluate();

    let mut mem: Memoized<BigInt, BigRational> =
        Memoized::new(/* max(r) */ 50, /* max(B) */ 20);
    mem.evaluate();
}

struct Memoized<I, T> {
    weight_poisson: Table3d<T>,
    choose: Table2d<I>,
    binom_power: Table2d<T>,
    binom_opposite_power: Table2d<T>,
    rmax: u32,
}

impl<I: Clone, T: Clone> Memoized<I, T> {
    fn new(rmax: u32, bmax: usize) -> Self {
        Self {
            weight_poisson: Table3d::new([70, 70, rmax as usize + 1]),
            choose: Table2d::new([rmax as usize + 1, rmax as usize + 1]),
            binom_power: Table2d::new([bmax + 1, rmax as usize + 1]),
            binom_opposite_power: Table2d::new([bmax + 1, rmax as usize + 1]),
            rmax,
        }
    }
}

impl<I, T> Memoized<I, T>
where
    I: Integer + Clone,
    T: Rational<I> + Debug + Clone,
    for<'a> &'a I: Mul<&'a I, Output = I>,
    for<'a> &'a T: Mul<&'a T, Output = T>,
{
    fn evaluate(&mut self) {
        self.slh_dsa();
        self.bpors_params();
    }

    fn slh_dsa(&mut self) {
        println!("SLH-DSA security:");
        // Parameters from https://eprint.iacr.org/2014/795.
        self.slh_dsa_variants(
            "SPHINCS v1 (conservative parameters based on HORST)",
            32,
            11,
            60,
            50,
        );
        // Parameters from https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf, section 11.
        self.slh_dsa_variants("SLH-DSA-128s", 14, 12, 63, 64);
        self.slh_dsa_variants("SLH-DSA-128f", 33, 6, 66, 64);
        self.slh_dsa_variants("SLH-DSA-192s", 17, 14, 63, 64);
        self.slh_dsa_variants("SLH-DSA-192f", 33, 8, 66, 64);
        self.slh_dsa_variants("SLH-DSA-256s", 22, 14, 64, 64);
        self.slh_dsa_variants("SLH-DSA-256f", 35, 9, 68, 64);
        // Parameters from https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-230.ipd.pdf, section 2.1.
        self.slh_dsa_variants("SLH-DSA-128-24", 6, 24, 22, 24);
        self.slh_dsa_variants("SLH-DSA-192-24", 9, 25, 21, 24);
        self.slh_dsa_variants("SLH-DSA-256-24", 12, 25, 21, 24);
    }

    fn bpors_params(&mut self) {
        // Parameters from https://eprint.iacr.org/2026/1328, section 5.1.
        println!("BPORS security:");
        println!(
            "- 128s: {}",
            self.bpors(4, 33 << 2, 5, 6, 63, 64).to_f64_log2()
        );
        println!(
            "- 128f: {}",
            self.bpors(5, 1 << 7, 8, 1, 66, 64).to_f64_log2()
        );
        println!(
            "- 192s: {}",
            self.bpors(5, 1 << 7, 6, 8, 63, 64).to_f64_log2()
        );
        println!(
            "- 192f: {}",
            self.bpors(5, 7 << 4, 9, 3, 66, 64).to_f64_log2()
        );
        println!(
            "- 256s: {}",
            self.bpors(5, 35 << 3, 7, 7, 64, 64).to_f64_log2()
        );
        println!(
            "- 256f: {}",
            self.bpors(5, 29 << 3, 9, 3, 68, 64).to_f64_log2()
        );
        // Parameters from https://eprint.iacr.org/2026/1328, section 5.2.
        println!(
            "- 128-24: {}",
            self.bpors(7, 23 << 5, 2, 13, 22, 24).to_f64_log2()
        );
        println!(
            "- 192-24: {}",
            self.bpors(8, 17 << 9, 2, 13, 21, 24).to_f64_log2()
        );
        println!(
            "- 256-24: {}",
            self.bpors(8, 27 << 7, 3, 13, 21, 24).to_f64_log2()
        );
    }

    fn slh_dsa_variants(&mut self, title: &str, k: u32, t: u32, h: u32, q: u32) {
        println!("- {title}: {}", self.fors(k, t, h, q).to_f64_log2());
        println!(
            "- {title} (PORS lower bound): {}",
            self.pors(k, k << t, h, q).to_f64_log2()
        );
        println!(
            "- {title} (PORS precise): {}",
            self.pors_precise(k, k << t, h, q).to_f64_log2()
        );
    }

    /// Returns an upper bound of the success probability of an attacker making
    /// `2^q` queries against a FORS construction with `k` trees of height `t`,
    /// on a hyper-tree of height `h`.
    ///
    /// See https://sphincs.org/data/sphincs+-r3.1-specification.pdf.
    fn fors(&mut self, k: u32, t: u32, h: u32, q: u32) -> T {
        let rate = T::from_log2(q) / T::from_log2(h);

        let mut res = T::zero();
        for r in 0..=self.rmax {
            //let cover = Self::cover_given_r(1, 1 << t, r).powi(k);
            let cover = Self::dark_side(k, 1 << t, r);
            let poisson = Self::weight_poisson(&mut self.weight_poisson, r, h, q, &rate);
            eprint!("r={r}: {} * {}", cover.to_f64_log2(), poisson.to_f64_log2());
            let product = cover * poisson;
            eprint!(" = {}", product.to_f64_log2());
            res += product;
            eprintln!(" -> {}", res.to_f64_log2());
        }
        res
    }

    /// Probability that `k` values, each chosen uniformly among `0..t`, all
    /// overlap with `r` previous uniform values in `k` trees.
    ///
    /// See https://sphincs.org/data/sphincs+-r3.1-specification.pdf, section 9.3.3.
    fn dark_side(k: u32, t: u32, r: u32) -> T {
        (T::one() / T::from(t))
            .one_minus_x()
            .powi(r)
            .one_minus_x()
            .powi(k)
    }

    /// Returns an upper bound of the success probability of an attacker making
    /// `2^q` queries against a PORS construction with `k` values chosen among
    /// `t`, on a hyper-tree of height `h`.
    ///
    /// See https://eprint.iacr.org/2017/909.
    fn pors(&mut self, k: u32, t: u32, h: u32, q: u32) -> T {
        let rate = T::from_log2(q) / T::from_log2(h);

        let mut res = T::zero();
        for r in 0..=self.rmax {
            let cover = Self::cover_pors(k, t, k * r);
            let poisson = Self::weight_poisson(&mut self.weight_poisson, r, h, q, &rate);
            eprint!("r={r}: {} * {}", cover.to_f64_log2(), poisson.to_f64_log2());
            let product = cover * poisson;
            eprint!(" = {}", product.to_f64_log2());
            res += product;
            eprintln!(" -> {}", res.to_f64_log2());
        }
        res
    }

    /// Probability that `k` distinct values chosen uniformly among `0..t` are
    /// covered by `revealed` arbitrary distinct values of `0..t`.
    ///
    /// This is equal to `choose(k, revealed) / choose(k, t)`, which simplifies
    /// to:
    /// `revealed! / (k! (revealed - k)!) * (k! (t - k)!) / t!`
    /// `revealed! / (revealed - k)! * (t - k)! / t!`
    ///
    /// See https://eprint.iacr.org/2017/909, section 6.2.
    fn cover_pors(k: u32, t: u32, revealed: u32) -> T {
        assert!(k <= t);
        if revealed < k {
            return T::zero();
        } else if revealed >= t {
            return T::one();
        }
        let mut res = T::one();
        for i in 0..k {
            res *= T::from(revealed - i) / T::from(t - i);
        }
        res
    }

    /// Returns an upper bound of the success probability of an attacker making
    /// `2^q` queries against a PORS construction with `k` values chosen among
    /// `t`, on a hyper-tree of height `h`.
    ///
    /// Contrary to [`Self::pors`], this version doesn't bound the number of
    /// revealed values after `r` signatures as `k * r`, but rather computes the
    /// exact distribution, assuming all signatures sample the `k` values
    /// uniformly (i.e. using vanilla PORS without forced pruning).
    ///
    /// See https://eprint.iacr.org/2017/909.
    fn pors_precise(&mut self, k: u32, t: u32, h: u32, q: u32) -> T {
        let kr_max = (k * self.rmax).min(t);

        let size_table = self.pors_size_table(k, t);
        let choose_kt = Self::choose_impl(k, t);
        let mut choose_kt_power = I::one();

        // Table of `cover_pors(k, t, revealed)`, scaled by `choose(k, t)`.
        let cover_pors_table: Vec<I> = (0..=kr_max)
            .map(|revealed| Self::choose_impl(k, revealed))
            .collect();

        let rate = T::from_log2(q) / T::from_log2(h);

        let mut res = T::zero();
        for r in 0..=self.rmax {
            let cover: I = (0..=(k * r).min(t) as usize)
                .map(|revealed| {
                    // Each term here is scaled by `choose(k, t) * choose(k, t)^r`...
                    &cover_pors_table[revealed]
                        * size_table[[r as usize, revealed]].as_ref().unwrap()
                })
                .sum();
            // ...so we divide by `choose(k, t)^(r + 1)`.
            choose_kt_power *= &choose_kt;
            let cover = T::from_ratio(cover, choose_kt_power.clone());

            let poisson = Self::weight_poisson(&mut self.weight_poisson, r, h, q, &rate);
            eprint!("r={r}: {} * {}", cover.to_f64_log2(), poisson.to_f64_log2());
            let product = cover * poisson;
            eprint!(" = {}", product.to_f64_log2());
            res += product;
            eprintln!(" -> {}", res.to_f64_log2());
        }
        res
    }

    /// Returns a probability table indexed by `0 <= i <= min(k * r_max, t)` and
    /// `0 <= j <= k` that contains in each cell the probability that: when
    /// choosing `k` distinct values uniformly at random in `0..t`, `j` of those
    /// overlap with `i` already revealed values.
    ///
    /// Each value is scaled by `choose(k, t)`.
    fn overlap_table(&self, k: u32, t: u32) -> Table2d<I> {
        let kr_max = (k * self.rmax).min(t);

        let mut table = Table2d::new([kr_max as usize + 1, k as usize + 1]);
        for i in 0..=kr_max {
            let mut sum = I::zero();
            for j in 0..=k {
                // The real probability is this value divided by `choose(k, t)`, but we let the
                // caller divide once at the end, which allows working on big integers rather
                // than big rationals, which is much faster.
                let value = Self::choose_impl(j, i) * Self::choose_impl(k - j, t - i);
                sum += &value;
                if !value.is_zero() {
                    eprintln!("  overlap[{t}, {k}, {i}, {j}] = {}", value.to_f64_log2());
                }
                table[[i as usize, j as usize]] = Some(value);
            }
            eprintln!(" overlap[{t}, {k}, {i}] = {}", sum.to_f64_log2());
        }
        table
    }

    /// Returns a probability table where `table[(r, i)]` contains the
    /// probability that after `r` signatures following the PORS construction
    /// (i.e. `r` samples each containing `k` distinct uniform values among
    /// `0..t`) the number of revealed values is `i`.
    ///
    /// Each value is scaled by `choose(k, t)^r`.
    fn pors_size_table(&self, k: u32, t: u32) -> Table2d<I> {
        let kr_max = (k * self.rmax).min(t);

        let overlap_table = self.overlap_table(k, t);

        let mut table = Table2d::new([self.rmax as usize + 1, kr_max as usize + 1]);
        // Initial case: with zero previous signatures, exactly zero values have been
        // revealed.
        table[[0, 0]] = Some(I::one());
        for i in 1..=kr_max as usize {
            table[[0, i]] = Some(I::zero());
        }

        // Other cases by recursion on `r`.
        for r in 1..=self.rmax as usize {
            for i in 0..=kr_max as usize {
                table[[r, i]] = Some(I::zero());
            }

            for i in 0..=kr_max as usize {
                if table[[r - 1, i]].as_ref().unwrap().is_zero() {
                    continue;
                }
                for j in 0..=k as usize {
                    // Ignore indices beyond the threshold. This case can happen if `k * rmax > t`.
                    if i + j > kr_max as usize {
                        continue;
                    }
                    // Each value in `overlap_table` is scaled by `choose(k, t)`, so this is scaled
                    // by `choose(k, t)^r`.
                    let p = table[[r - 1, i]].as_ref().unwrap()
                        * overlap_table[[i, k as usize - j]].as_ref().unwrap();
                    *table[[r, i + j]].as_mut().unwrap() += p;
                }
            }

            // For debugging.
            for i in 0..=kr_max as usize {
                let value = table[[r, i]].as_mut().unwrap();
                if !value.is_zero() {
                    eprintln!("  size_table[{t}, {k}, {r}, {i}] = {}", value.to_f64_log2());
                }
            }
        }

        table
    }

    /// See https://eprint.iacr.org/2026/1328.
    #[expect(non_snake_case)]
    fn bpors(&mut self, k: u32, t: u32, K: u32, B: u32, h: u32, q: u32) -> T {
        let rate = T::from_log2(q) / T::from_log2(h);

        let mut pors_table = vec![None; self.rmax as usize + 1];

        let mut res = T::zero();
        for r in 0..=self.rmax {
            let subcover = self.cover_bpors(&mut pors_table, k, t, B, r);
            eprintln!("r={r}: {}^{K}", subcover.to_f64_log2());
            let cover = subcover.powi(K);

            let poisson = Self::weight_poisson(&mut self.weight_poisson, r, h, q, &rate);
            eprint!("r={r}: {} * {}", cover.to_f64_log2(), poisson.to_f64_log2());
            let product = cover * poisson;
            eprint!(" = {}", product.to_f64_log2());
            res += product;
            eprintln!(" -> {}", res.to_f64_log2());
        }
        res
    }

    #[expect(non_snake_case)]
    fn cover_bpors(&mut self, pors_table: &mut [Option<T>], k: u32, t: u32, B: u32, r: u32) -> T {
        (0..=r)
            .map(|rr| {
                let binom = Self::binom_power(&mut self.binom_power, B, rr)
                    * Self::binom_opposite_power(&mut self.binom_opposite_power, B, r - rr)
                    * Self::choose(&mut self.choose, rr, r);
                let subcover = &mut pors_table[rr as usize];
                if subcover.is_none() {
                    *subcover = Some(Self::cover_pors(k, t, k * rr));
                }
                let subcover = subcover.as_ref().unwrap();
                eprint!(
                    "  rr={rr}: {} * {}",
                    subcover.to_f64_log2(),
                    binom.to_f64_log2()
                );
                let product = binom * subcover;
                eprintln!(" = {}", product.to_f64_log2());
                product
            })
            .sum()
    }

    fn choose(table: &mut Table2d<I>, n: u32, among: u32) -> &I {
        let x = &mut table[[n as usize, among as usize]];
        if x.is_none() {
            let value = Self::choose_impl(n, among);
            *x = Some(value);
        }
        x.as_ref().unwrap()
    }

    fn choose_impl(n: u32, among: u32) -> I {
        I::choose(n, among)
    }

    /// Returns 2^(-B * r)
    #[expect(non_snake_case)]
    fn binom_power(table: &mut Table2d<T>, B: u32, r: u32) -> &T {
        let x = &mut table[[B as usize, r as usize]];
        if x.is_none() {
            let value = (T::one() / T::from_log2(B)).powi(r);
            *x = Some(value);
        }
        x.as_ref().unwrap()
    }

    /// Returns (1 - 2^-B)^r
    #[expect(non_snake_case)]
    fn binom_opposite_power(table: &mut Table2d<T>, B: u32, r: u32) -> &T {
        let x = &mut table[[B as usize, r as usize]];
        if x.is_none() {
            let value = (T::one() / T::from_log2(B)).one_minus_x().powi(r);
            *x = Some(value);
        }
        x.as_ref().unwrap()
    }

    /// Probability that a Poisson distribution of parameter `rate = 2^(q - h)`
    /// is equal to `r`.
    fn weight_poisson<'a>(table: &'a mut Table3d<T>, r: u32, h: u32, q: u32, rate: &T) -> &'a T {
        let index = [h as usize, q as usize, r as usize];
        if table[index].is_none() {
            let value = Self::weight_poisson_impl(table, r, h, q, rate);
            table[index] = Some(value);
        }
        table[index].as_ref().unwrap()
    }

    fn weight_poisson_impl(table: &mut Table3d<T>, r: u32, h: u32, q: u32, rate: &T) -> T {
        if r == 0 {
            T::one() / T::exp(rate)
        } else {
            Self::weight_poisson(table, r - 1, h, q, rate) * rate / T::from(r)
        }
    }
}

trait Integer:
    Mul<Output = Self>
    + Div<Output = Self>
    + AddAssign
    + MulAssign
    + Sum
    + for<'a> AddAssign<&'a Self>
    + for<'a> MulAssign<&'a Self>
{
    fn zero() -> Self;

    fn one() -> Self;

    fn is_zero(&self) -> bool;

    fn from(x: u32) -> Self;

    fn choose(n: u32, among: u32) -> Self {
        if n > among {
            return Self::zero();
        }
        let mut res = Self::one();
        for i in 0..n {
            res *= Self::from(among - i) / Self::from(i + 1);
        }
        res
    }

    fn to_f64_log2(&self) -> f64;
}

trait Rational<I: Integer>:
    Mul<Output = Self>
    + Div<Output = Self>
    + Sub<Output = Self>
    + AddAssign
    + MulAssign
    + DivAssign
    + Sum
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> Div<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + for<'a> MulAssign<&'a Self>
    + for<'a> Mul<&'a I, Output = Self>
{
    fn from_ratio(num: I, denom: I) -> Self;

    fn zero() -> Self;

    fn one() -> Self;

    fn from(x: u32) -> Self;

    fn from_log2(x: u32) -> Self;

    fn to_f64(&self) -> f64;

    fn to_f64_log2(&self) -> f64;

    fn powi(&self, n: u32) -> Self;

    fn one_minus_x(&self) -> Self;

    fn exp(&self) -> Self;
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

impl Sub for F64Log2 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        assert!(self.0 >= rhs.0);
        if rhs.0 == f64::NEG_INFINITY {
            self
        } else {
            F64Log2(self.0 + (-(2.0_f64.powf(rhs.0 - self.0))).ln_1p() / std::f64::consts::LN_2)
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

impl MulAssign<&Self> for F64Log2 {
    #[expect(clippy::suspicious_op_assign_impl)]
    fn mul_assign(&mut self, rhs: &Self) {
        self.0 += rhs.0;
    }
}

impl DivAssign for F64Log2 {
    #[expect(clippy::suspicious_op_assign_impl)]
    fn div_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl Sum for F64Log2 {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = Self>,
    {
        iter.fold(<Self as Rational<Self>>::zero(), |acc, x| acc + x)
    }
}

impl Integer for F64Log2 {
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

    fn to_f64_log2(&self) -> f64 {
        self.0
    }
}

impl Rational<F64Log2> for F64Log2 {
    fn from_ratio(num: F64Log2, denom: F64Log2) -> Self {
        num / denom
    }

    fn zero() -> Self {
        F64Log2(f64::NEG_INFINITY)
    }

    fn one() -> Self {
        F64Log2(0.0)
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

    fn powi(&self, n: u32) -> Self {
        F64Log2(n as f64 * self.0)
    }

    fn one_minus_x(&self) -> Self {
        F64Log2((-(2.0_f64.powf(self.0))).ln_1p() / std::f64::consts::LN_2)
    }

    fn exp(&self) -> Self {
        F64Log2(2.0_f64.powf(self.0) / std::f64::consts::LN_2)
    }
}

impl Integer for BigInt {
    fn zero() -> Self {
        <BigInt as Zero>::zero()
    }

    fn one() -> Self {
        <BigInt as One>::one()
    }

    fn is_zero(&self) -> bool {
        Zero::is_zero(self)
    }

    fn from(x: u32) -> Self {
        x.into()
    }

    fn choose(n: u32, among: u32) -> Self {
        if n > among {
            return <Self as Integer>::zero();
        }

        let mut num = <Self as Integer>::one();
        for i in 0..n {
            num *= <Self as Integer>::from(among - i);
        }

        let mut denom = <Self as Integer>::one();
        for i in 0..n {
            denom *= <Self as Integer>::from(i + 1);
        }

        num / denom
    }

    fn to_f64_log2(&self) -> f64 {
        match self.sign() {
            Sign::Minus => f64::NAN,
            Sign::NoSign => f64::NEG_INFINITY,
            Sign::Plus => biguint_log2(self.magnitude()),
        }
    }
}

fn biguint_log2(x: &BigUint) -> f64 {
    let bits = x.bits();
    if bits == 0 {
        return f64::NEG_INFINITY;
    }

    if bits <= 64 {
        x.to_f64().unwrap().log2()
    } else {
        let shift = bits - 64;
        (x >> shift).to_f64().unwrap().log2() + (shift as f64)
    }
}

impl Rational<BigInt> for BigRational {
    fn from_ratio(num: BigInt, denom: BigInt) -> Self {
        BigRational::new(num, denom)
    }

    fn zero() -> Self {
        <BigRational as Zero>::zero()
    }

    fn one() -> Self {
        <BigRational as One>::one()
    }

    fn from(x: u32) -> Self {
        BigRational::from_integer(<BigInt as Integer>::from(x))
    }

    fn from_log2(x: u32) -> Self {
        BigRational::from_integer(<BigInt as Integer>::one() << x)
    }

    fn to_f64(&self) -> f64 {
        ToPrimitive::to_f64(self).unwrap()
    }

    fn to_f64_log2(&self) -> f64 {
        Rational::to_f64(self).log2()
    }

    fn powi(&self, n: u32) -> Self {
        self.pow(n.try_into().unwrap())
    }

    fn one_minus_x(&self) -> Self {
        <BigRational as One>::one() - self
    }

    fn exp(&self) -> Self {
        BigRational::from_float(Rational::to_f64(self).exp()).unwrap()
    }
}

type Table2d<T> = ndtable::Table2d<Option<T>>;
type Table3d<T> = ndtable::Table3d<Option<T>>;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_f64log2_add() {
        assert_eq!(
            (<F64Log2 as Integer>::zero() + <F64Log2 as Integer>::zero()).to_f64(),
            0.0
        );
        assert_eq!(
            (<F64Log2 as Integer>::zero() + <F64Log2 as Integer>::one()).to_f64(),
            1.0
        );
        assert_eq!(
            (<F64Log2 as Integer>::one() + <F64Log2 as Integer>::zero()).to_f64(),
            1.0
        );
        assert_eq!(
            (<F64Log2 as Integer>::one() + <F64Log2 as Integer>::one()).to_f64(),
            2.0
        );
        assert_eq!(
            (<F64Log2 as Integer>::from(2) + <F64Log2 as Integer>::from(2)).to_f64(),
            4.0
        );
        assert_eq!(
            Integer::to_f64_log2(&(<F64Log2 as Integer>::from(2) + <F64Log2 as Integer>::from(3))),
            5.0_f64.log2()
        );
        assert_eq!(
            Integer::to_f64_log2(
                &(<F64Log2 as Integer>::from(2).powi(10_000) + <F64Log2 as Integer>::from(2))
            ),
            10_000.0
        );
        assert_eq!(
            Integer::to_f64_log2(
                &(<F64Log2 as Integer>::from(2) + <F64Log2 as Integer>::from(2).powi(10_000))
            ),
            10_000.0
        );
    }

    #[test]
    fn test_f64log2_powi() {
        for i in 0..=10_000 {
            assert_eq!(
                Integer::to_f64_log2(&<F64Log2 as Integer>::from(2).powi(i)),
                i as f64
            );
            assert_eq!(
                Integer::to_f64_log2(
                    &(<F64Log2 as Integer>::one() / <F64Log2 as Integer>::from(2)).powi(i)
                ),
                -(i as f64)
            );
        }
    }
}
