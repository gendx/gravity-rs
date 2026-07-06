use num::{BigInt, BigRational, ToPrimitive};
use std::fmt::Debug;
use std::iter::Sum;
use std::ops::{AddAssign, Div, DivAssign, Index, IndexMut, Mul, MulAssign, Sub};

fn main() {
    let mut mem: Memoized<F64Log2> = Memoized::new(50, 10);
    mem.evaluate();

    let mut mem: Memoized<BigRational> = Memoized::new(50, 10);
    mem.evaluate();
}

struct Memoized<T> {
    weight_poisson: Vec3d<T>,
    choose: Vec2d<T>,
    binom_power: Vec2d<T>,
    binom_opposite_power: Vec2d<T>,
    rmax: u32,
}

impl<T: Clone> Memoized<T> {
    fn new(rmax: u32, bmax: usize) -> Self {
        Self {
            weight_poisson: Vec3d::new((70, 70, rmax as usize + 1)),
            choose: Vec2d::new((rmax as usize + 1, rmax as usize + 1)),
            binom_power: Vec2d::new((bmax + 1, rmax as usize + 1)),
            binom_opposite_power: Vec2d::new((bmax + 1, rmax as usize + 1)),
            rmax,
        }
    }
}

impl<T> Memoized<T>
where
    T: Arithmetic + Debug + Clone,
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
    }

    fn slh_dsa_variants(&mut self, title: &str, k: u32, t: u32, h: u32, q: u32) {
        println!("- {title}: {}", self.fors(k, t, h, q).to_f64_log2());
        println!(
            "- {title} (PORS): {}",
            self.pors(k, k << t, h, q).to_f64_log2()
        );
    }

    /// Returns an upper bound of the success probability of an attacker making
    /// `2^q` queries against a FORS construction with `k` trees of height
    /// `t`, on a hyper-tree of height `h`.
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
            let cover = Self::cover_pors(k, t, r);
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
    /// covered by `k * r` arbitrary distinct values of `0..t`.
    ///
    /// This is equal to `choose(k, k * r) / choose(k, t)`, which simplifies to:
    /// `(kr)! / (k! (kr - k)!) * (k! (t - k)!) / t!`
    /// `(kr)! / (kr - k)! * (t - k)! / t!`
    ///
    /// See https://eprint.iacr.org/2017/909, section 6.2.
    fn cover_pors(k: u32, t: u32, r: u32) -> T {
        assert!(k <= t);
        if r == 0 {
            return T::zero();
        }
        let mut res = T::one();
        for i in 0..k {
            res *= T::from(k * r - i) / T::from(t - i);
        }
        res
    }

    /// See https://eprint.iacr.org/2026/1328.
    #[expect(non_snake_case)]
    fn bpors(&mut self, k: u32, t: u32, K: u32, B: u32, h: u32, q: u32) -> T {
        let rate = T::from_log2(q) / T::from_log2(h);

        let mut pors_table = vec![None; self.rmax as usize + 1];

        let mut res = T::zero();
        for r in 0..=self.rmax {
            let subcover = self.cover_bpors(&mut pors_table, k, t, B, r);
            eprint!("r={r}: {}^{K}", subcover.to_f64_log2());
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
                let binom = Self::choose(&mut self.choose, rr, r)
                    * Self::binom_power(&mut self.binom_power, B, rr)
                    * Self::binom_opposite_power(&mut self.binom_opposite_power, B, r - rr);
                let subcover = &mut pors_table[rr as usize];
                if subcover.is_none() {
                    *subcover = Some(Self::cover_pors(k, t, rr));
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

    fn choose(table: &mut Vec2d<T>, n: u32, among: u32) -> &T {
        let x = &mut table[(n as usize, among as usize)];
        if x.is_none() {
            let value = Self::choose_impl(n, among);
            *x = Some(value);
        }
        x.as_ref().unwrap()
    }

    fn choose_impl(n: u32, among: u32) -> T {
        if n > among {
            return T::zero();
        }
        let mut res = T::one();
        for i in 0..n {
            res *= T::from(among - i) / T::from(i + 1);
        }
        res
    }

    /// Returns 2^(-B * r)
    #[expect(non_snake_case)]
    fn binom_power(table: &mut Vec2d<T>, B: u32, r: u32) -> &T {
        let x = &mut table[(B as usize, r as usize)];
        if x.is_none() {
            let value = (T::one() / T::from_log2(B)).powi(r);
            *x = Some(value);
        }
        x.as_ref().unwrap()
    }

    /// Returns (1 - 2^-B)^r
    #[expect(non_snake_case)]
    fn binom_opposite_power(table: &mut Vec2d<T>, B: u32, r: u32) -> &T {
        let x = &mut table[(B as usize, r as usize)];
        if x.is_none() {
            let value = (T::one() / T::from_log2(B)).one_minus_x().powi(r);
            *x = Some(value);
        }
        x.as_ref().unwrap()
    }

    /// Probability that a Poisson distribution of parameter `rate = 2^(q - h)`
    /// is equal to `r`.
    fn weight_poisson<'a>(table: &'a mut Vec3d<T>, r: u32, h: u32, q: u32, rate: &T) -> &'a T {
        let index = (h as usize, q as usize, r as usize);
        if table[index].is_none() {
            let value = Self::weight_poisson_impl(table, r, h, q, rate);
            table[index] = Some(value);
        }
        table[index].as_ref().unwrap()
    }

    fn weight_poisson_impl(table: &mut Vec3d<T>, r: u32, h: u32, q: u32, rate: &T) -> T {
        if r == 0 {
            T::one() / T::exp(rate)
        } else {
            Self::weight_poisson(table, r - 1, h, q, rate) * rate / T::from(r)
        }
    }
}

trait Arithmetic:
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
{
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

impl Sub for F64Log2 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        F64Log2((2.0_f64.powf(self.0) - 2.0_f64.powf(rhs.0)).log2())
    }
}

impl AddAssign for F64Log2 {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = (2.0_f64.powf(self.0) + 2.0_f64.powf(rhs.0)).log2();
    }
}

impl AddAssign<&Self> for F64Log2 {
    fn add_assign(&mut self, rhs: &Self) {
        self.0 = (2.0_f64.powf(self.0) + 2.0_f64.powf(rhs.0)).log2();
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
        F64Log2(iter.fold(0.0, |acc, x| acc + 2.0_f64.powf(x.0)).log2())
    }
}

impl Arithmetic for F64Log2 {
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

impl Arithmetic for BigRational {
    fn zero() -> Self {
        BigRational::from_integer(BigInt::from(0))
    }

    fn one() -> Self {
        BigRational::from_integer(BigInt::from(1))
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

    fn powi(&self, n: u32) -> Self {
        self.pow(n.try_into().unwrap())
    }

    fn one_minus_x(&self) -> Self {
        Self::one() - self
    }

    fn exp(&self) -> Self {
        BigRational::from_float(Arithmetic::to_f64(self).exp()).unwrap()
    }
}

struct Vec2d<T> {
    size: (usize, usize),
    matrix: Vec<Option<T>>,
}

impl<T: Clone> Vec2d<T> {
    fn new(size: (usize, usize)) -> Self {
        Self {
            size,
            matrix: vec![None; size.0 * size.1],
        }
    }
}

impl<T> Index<(usize, usize)> for Vec2d<T> {
    type Output = Option<T>;

    fn index(&self, index: (usize, usize)) -> &Self::Output {
        assert!(
            index.0 < self.size.0,
            "{} < {} for index.0",
            index.0,
            self.size.0
        );
        assert!(
            index.1 < self.size.1,
            "{} < {} for index.1",
            index.1,
            self.size.1
        );
        &self.matrix[index.0 + self.size.0 * index.1]
    }
}

impl<T> IndexMut<(usize, usize)> for Vec2d<T> {
    fn index_mut(&mut self, index: (usize, usize)) -> &mut Self::Output {
        assert!(
            index.0 < self.size.0,
            "{} < {} for index.0",
            index.0,
            self.size.0
        );
        assert!(
            index.1 < self.size.1,
            "{} < {} for index.1",
            index.1,
            self.size.1
        );
        &mut self.matrix[index.0 + self.size.0 * index.1]
    }
}

struct Vec3d<T> {
    size: (usize, usize, usize),
    matrix: Vec<Option<T>>,
}

impl<T: Clone> Vec3d<T> {
    fn new(size: (usize, usize, usize)) -> Self {
        Self {
            size,
            matrix: vec![None; size.0 * size.1 * size.2],
        }
    }
}

impl<T> Index<(usize, usize, usize)> for Vec3d<T> {
    type Output = Option<T>;

    fn index(&self, index: (usize, usize, usize)) -> &Self::Output {
        assert!(
            index.0 < self.size.0,
            "{} < {} for index.0",
            index.0,
            self.size.0
        );
        assert!(
            index.1 < self.size.1,
            "{} < {} for index.1",
            index.1,
            self.size.1
        );
        assert!(
            index.2 < self.size.2,
            "{} < {} for index.2",
            index.2,
            self.size.2
        );
        &self.matrix[index.0 + self.size.0 * (index.1 + self.size.1 * index.2)]
    }
}

impl<T> IndexMut<(usize, usize, usize)> for Vec3d<T> {
    fn index_mut(&mut self, index: (usize, usize, usize)) -> &mut Self::Output {
        assert!(
            index.0 < self.size.0,
            "{} < {} for index.0",
            index.0,
            self.size.0
        );
        assert!(
            index.1 < self.size.1,
            "{} < {} for index.1",
            index.1,
            self.size.1
        );
        assert!(
            index.2 < self.size.2,
            "{} < {} for index.2",
            index.2,
            self.size.2
        );
        &mut self.matrix[index.0 + self.size.0 * (index.1 + self.size.1 * index.2)]
    }
}
