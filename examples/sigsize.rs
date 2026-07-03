use num::{BigInt, BigRational, ToPrimitive};
use std::fmt::Debug;
use std::iter::Sum;
use std::ops::{AddAssign, Div, Index, IndexMut, Mul, MulAssign};

fn main() {
    octopus_size_distribution::<F64Log2>(16, 24);
    println!("****************************************");
    octopus_size_distribution::<F64Log2>(16, 32);
    println!("****************************************");
    octopus_size_distribution::<F64Log2>(16, 28);
    println!("****************************************");

    octopus_size_distribution::<F64Log2>(16, 14);
    println!("****************************************");
    octopus_size_distribution::<F64Log2>(25, 9);
    println!("****************************************");

    octopus_size_distribution::<BigRational>(16, 24);
    println!("****************************************");
    octopus_size_distribution::<BigRational>(16, 32);
    println!("****************************************");
    octopus_size_distribution::<BigRational>(16, 28);
    println!("****************************************");

    octopus_size_distribution::<BigRational>(16, 14);
    println!("****************************************");
    octopus_size_distribution::<BigRational>(25, 9);
    println!("****************************************");

    octopus_size_cutoff::<F64Log2>(16, 24, -10.0);
    octopus_size_cutoff::<F64Log2>(16, 32, -14.0);
    octopus_size_cutoff::<F64Log2>(16, 28, -12.0);

    octopus_size_cutoff::<F64Log2>(16, 14, -12.0);
    octopus_size_cutoff::<F64Log2>(25, 9, -20.0);

    octopus_size_cutoff::<BigRational>(16, 24, -10.0);
    octopus_size_cutoff::<BigRational>(16, 32, -14.0);
    octopus_size_cutoff::<BigRational>(16, 28, -12.0);

    octopus_size_cutoff::<BigRational>(16, 14, -12.0);
    octopus_size_cutoff::<BigRational>(25, 9, -20.0);

    octopus_size_bpors_distribution::<F64Log2>(7, 5, 1, 8);
    println!("****************************************");
    octopus_size_bpors_distribution::<F64Log2>(7, 5, 8, 6);
    println!("****************************************");

    octopus_size_bpors_distribution::<BigRational>(7, 5, 1, 8);
    println!("****************************************");
    octopus_size_bpors_distribution::<BigRational>(7, 5, 8, 6);
    println!("****************************************");
}

/// Computes the size distribution of a bucketized PORS Octopus (BPORS) as
/// described in https://eprint.iacr.org/2026/1328.
#[expect(non_snake_case)]
fn octopus_size_bpors_distribution<T>(h: u32, k: u32, B: u32, K: u32)
where
    T: Arithmetic + Debug + Clone,
    for<'a> &'a T: Mul<&'a T, Output = T>,
{
    let mut mem: Memoized<T> = Memoized::new(k as usize, h as usize);

    let mut baseline = Vec::new();
    for m in 0..=k * h {
        let p = mem.size(h, k, m);
        if !p.is_zero() {
            println!("base size({h}, {k}, {m}) = {}", p.to_f64_log2(),);
            baseline.resize_with(m as usize, T::zero);
            baseline.push(p.clone());
        }
    }

    let distribution = convoluted_exponent(&baseline, K);
    let mut sum = T::zero();
    for (i, p) in distribution.iter().enumerate() {
        let m = i as u32 + K * B;
        sum += p;
        if !p.is_zero() {
            println!(
                "product size({h}, {k}, {K}, {m}) = {} | {} | {}",
                p.to_f64_log2(),
                sum.to_f64_log2(),
                sum.to_f64()
            );
        }
    }
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

/// Computes the size distribution of a PORS Octopus as described in
/// https://eprint.iacr.org/2025/2069.
fn octopus_size_distribution<T>(h: u32, k: u32)
where
    T: Arithmetic + Debug + Clone,
    for<'a> &'a T: Mul<&'a T, Output = T>,
{
    let mut mem: Memoized<T> = Memoized::new(k as usize, h as usize);

    let mut sum = T::zero();
    for m in 0..=k * h {
        let p = mem.size(h, k, m);
        sum += p;
        if !p.is_zero() {
            println!(
                "size({h}, {k}, {m}) = {} | {}",
                p.to_f64_log2(),
                sum.to_f64_log2()
            );
        }
    }
}

fn octopus_size_cutoff<T>(h: u32, k: u32, threshold: f64)
where
    T: Arithmetic + Debug + Clone,
    for<'a> &'a T: Mul<&'a T, Output = T>,
{
    let mut mem: Memoized<T> = Memoized::new(k as usize, h as usize);

    let mut sum = T::zero();
    for m in 0..=k * h {
        let p = mem.size(h, k, m);
        sum += p;
        if sum.to_f64_log2() >= threshold {
            println!(
                "P(size({h}, {k}) <= {m}) = 2^{} | {}",
                sum.to_f64_log2(),
                sum.to_f64()
            );
            break;
        }
    }
}

struct Memoized<T> {
    choose: Vec2d<T>,
    choose_h: Vec2d<T>,
    siblings: Vec3d<T>,
    size: Vec3d<T>,
}

impl<T: Clone> Memoized<T> {
    fn new(k: usize, h: usize) -> Self {
        Self {
            choose: Vec2d::new((k + 1, k + 1)),
            choose_h: Vec2d::new((k + 1, h + 1)),
            siblings: Vec3d::new((h + 1, k + 1, k + 1)),
            size: Vec3d::new((h + 1, k + 1, k * h + 1)),
        }
    }
}

impl<T> Memoized<T>
where
    T: Arithmetic,
    for<'a> &'a T: Mul<&'a T, Output = T>,
{
    fn size(&mut self, h: u32, k: u32, m: u32) -> &T {
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

    fn size_inner<'a>(
        size_table: &'a mut Vec3d<T>,
        siblings_table: &mut Vec3d<T>,
        choose_table: &mut Vec2d<T>,
        choose_h_table: &mut Vec2d<T>,
        h: u32,
        k: u32,
        m: u32,
    ) -> &'a T {
        let index = (h as usize, k as usize, m as usize);
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
        size_table: &mut Vec3d<T>,
        siblings_table: &mut Vec3d<T>,
        choose_table: &mut Vec2d<T>,
        choose_h_table: &mut Vec2d<T>,
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
        siblings_table: &'a mut Vec3d<T>,
        choose_table: &mut Vec2d<T>,
        choose_h_table: &mut Vec2d<T>,
        h: u32,
        k: u32,
        s: u32,
    ) -> &'a T {
        let index = (h as usize, k as usize, s as usize);
        if siblings_table[index].is_none() {
            let value = Self::siblings_impl(choose_table, choose_h_table, h, k, s);
            siblings_table[index] = Some(value);
        }
        siblings_table[index].as_ref().unwrap()
    }

    fn siblings_impl(
        choose_table: &mut Vec2d<T>,
        choose_h_table: &mut Vec2d<T>,
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

    fn choose(table: &mut Vec2d<T>, n: u32, among: u32) -> &T {
        let x = &mut table[(n as usize, among as usize)];
        if x.is_none() {
            let value = Self::choose_impl(n, among);
            *x = Some(value);
        }
        x.as_ref().unwrap()
    }

    fn choose_h(table: &mut Vec2d<T>, n: u32, among_h: u32) -> &T {
        let x = &mut table[(n as usize, among_h as usize)];
        if x.is_none() {
            let value = Self::choose_impl(n, 1 << among_h);
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
        *self == Self::zero()
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
