use num::traits::Pow;
use num::{BigInt, BigRational, One, ToPrimitive, Zero};
use smart_big_rational::{
    Denom, DenomRef, DenomSparseU16, SmartBigRational as SmartBigRationalImpl,
};
use std::fmt;
use std::fmt::Debug;
use std::iter::Sum;
use std::marker::PhantomData;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub};

type Table2d<T> = ndtable::Table2d<Option<T>>;
type Table3d<T> = ndtable::Table3d<Option<T>>;
type SmartBigRational = SmartBigRationalImpl<DenomSparseU16<6542, 16>>;

fn main() {
    let mut mem: Memoized<F64Log2, F64Log2> = Memoized::new(/* max(r) */ 50);
    mem.evaluate();

    let mut mem: Memoized<BigInt, SmartBigRational> = Memoized::new(/* max(r) */ 50);
    mem.evaluate();
}

struct Memoized<I, T> {
    weight_poisson: Table3d<T>,
    choose: Table2d<I>,
    binom_t: Table2d<T>,
    rmax: u32,
}

impl<I: Clone, T: Clone> Memoized<I, T> {
    fn new(rmax: u32) -> Self {
        Self {
            weight_poisson: Table3d::new([70, 70, rmax as usize + 1]),
            choose: Table2d::new([rmax as usize + 1, rmax as usize + 1]),
            binom_t: Table2d::new([rmax as usize + 1, rmax as usize + 1]),
            rmax,
        }
    }
}

impl<I, T> Memoized<I, T>
where
    I: Integer + Clone,
    T: Rational<I> + Debug + Default + Clone,
    for<'a> &'a I: Mul<&'a I, Output = I>,
    for<'a> &'a T: Mul<&'a T, Output = T>,
{
    fn evaluate(&mut self) {
        // Parameters from https://eprint.iacr.org/2026/2502.pdf, table 5.
        self.evaluate_base_gs("128s", 3, 10, 5, 1, 0, 63, 64);
        self.evaluate_base_gs("192s", 6, 12, 6, 1, 0, 63, 64);
        self.evaluate_base_gs("256s", 3, 17, 6, 1, 0, 64, 64);
        self.evaluate_base_gs("128f", 2, 5, 2, 7, 1, 66, 64);
        self.evaluate_base_gs("192f", 4, 34, 3, 1, 0, 66, 64);
        self.evaluate_base_gs("256f", 3, 6, 3, 6, 1, 68, 64);
        self.evaluate_base_gs("128-224", 3, 5, 7, 1, 5, 22, 24);
        self.evaluate_base_gs("192-224", 7, 8, 7, 1, 6, 21, 24);
        self.evaluate_base_gs("256-224", 9, 11, 7, 1, 8, 21, 24);
    }

    #[expect(non_snake_case, unused_variables, clippy::too_many_arguments)]
    fn evaluate_base_gs(
        &mut self,
        title: &str,
        u: u32,
        r: u32,
        L: u32,
        K: u32,
        b: u32,
        h: u32,
        q: u32,
    ) {
        self.binom_t = Table2d::new([self.rmax as usize + 1, self.rmax as usize + 1]);
        println!(
            "- {title}: base_gs(2^{u}, {r}, 2^{L}, 2^{h}, 2^{q}) = 2^{}",
            self.base_gs(u, r, L, h, q).to_f64_log2()
        );
    }

    /// Returns an upper bound of the success probability of an attacker making
    /// `2^q` queries against a baseline GS construction with `2^u` owners, `r`
    /// layers of height `l`, on a hyper-tree of height `h`.
    ///
    /// See https://sphincs.org/data/sphincs+-r3.1-specification.pdf.
    #[expect(non_snake_case)]
    fn base_gs(&mut self, u: u32, r: u32, L: u32, h: u32, q: u32) -> T {
        let rate = T::from_log2(q) / T::from_log2(h);

        let mut res = T::zero();
        for rr in 0..=self.rmax {
            let cover = self.gs_cover(1 << u, r, 1 << L, rr);
            let poisson = Self::weight_poisson(&mut self.weight_poisson, rr, h, q, &rate);
            eprint!(
                "rr={rr}: {} * {}",
                cover.to_f64_log2(),
                poisson.to_f64_log2()
            );
            let product = cover * poisson;
            eprint!(" = {}", product.to_f64_log2());
            res += product;
            eprintln!(" -> {}", res.to_f64_log2());
        }
        res.reduced()
    }

    fn gs_cover(&mut self, o: u32, r: u32, t: u32, q: u32) -> T {
        let tt = T::one() / T::from(t);
        let one_minus_tt = tt.one_minus_x();

        let matrix_q: Matrix<I, T> = Matrix::generate(q, |i, j| {
            let i = i + 1;
            let j = j + 1;
            ((i + j).saturating_sub(q).max(1)..=i.min(j))
                .map(|v| {
                    assert!(v <= j);
                    assert!(i <= q);
                    assert!(v <= i);
                    assert!(j - v <= q - i);
                    Self::binom(
                        &mut self.binom_t,
                        &mut self.choose,
                        v,
                        i,
                        &tt,
                        &one_minus_tt,
                    )
                    .clone()
                        * Self::binom(
                            &mut self.binom_t,
                            &mut self.choose,
                            j - v,
                            q - i,
                            &tt,
                            &one_minus_tt,
                        )
                })
                .sum::<T>()
        });
        let matrix_qr = matrix_q.powi(r);

        let oo = T::one() / T::from(o);
        let one_minus_oo = oo.one_minus_x();
        (0..q)
            .map(|i| {
                (0..q)
                    .map(|j| matrix_qr.data[[i as usize, j as usize]].clone())
                    .sum::<T>()
                    * Self::binom_impl(&mut self.choose, i + 1, q, &oo, &one_minus_oo)
            })
            .sum::<T>()
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

    fn binom<'a>(
        table: &'a mut Table2d<T>,
        choose_table: &mut Table2d<I>,
        n: u32,
        among: u32,
        rate: &T,
        one_minus_rate: &T,
    ) -> &'a T {
        let x = &mut table[[n as usize, among as usize]];
        if x.is_none() {
            let value = Self::binom_impl(choose_table, n, among, rate, one_minus_rate);
            *x = Some(value);
        }
        x.as_ref().unwrap()
    }

    fn binom_impl(
        choose_table: &mut Table2d<I>,
        n: u32,
        among: u32,
        rate: &T,
        one_minus_rate: &T,
    ) -> T {
        assert!(among >= n);
        rate.powi(n) * one_minus_rate.powi(among - n) * Self::choose(choose_table, n, among)
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
}

#[derive(Clone)]
struct Matrix<I, T> {
    data: ndtable::Table2d<T>,
    _phantom: PhantomData<I>,
}

impl<I, T> Debug for Matrix<I, T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let &[a, _] = self.data.size();
        // TODO: use debug_list().entry_with() once stable.
        f.debug_list()
            .entries((0..a).map(|i| MatrixSlice {
                data: &self.data,
                i,
            }))
            .finish()
    }
}

struct MatrixSlice<'a, T> {
    data: &'a ndtable::Table2d<T>,
    i: usize,
}

impl<T> Debug for MatrixSlice<'_, T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let &[_, b] = self.data.size();
        f.debug_list()
            .entries((0..b).map(|j| &self.data[[self.i, j]]))
            .finish()
    }
}

impl<I, T> Mul for &Matrix<I, T>
where
    I: Integer + Clone,
    T: Rational<I> + Default + Clone,
    for<'a> &'a T: Mul<Output = T>,
{
    type Output = Matrix<I, T>;

    fn mul(self, rhs: Self) -> Self::Output {
        let &[a, b] = self.data.size();
        let &[c, d] = rhs.data.size();
        assert_eq!(b, c);
        let mut data = ndtable::Table2d::init(T::zero(), [a, d]);
        for i in 0..a {
            for j in 0..b {
                for k in 0..d {
                    data[[i, k]] += &self.data[[i, j]] * &rhs.data[[j, k]];
                }
            }
        }
        Matrix {
            data,
            _phantom: PhantomData,
        }
    }
}

impl<I, T> Matrix<I, T>
where
    I: Integer + Clone,
    T: Rational<I> + Default + Clone,
    for<'a> &'a T: Mul<Output = T>,
{
    fn generate(n: u32, mut f: impl FnMut(u32, u32) -> T) -> Self {
        let mut data = ndtable::Table2d::new([n as usize, n as usize]);
        for i in 0..n {
            for j in 0..n {
                data[[i as usize, j as usize]] = f(i, j);
            }
        }
        Matrix {
            data,
            _phantom: PhantomData,
        }
    }

    fn identity(n: usize) -> Self {
        let mut data = ndtable::Table2d::init(T::zero(), [n, n]);
        for i in 0..n {
            data[[i, i]] = T::one();
        }
        Matrix {
            data,
            _phantom: PhantomData,
        }
    }

    fn powi(&self, mut n: u32) -> Self {
        let &[a, b] = self.data.size();
        assert_eq!(a, b);
        let mut result = Self::identity(a);

        let mut power: Self = self.clone();
        loop {
            if n & 1 == 1 {
                result = &result * &power;
            }
            n >>= 1;
            if n == 0 {
                break;
            }
            power = &power * &power;
        }
        result
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
}

trait Rational<I: Integer>:
    Add<Output = Self>
    + Mul<Output = Self>
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
    fn zero() -> Self;

    fn one() -> Self;

    fn from(x: u32) -> Self;

    fn from_log2(x: u32) -> Self;

    fn to_f64(&self) -> f64;

    fn to_f64_log2(&self) -> f64;

    fn powi(&self, n: u32) -> Self;

    fn one_minus_x(&self) -> Self;

    fn exp(&self) -> Self;

    fn reduce(&mut self) {}

    fn reduced(mut self) -> Self {
        self.reduce();
        self
    }
}

#[derive(Default, Debug, Clone, Copy)]
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

    fn from(x: u32) -> Self {
        F64Log2((x as f64).log2())
    }
}

impl Rational<F64Log2> for F64Log2 {
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
}

impl Rational<BigInt> for BigRational {
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

impl<D: Denom> Rational<BigInt> for SmartBigRationalImpl<D>
where
    for<'a> &'a D: DenomRef<D>,
{
    fn zero() -> Self {
        Self::ZERO
    }

    fn one() -> Self {
        Self::ONE
    }

    fn from(x: u32) -> Self {
        Self::ratio(x, D::one())
    }

    fn from_log2(x: u32) -> Self {
        Self::ratio(<BigInt as Integer>::one() << x, D::one())
    }

    fn to_f64(&self) -> f64 {
        Rational::to_f64(&self.to_big_rational())
    }

    fn to_f64_log2(&self) -> f64 {
        self.to_f64().log2()
    }

    fn powi(&self, n: u32) -> Self {
        self.pow(n)
    }

    fn one_minus_x(&self) -> Self {
        Self::ONE - self
    }

    fn exp(&self) -> Self {
        BigRational::from_float(Rational::to_f64(self).exp())
            .unwrap()
            .into()
    }

    fn reduce(&mut self) {
        self.reduce();
    }
}
