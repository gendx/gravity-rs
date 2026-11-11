use num::bigint::Sign;
use num::traits::Pow;
use num::{BigInt, BigRational, BigUint, One, ToPrimitive, Zero};
use smart_big_rational::{Denom, DenomRef, SmartBigRational};
use std::fmt::Debug;
use std::iter::Sum;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub};

pub trait Integer:
    Sub<Output = Self>
    + Mul<Output = Self>
    + Div<Output = Self>
    + AddAssign
    + MulAssign
    + Sum
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + for<'a> MulAssign<&'a Self>
{
    fn zero() -> Self;

    fn one() -> Self;

    fn is_zero(&self) -> bool;

    fn from(x: u32) -> Self;

    fn powi(&self, n: u32) -> Self;

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

pub trait Denominator:
    Sized + Mul<Output = Self> + Div<Output = Self> + MulAssign + for<'a> MulAssign<&'a Self>
{
    fn one() -> Self;

    fn from(x: u32) -> Self;

    fn powi(&self, n: u32) -> Self;

    fn choose(n: u32, among: u32) -> Self {
        if n > among {
            panic!("Division by zero");
        }
        let mut res = Self::one();
        for i in 0..n {
            res *= Self::from(among - i) / Self::from(i + 1);
        }
        res
    }
}

pub trait Rational<I: Integer, D: Denominator>:
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
    fn from_ratio(num: I, denom: D) -> Self;

    fn zero() -> Self;

    fn one() -> Self;

    fn is_zero(&self) -> bool;

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
pub struct F64Log2(f64);

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
        iter.fold(<Self as Rational<Self, Self>>::zero(), |acc, x| acc + x)
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

    fn powi(&self, n: u32) -> Self {
        F64Log2(n as f64 * self.0)
    }

    fn to_f64_log2(&self) -> f64 {
        self.0
    }
}

impl Denominator for F64Log2 {
    fn one() -> Self {
        F64Log2(0.0)
    }

    fn from(x: u32) -> Self {
        F64Log2((x as f64).log2())
    }

    fn powi(&self, n: u32) -> Self {
        F64Log2(n as f64 * self.0)
    }
}

impl Rational<F64Log2, F64Log2> for F64Log2 {
    fn from_ratio(num: F64Log2, denom: F64Log2) -> Self {
        num / denom
    }

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

    fn powi(&self, n: u32) -> Self {
        self.pow(n)
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

impl Denominator for BigInt {
    fn one() -> Self {
        <BigInt as One>::one()
    }

    fn from(x: u32) -> Self {
        x.into()
    }

    fn powi(&self, n: u32) -> Self {
        self.pow(n)
    }

    fn choose(n: u32, among: u32) -> Self {
        if n > among {
            panic!("Division by zero");
        }

        let mut num = <Self as Denominator>::one();
        for i in 0..n {
            num *= <Self as Denominator>::from(among - i);
        }

        let mut denom = <Self as Denominator>::one();
        for i in 0..n {
            denom *= <Self as Denominator>::from(i + 1);
        }

        num / denom
    }
}

impl Rational<BigInt, BigInt> for BigRational {
    fn from_ratio(num: BigInt, denom: BigInt) -> Self {
        BigRational::new(num, denom)
    }

    fn zero() -> Self {
        <BigRational as Zero>::zero()
    }

    fn one() -> Self {
        <BigRational as One>::one()
    }

    fn is_zero(&self) -> bool {
        Zero::is_zero(self)
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

impl Denominator for BigUint {
    fn one() -> Self {
        <BigUint as One>::one()
    }

    fn from(x: u32) -> Self {
        x.into()
    }

    fn powi(&self, n: u32) -> Self {
        self.pow(n)
    }

    fn choose(n: u32, among: u32) -> Self {
        if n > among {
            panic!("Division by zero");
        }

        let mut num = <Self as Denominator>::one();
        for i in 0..n {
            num *= <Self as Denominator>::from(among - i);
        }

        let mut denom = <Self as Denominator>::one();
        for i in 0..n {
            denom *= <Self as Denominator>::from(i + 1);
        }

        num / denom
    }
}

impl<D: Denom> Rational<BigInt, BigUint> for SmartBigRational<D>
where
    for<'a> &'a D: DenomRef<D>,
{
    fn from_ratio(num: BigInt, denom: BigUint) -> Self {
        Self::ratio(num, denom)
    }

    fn zero() -> Self {
        Self::ZERO
    }

    fn one() -> Self {
        Self::ONE
    }

    fn is_zero(&self) -> bool {
        Zero::is_zero(self)
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
                &(Integer::powi(&<F64Log2 as Integer>::from(2), 10_000)
                    + <F64Log2 as Integer>::from(2))
            ),
            10_000.0
        );
        assert_eq!(
            Integer::to_f64_log2(
                &(<F64Log2 as Integer>::from(2)
                    + Integer::powi(&<F64Log2 as Integer>::from(2), 10_000))
            ),
            10_000.0
        );
    }

    #[test]
    fn test_f64log2_powi() {
        for i in 0..=10_000 {
            assert_eq!(
                Integer::to_f64_log2(&Integer::powi(&<F64Log2 as Integer>::from(2), i)),
                i as f64
            );
            assert_eq!(
                Integer::to_f64_log2(
                    &(<F64Log2 as Integer>::one()
                        / Integer::powi(&<F64Log2 as Integer>::from(2), i))
                ),
                -(i as f64)
            );
        }
    }
}
