use num::traits::Pow;
use num::{BigInt, BigRational, BigUint, One, ToPrimitive, Zero};
use smart_big_rational::{
    Denom, DenomRef, DenomSparseU16, SmartBigRational as SmartBigRationalImpl,
};
use std::fmt;
use std::fmt::Debug;
use std::iter::Sum;
use std::marker::PhantomData;
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub};

type HashMap<K, V> = std::collections::HashMap<K, V, rustc_hash::FxBuildHasher>;
type Table2d<T> = ndtable::Table2d<Option<T>>;
type Table3d<T> = ndtable::Table3d<Option<T>>;
type SmartBigRational = SmartBigRationalImpl<DenomSparseU16<6542, 16>>;

fn main() {
    let mut mem: Memoized<F64Log2, F64Log2, F64Log2> =
        Memoized::new(/* max(r) */ 50, /* max(B) */ 20);
    mem.evaluate();

    let mut mem: Memoized<BigInt, BigUint, SmartBigRational> =
        Memoized::new(/* max(r) */ 50, /* max(B) */ 20);
    mem.evaluate();
}

#[expect(non_snake_case)]
struct Memoized<I, D, T> {
    weight_poisson: Table3d<T>,
    choose: Table2d<I>,
    binom_power: Table2d<T>,
    binom_opposite_power: Table2d<T>,
    binom_t: Table2d<T>,
    table_h: HashMap<(u32, u32), i32>,
    table_pow: HashMap<(u32, u32), I>,
    N: u32,
    fmv: Table2d<T>,
    rmax: u32,
    _phantom: PhantomData<D>,
}

impl<I: Clone, D, T: Clone> Memoized<I, D, T> {
    fn new(rmax: u32, bmax: usize) -> Self {
        Self {
            weight_poisson: Table3d::new([70, 70, rmax as usize + 1]),
            choose: Table2d::new([rmax as usize + 1, rmax as usize + 1]),
            binom_power: Table2d::new([bmax + 1, rmax as usize + 1]),
            binom_opposite_power: Table2d::new([bmax + 1, rmax as usize + 1]),
            binom_t: Table2d::new([rmax as usize + 1, rmax as usize + 1]),
            table_h: HashMap::default(),
            table_pow: HashMap::default(),
            N: 0,
            fmv: Table2d::new([rmax as usize + 1, rmax as usize + 1]),
            rmax,
            _phantom: PhantomData,
        }
    }
}

impl<I, D, T> Memoized<I, D, T>
where
    I: Integer + Clone,
    D: Denominator + Clone,
    T: Rational<I, D> + Debug + Default + Clone,
    for<'a> &'a I: Mul<&'a I, Output = I>,
    for<'a> &'a T: Mul<&'a T, Output = T>,
{
    fn evaluate(&mut self) {
        // Parameters from https://eprint.iacr.org/2026/2502.pdf, table 5.
        self.evaluate_gs(
            "128s",
            3,
            10,
            &[3, 3, 3, 3, 3, 6],
            8,
            1,
            0,
            63,
            64,
            19 << 14,
        );
        self.evaluate_gs(
            "192s",
            6,
            12,
            &[3, 3, 3, 3, 3, 3, 6],
            9,
            1,
            0,
            63,
            64,
            13 << 14,
        );
        self.evaluate_gs(
            "256s",
            3,
            17,
            &[1, 3, 3, 3, 3, 3, 3],
            8,
            1,
            0,
            64,
            64,
            273 << 8,
        );
        self.evaluate_gs("128f", 2, 5, &[1, 1, 2], 2, 7, 1, 66, 64, 7 << 21);
        self.evaluate_gs("192f", 4, 34, &[2, 2, 2, 4], 4, 1, 0, 66, 64, 69 << 16);
        self.evaluate_gs("256f", 3, 6, &[1, 3, 3, 3], 4, 6, 1, 68, 64, 41 << 15);
        self.evaluate_gs(
            "128-224",
            3,
            5,
            &[4, 4, 4, 4, 4, 4, 4, 4],
            12,
            1,
            5,
            22,
            24,
            82,
        );
        self.evaluate_gs(
            "192-224",
            7,
            8,
            &[4, 4, 4, 4, 4, 4, 4, 4],
            12,
            1,
            6,
            21,
            24,
            104,
        );
        self.evaluate_gs(
            "256-224",
            9,
            11,
            &[4, 4, 4, 4, 4, 4, 4, 4],
            12,
            1,
            8,
            21,
            24,
            208,
        );
    }

    #[expect(non_snake_case, clippy::too_many_arguments)]
    fn evaluate_gs(
        &mut self,
        title: &str,
        u: u32,
        r: u32,
        c: &[u32],
        E: u32,
        K: u32,
        b: u32,
        h: u32,
        q: u32,
        delta: u32,
    ) {
        let k = c.len() as u32;
        let L = k - 1;
        self.binom_t = Table2d::new([self.rmax as usize + 1, self.rmax as usize + 1]);
        self.fmv = Table2d::new([self.rmax as usize + 1, self.rmax as usize + 1]);

        (self.table_h, self.N) = Self::generate_table_h(c, E);
        let p = self.gsc(u, r, L, K, b, h, q).to_f64_log2();

        let tau = tau(r, K, delta, self.N);
        println!(
            "- {title}: cover_gsc(2^{u}, {r}, 2^{L}, {K}, 2^{b}, 2^{h}, 2^{q}) = 2^{} * 2^{} = 2^{}",
            p,
            tau.log2(),
            p + tau.log2(),
        );
    }

    /// Computes the table of `h_{a,d}` as described in
    /// https://eprint.iacr.org/2026/2502.pdf, equations 23-24.
    #[expect(non_snake_case)]
    fn generate_table_h(c: &[u32], E: u32) -> (HashMap<(u32, u32), i32>, u32) {
        let k = c.len() as u32;
        let L = k - 1;

        let mut N = 0;
        let mut table_h = HashMap::default();
        for e in LkceGenerator::new(c, E) {
            N += 1;
            let mut table_ae = vec![0; 1 << k];
            for s in 0..1 << k {
                table_ae[s as usize] = Self::aes(&e, c, s, E as usize);
            }
            for s in 0u32..1 << k {
                let ae = table_ae[s as usize];
                let de = (0..L)
                    .filter(|j| s & (1 << j) == 0)
                    .map(|j| table_ae[s as usize & ((1 << j) - 1)] << (L - j - 1))
                    .sum();
                if s.count_ones() % 2 == 0 {
                    *table_h.entry((ae, de)).or_insert(0) += 1;
                } else {
                    *table_h.entry((ae, de)).or_insert(0) -= 1;
                }
            }
        }

        // Double-checking the value of N.
        let mut p = Poly::ones(1);
        for &x in c.iter() {
            p = p.mul_trunc(&Poly::ones(x as usize + 1), E as usize + 1);
        }
        assert_eq!(N, p.0[E as usize]);

        let sum: i32 = table_h.values().sum();
        assert_eq!(sum, 0);

        (table_h, N)
    }

    /// Computes the number of codewords `x` satisfying `x.sum() == E` and `x[i]
    /// < e[i]` if the i-th bit of `s` is set and `x[i] <= c[i]` otherwise.
    ///
    /// See https://eprint.iacr.org/2026/2502.pdf, equation 21.
    #[expect(non_snake_case)]
    fn aes(e: &[u32], c: &[u32], s: u32, E: usize) -> u32 {
        // Optimization: if an index is selected where the codeword e[i] is
        // zero, the result is zero.
        for (i, x) in e.iter().enumerate() {
            if s & (1 << i) != 0 && *x == 0 {
                return 0;
            }
        }

        let mut p = Poly::ones(1);
        for (i, x) in e.iter().enumerate() {
            if s & (1 << i) != 0 {
                p = p.mul_trunc(&Poly::ones(*x as usize), E + 1);
            } else {
                p = p.mul_trunc(&Poly::ones(c[i] as usize + 1), E + 1);
            }
        }
        *p.0.get(E).unwrap_or(&0)
    }

    /// Returns an upper bound of the success probability of an attacker making
    /// `2^q` queries against a baseline GS construction with `2^u` owners, `r`
    /// layers of height `l`, on a hyper-tree of height `h`.
    ///
    /// See https://eprint.iacr.org/2026/2502.pdf, section 5.3.
    #[expect(non_snake_case, clippy::too_many_arguments)]
    fn gsc(&mut self, u: u32, r: u32, L: u32, K: u32, b: u32, h: u32, q: u32) -> T {
        let rate = T::from_log2(q) / T::from_log2(h);

        let mut gsc_table = vec![None; self.rmax as usize + 1];

        let mut res = T::zero();
        for rr in 0..=self.rmax {
            let subcover = self.cover_bgsc(&mut gsc_table, 1 << u, r, 1 << L, b, rr);
            eprintln!("rr={rr}: 2^{}^{K}", subcover.to_f64_log2());
            let cover = subcover.powi(K);

            let poisson = Self::weight_poisson(&mut self.weight_poisson, rr, h, q, &rate);
            eprint!(
                "rr={rr}: 2^{} * 2^{}",
                cover.to_f64_log2(),
                poisson.to_f64_log2()
            );
            let product = cover * poisson;
            eprint!(" = 2^{}", product.to_f64_log2());
            res += product;
            eprintln!(" -> 2^{}", res.to_f64_log2());
        }
        res.reduced()
    }

    fn cover_bgsc(
        &mut self,
        gsc_table: &mut [Option<T>],
        o: u32,
        r: u32,
        t: u32,
        b: u32,
        q: u32,
    ) -> T {
        if b == 0 {
            self.cover_gsc(gsc_table, o, r, t, q).clone()
        } else {
            (0..=q)
                .map(|qq| {
                    let binom = Self::binom_power(&mut self.binom_power, b, qq)
                        * Self::binom_opposite_power(&mut self.binom_opposite_power, b, q - qq)
                        * Self::choose(&mut self.choose, qq, q);
                    let subcover = self.cover_gsc(gsc_table, o, r, t, qq);
                    eprint!(
                        "  qq={qq}: 2^{} * 2^{}",
                        subcover.to_f64_log2(),
                        binom.to_f64_log2()
                    );
                    let product = binom * subcover;
                    eprintln!(" = 2^{}", product.to_f64_log2());
                    product
                })
                .sum()
        }
    }

    fn cover_gsc<'a>(
        &mut self,
        gsc_table: &'a mut [Option<T>],
        o: u32,
        r: u32,
        t: u32,
        q: u32,
    ) -> &'a T {
        let entry = &mut gsc_table[q as usize];
        if entry.is_none() {
            *entry = Some(self.cover_gsc_impl(o, r, t, q));
        }
        entry.as_ref().unwrap()
    }

    #[expect(non_snake_case)]
    fn cover_gsc_impl(&mut self, o: u32, r: u32, t: u32, q: u32) -> T {
        assert!(t > 1);
        assert!(self.N != 0);
        let tt = T::one() / T::from(t);
        let one_minus_tt = tt.one_minus_x();
        let t_minus_one = D::from(t - 1);
        let N = D::from(self.N);

        let matrix_q: Matrix<I, D, T> = Matrix::generate(q, |i, j| {
            let i = i + 1;
            let j = j + 1;
            ((i + j).saturating_sub(q).max(1)..=i.min(j))
                .map(|v| {
                    assert!(v <= j);
                    assert!(i <= q);
                    assert!(v <= i);
                    assert!(j - v <= q - i);
                    Self::fmv(
                        &mut self.fmv,
                        &self.table_h,
                        &mut self.table_pow,
                        i,
                        v,
                        &N,
                        &t_minus_one,
                    ) * Self::binom(
                        &mut self.binom_t,
                        &mut self.choose,
                        v,
                        i,
                        &tt,
                        &one_minus_tt,
                    ) * Self::binom(
                        &mut self.binom_t,
                        &mut self.choose,
                        j - v,
                        q - i,
                        &tt,
                        &one_minus_tt,
                    )
                })
                .sum::<T>()
                .reduced()
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

    /// Computes the local covering probability `f(m, v)` given that `m`
    /// histories select the current owner, of which `v` select the target slot,
    /// as described in https://eprint.iacr.org/2026/2502.pdf, equation 24.
    #[expect(non_snake_case)]
    fn fmv<'a>(
        table: &'a mut Table2d<T>,
        table_h: &HashMap<(u32, u32), i32>,
        table_pow: &mut HashMap<(u32, u32), I>,
        m: u32,
        v: u32,
        N: &D,
        t_minus_one: &D,
    ) -> &'a T {
        let x = &mut table[[m as usize, v as usize]];
        if x.is_none() {
            let value = Self::fmv_impl(table_h, table_pow, m, v, N, t_minus_one);
            *x = Some(value);
        }
        x.as_ref().unwrap()
    }

    #[expect(non_snake_case)]
    fn fmv_impl(
        table_h: &HashMap<(u32, u32), i32>,
        table_pow: &mut HashMap<(u32, u32), I>,
        m: u32,
        v: u32,
        N: &D,
        t_minus_one: &D,
    ) -> T {
        if v == 0 {
            return T::zero();
        }
        if m == 1 && v == 1 {
            return T::from_ratio(I::one(), N.clone());
        }

        assert!(v <= m);
        let mut sum_pos = I::zero();
        let mut sum_neg = I::zero();
        for (&(a, d), &h) in table_h.iter() {
            if h >= 0 {
                sum_pos +=
                    I::from(h as u32) * Self::pow(table_pow, a, v) * Self::pow(table_pow, d, m - v);
            } else {
                sum_neg += I::from((-h) as u32)
                    * Self::pow(table_pow, a, v)
                    * Self::pow(table_pow, d, m - v);
            }
        }
        T::from_ratio(sum_pos - sum_neg, N.powi(m + 1) * t_minus_one.powi(m - v))
    }

    /// Returns a^n, with the convention that 0^0 = 1.
    fn pow(table: &mut HashMap<(u32, u32), I>, a: u32, n: u32) -> &I {
        table.entry((a, n)).or_insert_with(|| {
            if a == 0 {
                I::zero()
            } else {
                I::from(a).powi(n)
            }
        })
    }

    /// Returns 2^(-B * r)
    #[expect(non_snake_case)]
    fn binom_power(table: &mut Table2d<T>, B: u32, r: u32) -> &T {
        let x = &mut table[[B as usize, r as usize]];
        if x.is_none() {
            let value = if r == 0 {
                T::one()
            } else {
                (T::one() / T::from_log2(B)).powi(r)
            };
            *x = Some(value);
        }
        x.as_ref().unwrap()
    }

    /// Returns (1 - 2^-B)^r
    #[expect(non_snake_case)]
    fn binom_opposite_power(table: &mut Table2d<T>, B: u32, r: u32) -> &T {
        let x = &mut table[[B as usize, r as usize]];
        if x.is_none() {
            let value = if r == 0 {
                T::one()
            } else {
                (T::one() / T::from_log2(B)).one_minus_x().powi(r)
            };
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

/// Computes the acceptance probability `tau` as described in
/// https://eprint.iacr.org/2026/2502.pdf, section 4.4.
#[expect(non_snake_case)]
fn tau(r: u32, K: u32, delta: u32, N: u32) -> f64 {
    let U = <BigUint as From<_>>::from(N).pow(r * K);
    assert!(!U.is_zero());
    let l = (&U - BigUint::one()).bits();
    let eta =
        ToPrimitive::to_f64(&BigRational::new(U.into(), (BigUint::one() << l).into())).unwrap();
    let rho = delta as f64 / 4294967296_f64;
    let tau = rho * eta;
    println!("tau = {rho} * {eta} = {tau}");
    tau
}

#[derive(Clone)]
struct Matrix<I, D, T> {
    data: ndtable::Table2d<T>,
    _phantom: PhantomData<(I, D)>,
}

impl<I, D, T> Debug for Matrix<I, D, T>
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

impl<I, D, T> Mul for &Matrix<I, D, T>
where
    I: Integer + Clone,
    D: Denominator + Clone,
    T: Rational<I, D> + Default + Clone,
    for<'a> &'a T: Mul<Output = T>,
{
    type Output = Matrix<I, D, T>;

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
        for i in 0..a {
            for k in 0..d {
                data[[i, k]].reduce();
            }
        }
        Matrix {
            data,
            _phantom: PhantomData,
        }
    }
}

impl<I, D, T> Matrix<I, D, T>
where
    I: Integer + Clone,
    D: Denominator + Clone,
    T: Rational<I, D> + Default + Clone,
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

        if n == 0 {
            return result;
        }

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

#[derive(Debug)]
struct Poly(Vec<u32>);

impl Poly {
    fn ones(n: usize) -> Self {
        Self(vec![1; n])
    }

    fn mul_trunc(&self, other: &Self, n: usize) -> Self {
        let n = (self.0.len() + other.0.len() - 1).min(n);
        let mut result = vec![0; n];
        for (i, x) in self.0.iter().enumerate() {
            if i >= n {
                break;
            }
            for (j, y) in other.0.iter().enumerate() {
                if i + j >= n {
                    break;
                }
                result[i + j] += x * y;
            }
        }
        Self(result)
    }
}

/// Generator of all codewords `x` satisfying `x[i] <= c[i]` and `x.sum() == E`.
#[derive(PartialEq, Eq, Debug)]
#[expect(non_snake_case)]
struct LkceGenerator<'a> {
    c: &'a [u32],
    E: u32,
    e: Option<Vec<u32>>,
}

impl<'a> LkceGenerator<'a> {
    #[expect(non_snake_case)]
    fn new(c: &'a [u32], E: u32) -> Self {
        let mut e = vec![0; c.len()];
        let mut sum = 0;
        for (i, x) in e.iter_mut().enumerate() {
            if sum + c[i] < E {
                *x = c[i];
                sum += c[i];
            } else {
                *x = E - sum;
                return Self { c, E, e: Some(e) };
            }
        }
        Self { c, E, e: None }
    }
}

impl Iterator for LkceGenerator<'_> {
    type Item = Vec<u32>;

    fn next(&mut self) -> Option<Self::Item> {
        let e = self.e.as_mut()?;
        let result = e.clone();

        let mut sum = 0;
        for (i, x) in e.iter_mut().enumerate() {
            if sum > 0 && *x < self.c[i] {
                *x += 1;
                sum -= 1;
                for (j, y) in e.iter_mut().enumerate().take(i) {
                    if self.c[j] < sum {
                        *y = self.c[j];
                        sum -= self.c[j];
                    } else {
                        *y = sum;
                        sum = 0;
                    }
                }
                return Some(result);
            }
            sum += *x;
        }

        self.e = None;
        Some(result)
    }
}

trait Integer:
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
}

trait Denominator: Sized + Mul<Output = Self> {
    fn from(x: u32) -> Self;

    fn powi(&self, n: u32) -> Self;
}

trait Rational<I: Integer, D: Denominator>:
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

    fn from(x: u32) -> Self {
        F64Log2((x as f64).log2())
    }

    fn powi(&self, n: u32) -> Self {
        F64Log2(n as f64 * self.0)
    }
}

impl Denominator for F64Log2 {
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
}

impl Denominator for BigInt {
    fn from(x: u32) -> Self {
        x.into()
    }

    fn powi(&self, n: u32) -> Self {
        self.pow(n)
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
    fn from(x: u32) -> Self {
        x.into()
    }

    fn powi(&self, n: u32) -> Self {
        self.pow(n)
    }
}

impl<D: Denom> Rational<BigInt, BigUint> for SmartBigRationalImpl<D>
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
    fn test_lkce_generator() {
        let codewords: Vec<_> = LkceGenerator::new(&[1, 1, 2], 2).collect();
        assert_eq!(
            codewords,
            vec![vec![1, 1, 0], vec![1, 0, 1], vec![0, 1, 1], vec![0, 0, 2]]
        );

        let codewords: Vec<_> = LkceGenerator::new(&[1, 3, 3, 3], 4).collect();
        assert_eq!(
            codewords,
            vec![
                vec![1, 3, 0, 0],
                vec![1, 2, 1, 0],
                vec![0, 3, 1, 0],
                vec![1, 1, 2, 0],
                vec![0, 2, 2, 0],
                vec![1, 0, 3, 0],
                vec![0, 1, 3, 0],
                vec![1, 2, 0, 1],
                vec![0, 3, 0, 1],
                vec![1, 1, 1, 1],
                vec![0, 2, 1, 1],
                vec![1, 0, 2, 1],
                vec![0, 1, 2, 1],
                vec![0, 0, 3, 1],
                vec![1, 1, 0, 2],
                vec![0, 2, 0, 2],
                vec![1, 0, 1, 2],
                vec![0, 1, 1, 2],
                vec![0, 0, 2, 2],
                vec![1, 0, 0, 3],
                vec![0, 1, 0, 3],
                vec![0, 0, 1, 3]
            ]
        );

        let codewords: Vec<_> = LkceGenerator::new(&[2, 2, 2, 4], 4).collect();
        assert_eq!(
            codewords,
            vec![
                vec![2, 2, 0, 0],
                vec![2, 1, 1, 0],
                vec![1, 2, 1, 0],
                vec![2, 0, 2, 0],
                vec![1, 1, 2, 0],
                vec![0, 2, 2, 0],
                vec![2, 1, 0, 1],
                vec![1, 2, 0, 1],
                vec![2, 0, 1, 1],
                vec![1, 1, 1, 1],
                vec![0, 2, 1, 1],
                vec![1, 0, 2, 1],
                vec![0, 1, 2, 1],
                vec![2, 0, 0, 2],
                vec![1, 1, 0, 2],
                vec![0, 2, 0, 2],
                vec![1, 0, 1, 2],
                vec![0, 1, 1, 2],
                vec![0, 0, 2, 2],
                vec![1, 0, 0, 3],
                vec![0, 1, 0, 3],
                vec![0, 0, 1, 3],
                vec![0, 0, 0, 4]
            ]
        );
    }

    #[expect(non_snake_case)]
    fn n(c: &[u32], E: u32) -> u32 {
        let mut p = Poly::ones(1);
        for &x in c.iter() {
            p = p.mul_trunc(&Poly::ones(x as usize + 1), E as usize + 1);
        }
        p.0[E as usize]
    }

    #[test]
    fn test_tau() {
        // 128s
        assert_eq!(
            tau(10, 1, 19 << 14, n(&[3, 3, 3, 3, 3, 6], 8)),
            5.826512485669614e-5
        );
        // 192s
        assert_eq!(
            tau(12, 1, 13 << 14, n(&[3, 3, 3, 3, 3, 3, 6], 9)),
            2.6284382248589868e-5
        );
        // 256s
        assert_eq!(
            tau(17, 1, 273 << 8, n(&[1, 3, 3, 3, 3, 3, 3], 8)),
            1.1248503667621254e-5
        );

        // 128f
        assert_eq!(tau(5, 7, 7 << 21, n(&[1, 1, 2], 2)), 0.00341796875);
        // 192f
        assert_eq!(
            tau(34, 1, 69 << 16, n(&[2, 2, 2, 4], 4)),
            0.0009172680202196682
        );
        // 256f
        assert_eq!(
            tau(6, 6, 41 << 15, n(&[1, 3, 3, 3], 4)),
            0.00022733229595057778
        );

        // 128-24
        assert_eq!(
            tau(5, 1, 82, n(&[4, 4, 4, 4, 4, 4, 4, 4], 12)),
            1.589589692632599e-8
        );
        // 192-24
        assert_eq!(
            tau(8, 1, 104, n(&[4, 4, 4, 4, 4, 4, 4, 4], 12)),
            1.5723787066908483e-8
        );
        // 256-24
        assert_eq!(
            tau(11, 1, 208, n(&[4, 4, 4, 4, 4, 4, 4, 4], 12)),
            2.4526737249643192e-8
        );
    }
}
