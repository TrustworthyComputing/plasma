//  63-bit modulus:   p = 2^63 - 25;
const MODULUS_64: u64 = 9223372036854775783u64;

impl crate::Group for u64 {
    #[inline]
    fn zero() -> Self {
        0u64
    }

    #[inline]
    fn one() -> Self {
        1u64
    }

    #[inline]
    fn add(&mut self, other: &Self) {
        debug_assert!(*self < MODULUS_64);
        debug_assert!(*other < MODULUS_64);
        *self = (*self + other) % MODULUS_64;
    }

    #[inline]
    fn sub(&mut self, other: &Self) {
        debug_assert!(*self < MODULUS_64);
        debug_assert!(*other < MODULUS_64);
        let mut neg = *other;
        neg.negate();
        self.add(&neg);
    }

    #[inline]
    fn negate(&mut self) {
        debug_assert!(*self < MODULUS_64);
        *self = MODULUS_64 - *self;
        *self %= MODULUS_64;
    }

    #[inline]
    fn value(self) -> u64 {
        self
    }
}

impl crate::prg::FromRng for u64 {
    fn from_rng(&mut self, rng: &mut impl rand::Rng) {
        *self = u64::MAX;
        while *self >= MODULUS_64 {
            *self = rng.next_u64();
            *self &= 0x7fffffffffffffffu64;
        }
    }
}

impl crate::Share for u64 {}

impl<T> crate::Group for (T, T)
where
    T: crate::Group + Clone,
{
    #[inline]
    fn zero() -> Self {
        (T::zero(), T::zero())
    }

    #[inline]
    fn one() -> Self {
        (T::one(), T::one())
    }

    #[inline]
    fn add(&mut self, other: &Self) {
        self.0.add(&other.0);
        self.1.add(&other.1);
    }

    #[inline]
    fn negate(&mut self) {
        self.0.negate();
        self.1.negate();
    }

    #[inline]
    fn sub(&mut self, other: &Self) {
        let mut inv0 = other.0.clone();
        let mut inv1 = other.1.clone();
        inv0.negate();
        inv1.negate();
        self.0.add(&inv0);
        self.1.add(&inv1);
    }

    #[inline]
    fn value(self) -> u64 {
        println!("value: Group for (T, T)");

        0u64
    }
}

impl<T> crate::prg::FromRng for (T, T)
where
    T: crate::prg::FromRng + crate::Group,
{
    fn from_rng(&mut self, mut rng: &mut impl rand::Rng) {
        self.0 = T::zero();
        self.1 = T::zero();
        self.0.from_rng(&mut rng);
        self.1.from_rng(&mut rng);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::Group;

    #[test]
    fn add128() {
        let mut res = u64::zero();
        let one = 1u64;
        let two = 2u64;
        res.add(&one);
        res.add(&one);
        assert_eq!(two, res);
    }

    #[test]
    fn add_big128() {
        let mut res = 1u64;
        let two = 2u64;
        res.add(&two);
        res.add(&(MODULUS_64 - 1));
        assert_eq!(two, res);
    }

    #[test]
    fn negate128() {
        let zero = u64::zero();
        let x = 1123123u64;
        let mut negx = 1123123u64;
        let mut res = 0u64;

        negx.negate();
        res.add(&x);
        res.add(&negx);
        assert_eq!(zero, res);
    }
}
