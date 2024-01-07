use crate::util::*;
use bs58;
use curve25519_dalek::constants::{
    RISTRETTO_BASEPOINT_POINT as G, RISTRETTO_BASEPOINT_TABLE as GT,
};
use std::borrow::Borrow;
use subtle::{ConditionallySelectable, ConstantTimeEq};

#[derive(Clone)]
pub struct PublicKey(pub(crate) [u8; 32], pub(crate) Point);
#[derive(Clone)]
pub struct SecretKey(Scalar, PublicKey);
value_type!(pub, Value, 32, "value");
value_type!(pub, Proof, 64, "proof");

impl PublicKey {
    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        Some(PublicKey(*bytes, unpack(bytes)?))
    }

    fn offset(&self, input: &[u8]) -> Scalar {
        hash_s!(&self.0, input)
    }

    pub fn is_vrf_valid(&self, input: &impl Borrow<[u8]>, value: &Value, proof: &Proof) -> bool {
        self.is_valid(input.borrow(), value, proof)
    }

    // FIXME: no clear fix is available here -- the underlying library runs a non-trivial amount of
    // unchecked arithmetic inside and provides no apparent way to do it in a checked manner.
    #[allow(clippy::arithmetic_side_effects)]
    fn is_valid(&self, input: &[u8], value: &Value, proof: &Proof) -> bool {
        let p = unwrap_or_return_false!(unpack(&value.0));
        let (r, c) = unwrap_or_return_false!(unpack(&proof.0));
        hash_s!(
            &self.0,
            &value.0,
            vmul2(r + c * self.offset(input), &G, c, &self.1),
            vmul2(r, &p, c, &G)
        ) == c
    }
}

// FIXME: no clear fix is available here -- the underlying library runs a non-trivial amount of
// unchecked arithmetic inside and provides no apparent way to do it in a checked or wrapping
// manner.
#[allow(clippy::arithmetic_side_effects)]
fn basemul(s: Scalar) -> Point {
    &s * &*GT
}

fn safe_invert(s: Scalar) -> Scalar {
    Scalar::conditional_select(&s, &Scalar::ONE, s.ct_eq(&Scalar::ZERO)).invert()
}

impl SecretKey {
    pub(crate) fn from_scalar(sk: Scalar) -> Self {
        let pk = basemul(sk);
        SecretKey(sk, PublicKey(pk.pack(), pk))
    }

    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        Some(Self::from_scalar(unpack(bytes)?))
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.1
    }

    pub fn compute_vrf(&self, input: &impl Borrow<[u8]>) -> Value {
        self.compute(input.borrow())
    }

    // FIXME: no clear fix is available here -- the underlying library runs a non-trivial amount of
    // unchecked arithmetic inside and provides no apparent way to do it in a checked or wrapping
    // manner.
    #[allow(clippy::arithmetic_side_effects)]
    fn compute(&self, input: &[u8]) -> Value {
        Value(basemul(safe_invert(self.0 + self.1.offset(input))).pack())
    }

    pub fn compute_vrf_with_proof(&self, input: &impl Borrow<[u8]>) -> (Value, Proof) {
        self.compute_with_proof(input.borrow())
    }

    // FIXME: no clear fix is available here -- the underlying library runs a non-trivial amount of
    // unchecked arithmetic inside and provides no apparent way to do it in a checked or wrapping
    // manner.
    #[allow(clippy::arithmetic_side_effects)]
    fn compute_with_proof(&self, input: &[u8]) -> (Value, Proof) {
        let x = self.0 + self.1.offset(input);
        let inv = safe_invert(x);
        let val = basemul(inv).pack();
        let k = prs!(x);
        let c = hash_s!(&(self.1).0, &val, basemul(k), basemul(inv * k));
        (Value(val), Proof((k - c * x, c).pack()))
    }

    pub fn is_vrf_valid(&self, input: &impl Borrow<[u8]>, value: &Value, proof: &Proof) -> bool {
        self.1.is_valid(input.borrow(), value, proof)
    }
}

macro_rules! traits {
    ($ty:ident, $l:literal, $bytes:expr, $what:literal) => {
        eq!($ty, |a, b| a.0 == b.0);
        common_conversions_fixed!($ty, 32, $bytes, $what);

        impl TryFrom<&[u8; $l]> for $ty {
            type Error = ();
            fn try_from(value: &[u8; $l]) -> Result<Self, ()> {
                Self::from_bytes(value).ok_or(())
            }
        }
    };
}

traits!(PublicKey, 32, |s| &s.0, "public key");
traits!(SecretKey, 32, |s| s.0.as_bytes(), "secret key");

#[cfg(test)]
mod tests {
    use super::*;

    use secp256k1::rand::rngs::OsRng;

    fn random_secret_key() -> SecretKey {
        SecretKey::from_scalar(Scalar::random(&mut OsRng))
    }

    #[test]
    fn test_conversion() {
        let sk = random_secret_key();
        let sk2 = SecretKey::from_bytes(&sk.clone().into()).unwrap();
        assert_eq!(sk, sk2);
        let pk = sk.public_key();
        let pk2 = sk2.public_key();
        assert_eq!(pk, pk2);
    }
}