use crate::SetupForVDF;
use curv::arithmetic::traits::*;
use curv::arithmetic::BitManipulation;
use curv::arithmetic::{Integer, One, Zero};
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use curv::BigInt;
use std::error::Error;
use std::fmt;
use std::ops::Shl;
use hex;
use ethereum_keystore::keccak256;

pub struct Keccak256;

impl Hash for Keccak256 {
    fn create_hash(big_ints: &[&BigInt]) -> BigInt {
        let mut inputs = Vec::new();
        for value in big_ints {
            inputs.extend_from_slice(&BigInt::to_bytes(value));
        }
        let result = keccak256(&inputs);
        BigInt::from_bytes(&result[..])
    }

    fn create_hash_from_ge<P: ECPoint>(ge_vec: &[&P]) -> P::Scalar {
        let mut inputs = Vec::new();
        for value in ge_vec {
            inputs.extend_from_slice(&value.pk_to_key_slice());
        }
        let result_bytes = keccak256(&inputs);
        let result_int = BigInt::from_bytes(&result_bytes[..]);
        ECScalar::from(&result_int)
    }

    fn create_hash_from_slice(byte_slice: &[u8]) -> BigInt {
        let result = keccak256(byte_slice);
        BigInt::from_bytes(&result[..])
    }
}