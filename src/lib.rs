#![allow(non_snake_case)]

use crate::utilities::ErrorReason;
use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::Samplable;
use curv::arithmetic::{traits::*, BigInt};
use serde::{Deserialize, Serialize};
use utilities::{get_trusted_rsa_modules, h_g, hash_to_prime};

const SEED_LENGTH: usize = 32;
const GROUP_SIZE: usize = 256;
const NONCE_SIZE: usize = 4;
pub mod utilities;
pub(crate) mod keccak256;


/// Wesolowski VDF, based on https://eprint.iacr.org/2018/712.pdf.
/// Original paper: https://eprint.iacr.org/2018/623.pdf
///
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SolvedVDF {
    vdf_instance: UnsolvedVDF,
    pub y: BigInt,
    pub pi: BigInt,
    pub q: BigInt,
    pub nonce: u32
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SetupForVDF {
    pub t: BigInt,
    pub N: BigInt,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UnsolvedVDF {
    pub x: BigInt,
    pub setup: SetupForVDF,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SerializedVDFParameter {
    pub x: Vec<u8>,
    pub t: u64
}


#[derive(Clone, Debug, PartialEq)]
pub struct SerializedVDFProof {
    pub y: [u8;GROUP_SIZE],
    pub pi: [u8;GROUP_SIZE],
    pub q: [u8;GROUP_SIZE],
    pub nonce: u32
}


impl SetupForVDF {
    pub fn public_setup(t: &BigInt) -> Self {
        // todo: setup can also be used to define H_G. for example pick random domain separator
        let N = get_trusted_rsa_modules();
        SetupForVDF { t: t.clone(), N }
    }

    pub fn pick_challenge(setup: &SetupForVDF) -> UnsolvedVDF {
        let x = BigInt::sample(SEED_LENGTH);
        UnsolvedVDF {
            x,
            setup: setup.clone(),
        }
    }
}

impl UnsolvedVDF {
    //algorithm 3 from https://eprint.iacr.org/2018/623.pdf
    pub fn eval(unsolved_vdf: &UnsolvedVDF) -> SolvedVDF {
        let N = unsolved_vdf.setup.N.clone();
        let x = unsolved_vdf.x.clone();
        let t = unsolved_vdf.setup.t.clone();

        let g = h_g(&N, &x);
        let mut y = g.clone();
        let mut i = BigInt::zero();

        while i < t {
            y = BigInt::mod_mul(&y, &y, &N);
            i = i + BigInt::one();
        }
        //println!("before to prime {}", hex::encode(&y.to_bytes()));
        let (l,nonce) = hash_to_prime(&g, &y);

        //algorithm 4 from https://eprint.iacr.org/2018/623.pdf
        // long division TODO: consider alg 5 instead
        let mut i = BigInt::zero();
        let mut b: BigInt;
        let mut r = BigInt::one();
        let mut r2: BigInt = BigInt::zero();
        let two = BigInt::from(2);
        let mut pi = BigInt::one();
        let mut g_b: BigInt;

        while i < t {
            r2 = r.clone() * two.clone();
            b = r2.div_floor(&l);
            r = r2.mod_floor(&l);
            g_b = BigInt::mod_pow(&g, &b, &N);
            pi = BigInt::mod_mul(&pi, &pi, &N);
            pi = BigInt::mod_mul(&pi, &g_b, &N);
            i = i + BigInt::one();
        }

        // get helper data "q"
        let u1 = BigInt::mod_pow(&pi, &l, &N);
        let u2 = BigInt::mod_pow(&g, &r2, &N);
        let q = u1.mul(&u2).div_floor(&N);

        let vdf = SolvedVDF {
            vdf_instance: unsolved_vdf.clone(),
            y,
            pi,
            q,
            nonce
        };
        vdf
    }

    pub fn from_parameter(parameter: &SerializedVDFParameter) -> Self {
        let t = BigInt::from(parameter.t);
        let setup = SetupForVDF::public_setup(&t);
        let x = BigInt::from_bytes(&parameter.x);
        Self {
            x,
            setup
        }
    }
}

impl SolvedVDF {
    pub fn from_parameter_and_proof(parameter: &SerializedVDFParameter, proof: &SerializedVDFProof) -> Self {
        let unsolved_vdf = UnsolvedVDF::from_parameter(parameter);
        let y = BigInt::from_bytes(&proof.y);
        let pi = BigInt::from_bytes(&proof.pi);
        let q = BigInt::from_bytes(&proof.q);
        Self {
            vdf_instance: unsolved_vdf.clone(),
            y,
            pi,
            q,
            nonce: proof.nonce
        }
    }

    //algorithm 2 from https://eprint.iacr.org/2018/623.pdf
    pub fn verify(&self, unsolved_vdf: &UnsolvedVDF) -> Result<(), ErrorReason> {
        // we first check the solution received is for VDF generated by us
        if &self.vdf_instance != unsolved_vdf {
            return Err(ErrorReason::MisMatchedVDF);
        }
        let N = self.vdf_instance.setup.N.clone();
        let g = h_g(&self.vdf_instance.setup.N, &self.vdf_instance.x);

        // test that y is element in the group : https://eprint.iacr.org/2018/712.pdf 2.1 line 0
        if &self.y >= &N || &self.pi >= &N {
            return Err(ErrorReason::VDFVerifyError);
        }

        let (l,_) = hash_to_prime(&g, &self.y);

        let r = BigInt::mod_pow(&BigInt::from(2), &self.vdf_instance.setup.t, &l);
        let pi_l = BigInt::mod_pow(&self.pi, &l, &N);
        let g_r = BigInt::mod_pow(&g, &r, &N);
        let pi_l_g_r = BigInt::mod_mul(&pi_l, &g_r, &N);

        match pi_l_g_r == self.y {
            true => return Ok(()),
            false => return Err(ErrorReason::VDFVerifyError),
        }
    }
}

impl SerializedVDFProof {
    pub const SIZE:usize = GROUP_SIZE*3+NONCE_SIZE;

    pub fn verify_with_parameter(&self, parameter: &SerializedVDFParameter) -> Result<(), ErrorReason> {
        let solved_vdf = SolvedVDF::from_parameter_and_proof(parameter, self);
        let unsolved_vdf = &solved_vdf.vdf_instance;
        solved_vdf.verify(unsolved_vdf)
    }

    pub fn from_bytes(_bytes:&[u8]) -> Self {
        assert!(_bytes.len()==Self::SIZE, "invalid size");
        let mut y = [0;GROUP_SIZE];
        let mut pi = [0;GROUP_SIZE];
        let mut q = [0;GROUP_SIZE];
        let mut nonce = [0;NONCE_SIZE];
        y.copy_from_slice(&_bytes[0..GROUP_SIZE]);
        pi.copy_from_slice(&_bytes[GROUP_SIZE..GROUP_SIZE*2]);
        q.copy_from_slice(&_bytes[GROUP_SIZE*2..GROUP_SIZE*3]);
        nonce.copy_from_slice(&_bytes[GROUP_SIZE*3..GROUP_SIZE*3+NONCE_SIZE]);
        Self {
            y,
            pi,
            q,
            nonce:u32::from_be_bytes(nonce)
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.y[..]);
        bytes.extend_from_slice(&self.pi[..]);
        bytes.extend_from_slice(&self.q[..]);
        let nonce_bytes = self.nonce.to_be_bytes();
        bytes.extend_from_slice(&nonce_bytes[..]);
        bytes
    }

    pub fn compute(_t:u64, _x:&[u8]) -> Result<Self,ErrorReason> {
        assert!(_x.len()==SEED_LENGTH,"invalid x length");
        let t = BigInt::from_bytes(&_t.to_be_bytes()[..]);
        let x = BigInt::from_bytes(&_x);
        let setup = SetupForVDF::public_setup(&t);
        let unsolved_vdf = UnsolvedVDF {
            x,
            setup: setup.clone()
        };
        let solved_vdf = UnsolvedVDF::eval(&unsolved_vdf);
        solved_vdf.verify(&unsolved_vdf)?;
        let mut y = [0;GROUP_SIZE];
        let mut pi = [0;GROUP_SIZE];
        let mut q = [0;GROUP_SIZE];
        let y_bytes = solved_vdf.y.to_bytes();
        let pi_bytes = solved_vdf.pi.to_bytes();
        let q_bytes = solved_vdf.q.to_bytes();
        y[GROUP_SIZE-y_bytes.len()..GROUP_SIZE].copy_from_slice(&y_bytes[..]);
        pi[GROUP_SIZE-pi_bytes.len()..GROUP_SIZE].copy_from_slice(&pi_bytes[..]);
        q[GROUP_SIZE-q_bytes.len()..GROUP_SIZE].copy_from_slice(&q_bytes[..]);
        /*for i in 0..y_bytes.len() {
            y[i] = y_bytes[i];
        }
        for i in 0..pi_bytes.len() {
            pi[i] = pi_bytes[i];
            pi[GROUP_SIZE-pi_bytes.len()..GROUP_SIZE].copy_from_slice(pi_bytes[..]);
        }
        for i in 0..q_bytes.len() {
            q[i] = q_bytes[i];
        }*/
        Ok(Self {
            y,
            pi,
            q,
            nonce:solved_vdf.nonce
        })
    }
}


#[cfg(test)]
mod tests {
    use super::SetupForVDF;
    use super::UnsolvedVDF;
    use super::{SerializedVDFProof,SerializedVDFParameter};
    use curv::arithmetic::traits::Samplable;
    use curv::BigInt;
    use std::time::Instant;
    use curv::cryptographic_primitives::hashing::traits::Hash;
    use curv::arithmetic::Converter;
    use super::keccak256::Keccak256;
    use hex;

    #[test]
    fn test_vdf_valid_proof() {
        let t = BigInt::from_str_radix("13",10).unwrap();
        let setup = SetupForVDF::public_setup(&t);

        let mut i = 0;
        while i < 10 {
            let seed_hash = Keccak256::create_hash_from_slice(&[i;32]);
            println!("input at {}, {}", i, hex::encode(&seed_hash.to_bytes()));
            let unsolved_vdf = UnsolvedVDF {
                x: seed_hash,
                setup: setup.clone()
            };
            let start = Instant::now();
            let solved_vdf = UnsolvedVDF::eval(&unsolved_vdf);
            let duration1 = start.elapsed();
            println!("answer at {}, {}", i, hex::encode(&solved_vdf.y.to_bytes()));
            let start = Instant::now();
            // here unsolved_vdf is the version that was kept by the challenger
            let res = solved_vdf.verify(&unsolved_vdf);
            let duration2 = start.elapsed();
            i = i + 1;

            // todo: compute mean and std
            println!("eval time: {:?}", duration1);
            println!("verify time: {:?}", duration2);

            assert!(res.is_ok());
        }
    }

    #[test]
    fn test_serialized_vdf_valid_proof() {
        let t = 13;
        let mut i = 0;
        while i < 10 {
            let seed_hash = Keccak256::create_hash_from_slice(&[i;32]);
            println!("input at {}, {}", i, hex::encode(&seed_hash.to_bytes()));

            let serialized_proof = SerializedVDFProof::compute(t,&seed_hash.to_bytes()).expect("Fail to compute vdf proof.");
            let serialized_param = SerializedVDFParameter {
                x:seed_hash.to_bytes(),
                t
            };
            serialized_proof.verify_with_parameter(&serialized_param);
            i = i+1;
        }
    }
}
