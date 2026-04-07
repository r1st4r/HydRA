use ark_groth16::Groth16;
use ark_crypto_primitives::SNARK;

use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use arkworks_r1cs_gadgets::poseidon::PoseidonGadget;
use arkworks_utils::Curve;
use std::time::Instant;
use arkworks_native_gadgets::poseidon::FieldHasher;

use ark_std::UniformRand;

fn main() {
    let rng = &mnt ark_std::test_rng();
    let mut b_tree = Vec::new();
    for i in 0.2_i32.pow(10) {
        b_tree.push(BlsFr::rand(rng));
    }
}
