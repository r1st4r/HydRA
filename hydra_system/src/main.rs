use ark_groth16::Groth16;
use ark_crypto_primitives::SNARK;
use ark_bls12_381::{Bls12_381, Fr};
use arkworks_r1cs_gadgets::poseidon::PoseidonGadget;
use arkworks_utils::Curve;
use std::time::Instant;

use arkworks_native_gadgets::poseidon::FieldHasher;

use ark_std::UniformRand;
use smart_tree::poseidon::PoseidonSetup;
fn main() {
    println!("Hello, world!");
}
