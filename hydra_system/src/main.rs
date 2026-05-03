use ark_groth16::Groth16;
use ark_crypto_primitives::SNARK;
use ark_bls12_381::{Bls12_381, Fr};
use arkworks_r1cs_gadgets::poseidon::PoseidonGadget;
use arkworks_utils::Curve;
use std::time::Instant;

use arkworks_native_gadgets::poseidon::FieldHasher;

use ark_std::UniformRand;
use smart_tree::poseidon::PoseidonSetup;
use smart_tree::zkcircuit::TestCircuit;
use smart_tree::shurbstree::{BuildShrubs,Build_Static_Shrubs, Find_Shrubs_Path};
type GrothSetup = Groth16<Bls12_381>;
type PoseidonC<'a> = TestCircuit<'a, Fr, PoseidonGadget<Fr>>;
const LEN: usize = 10;

fn main() {
    println!("Hello, world!");
    let mut b_tree = Vec::new();
    for i in 0..2_i32.pow(LEN as u32) {
         b_tree.push(Fr::rand(rng));
}
    
let mut root = vec![];






    
}
