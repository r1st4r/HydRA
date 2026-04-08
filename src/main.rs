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
    let mut root = vec![];

    let hasher = PoseidonSetup(Curve::Bls12_381, 5, 3);
    let pk = BlsFr::rand(rng);
    let sk = BlsFr::rand(rng);
    let time = BlsFr::rand(rng);
    let period = BlsFr::rand(rng);
    let ar = BlsFr::rand(rng);

    let c = hasher.hash(&[ar, sk]).unwrap();
	let leaf = hasher.hash(&[c, pk]).unwrap();
	let output_1 = hasher.hash(&[pk, ar]).unwrap();
	let output_2 = hasher.hash(&[output_1,sk]).unwrap();
	let output_3 = hasher.hash(&[output_2,time]).unwrap();
	let output = hasher.hash(&[output_3,period]).unwrap();
}
