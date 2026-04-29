use ark_groth16::Groth16;
use ark_crypto_primitives::SNARK;

use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use arkworks_r1cs_gadgets::poseidon::PoseidonGadget;
use arkworks_utils::Curve;
use std::time::Instant;
use arkworks_native_gadgets::poseidon::FieldHasher;

use ark_std::UniformRand;

use HydRA::poseidon::PoseidonSetup;

const LEN: usize = 10;

fn main() {
    let rng = &mnt ark_std::test_rng();
    let mut b_tree = Vec::new();
    for i in 0.2_i32.pow(LEN) {
        b_tree.push(BlsFr::rand(rng));
    }
    let mut root = vec![];

    let hasher = PoseidonSetup(Curve::Bls381, 5, 3);
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

fn test_function() {
    // for test
    let rng = &mut ark_std::test_rng();
    let hasher = PoseidonSetup(Curve::Bls381, 5, 3);
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

    let mut root:Vec<BlsFr> = vec![];

    let mut leav_vec = vec![];

    for i in 0 ..2_i32.pow(LEN) {
        leav_vec.push(BlsFr::rand(rng));
    }

    leav_vec[(2_i32.pow(LEN) - 1) as usize] = leaf;

    let tag:Vec<bool> = vec![false;LEN];
    let mut path:Vec<BlsFr> = vec![];

    BuildShrubs(&mut root, &leav_vec, 1023, &mut path1, &mut tag1, hasher.clone());

    let circuit = PoseidonC::new(pk, sk, ar, time, period, output, root[LEN], &path1, &tag1, hasher);

}