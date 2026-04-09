use ark_ff::PrimeField;
use ark_bls12_381:: Fr as BlsFr;
use arkworks_utils::{
    bytes_matrix_to_f, bytes_vec_to_f, poseidon_params::setup_poseidon_params, Curve,
};

use arkworks_native_gadgets::poseidon::{
    sbox::PoseidonSbox, Poseidon, PoseidonParameters,
};