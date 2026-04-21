use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use arkworks_r1cs_gadgets::poseidon::FieldHasherGadget;

#[derive(Copy, Debug)]
pub struct TestCircuit<'a, F: PrimeField, HG: FieldHasherGadget<F>> {
    pk: F,
    sk: F,
    ar: F,
    time: F,
    period: F,
    output: F,
    root: F,
    path: F,
    path: &'a [F],
    tag: &'a [bool],
    hasher: HG::Native,
}