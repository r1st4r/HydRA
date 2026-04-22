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

#[allow(dead_code)]
impl<'a, F: PrimeField, HG: FieldHasherGadget<F>> TestCircuit<'a, F, HG> {
    pub fn new(pk: F, sk: F, ar: F, time: F, period: F, output: F, root: F, path: &'a [F], tag: &'a [bool], hasher: HG::Native) -> Self {
        Self {pk, sk, ar, time, period, output, root, path, tag, hasher}
    }
}

impl<'a, F: PrimeField, HG: FieldHasherGadget<F>> Clone for TestCircuit<'a, F, HG> {
    fn clone(&self) -> Self {

    }
}