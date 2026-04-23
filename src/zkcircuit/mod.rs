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
        TestCircuit {
            pk: self.pk,
            sk: self.sk,
            ar: self.ar,
            period: self.period,
            output: self.output,
            root: self.root,
            time: self.time,
            tag: self.tag,
            path: self.path,
            hasher: self.hasher.clone(),
        }
    }
}

impl<'a, F: PrimeField, HG: FieldHasherGadget<F>> ConstraintSynthesizer<F> for TestCircuit<'a, F, HG> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let sk = FpVar::new_witness(cs.clone(), || Ok(self.sk))?;
        let ar = FpVar::new_witness(cs.clone(), || Ok(self.ar))?;
        let path: Vec<_> = self.path.iter().map(|x| FpVar::<F>::new_witness(cs.clone(), || Ok(x)).unwrap()).collect();
        let pk = FpVar::<F>::new_input(cs.clone(), || Ok(&self.pk))?;
        let root = FpVar::<F>::new_input(cs.clone(), || Ok(&self.root))?;
        let output = FpVar::<F>::new_input(cs.clone(), || Ok(&self.output))?;
        let time = FpVar::<F>::new_input(cs.clone(), || Ok(&self.time))?;
        let period = FpVar::<F>::new_input(cs.clone(), || Ok(&self.period))?;
        let hasher_gadget: HG = FieldHasherGadget::<F>::from_native(&mut cs.clone(), self.hasher)?;
    }
}