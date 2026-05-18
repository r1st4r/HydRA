use ark_r1cs_std::{boolean::Boolean, alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use arkworks_r1cs_gadgets::poseidon::FieldHasherGadget;
use crate::{DeviceConfigInfor};
use ark_bls12_381:: Fr as BlsScalar;
use num_bigint::BigUint;
#[derive(Copy, Debug)]
pub struct AttestationCircuit<'a,  HG: FieldHasherGadget<BlsScalar>> {
    pk: BlsScalar,
    sk: BlsScalar,
    ar: BlsScalar,
    time: BlsScalar,
    period: BlsScalar,
    output: BlsScalar,
    root: &'a [BlsScalar],
    path: Option<&'a [BlsScalar]>,
    tag: Option<&'a [bool]>,
    hasher: &'a HG::Native,
}

#[allow(dead_code)]
impl<'a,  HG: FieldHasherGadget<BlsScalar>> AttestationCircuit<'a, HG> {
    pub fn new(
        // pk: F,
        // sk: F,
        // ar: F,
        // time: F,
        // period: F,
        // output: F,
        device_config: &DeviceConfigInfor,
        root: &'a [BlsScalar],
        path: Option<&'a [BlsScalar]>,
        tag: Option<&'a [bool]>,
        hasher: &'a HG::Native,
    ) -> Self {
        Self {
            pk: BlsScalar::from(BigUint::from_bytes_be(device_config.verifying_key.to_encoded_point(true).as_bytes())),  //BlsScalar::from(BigUint::from_bytes_be(device_config.verifying_key.to_encoded_point(true).as_bytes()))
            sk:  BlsScalar::from(BigUint::from_bytes_be(&device_config.signing_key.to_bytes()[..])), //  BlsScalar::from(BigUint::from_bytes_be(device_config.signing_key.to_bytes()[..]))
            ar: device_config.measured_value, 
            period: BlsScalar::from(device_config.period.as_secs()),  //BlsScalar::from(device_config.period.as_secs())
            output: device_config.authorized_infor,
            time: BlsScalar::from(device_config.timestamp.as_secs()), //BlsScalar::from(device_config.timestamp.as_secs())
            root,
            path,
            tag,
            hasher,
        }
    }
}

impl<'a,  HG: FieldHasherGadget<BlsScalar>> Clone for AttestationCircuit<'a,  HG> {
    fn clone(&self) -> Self {
        AttestationCircuit {
            pk: self.pk,
            sk: self.sk,
            ar: self.ar,
            period: self.period,
            output: self.output,
            root: self.root,
            time: self.time,
            tag: self.tag,
            path: self.path,
            hasher: self.hasher,
        }
    }
}

impl<'a,  HG: FieldHasherGadget<BlsScalar>> ConstraintSynthesizer<BlsScalar>
    for AttestationCircuit<'a,  HG>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<BlsScalar>) -> Result<(), SynthesisError> {
        let sk = FpVar::new_witness(cs.clone(), || Ok(self.sk))?;
        let ar = FpVar::new_witness(cs.clone(), || Ok(self.ar))?;

        let pk = FpVar::<BlsScalar>::new_input(cs.clone(), || Ok(self.pk))?;

        let root: Vec<_> = self
            .root
            .iter()
            .map(|x| FpVar::<BlsScalar>::new_input(cs.clone(), || Ok(*x)))
            .collect::<Result<Vec<_>, _>>()?;

        let output = FpVar::<BlsScalar>::new_input(cs.clone(), || Ok(self.output))?;
        let time = FpVar::<BlsScalar>::new_input(cs.clone(), || Ok(self.time))?;
        let period = FpVar::<BlsScalar>::new_input(cs.clone(), || Ok(self.period))?;

        let hasher_gadget: HG = 
            FieldHasherGadget::<BlsScalar>::from_native(&mut cs.clone(), self.hasher.clone())?;

        let m = hasher_gadget.hash(&[ar.clone(), sk.clone()])?;
        let mut leaf = hasher_gadget.hash(&[m, pk.clone()])?;

        match (self.path, self.tag) {
            (Some(path_values), Some(tag_values)) => {
                if path_values.len() != tag_values.len() {
                    return Err(SynthesisError::Unsatisfiable);
                }

                let path: Vec<_> = path_values
                    .iter()
                    .map(|x| FpVar::<BlsScalar>::new_witness(cs.clone(), || Ok(*x)))
                    .collect::<Result<Vec<_>, _>>()?;

                for i in 0..tag_values.len() {
                    if tag_values[i] {
                        leaf = hasher_gadget.hash(&[
                            leaf.clone(),
                            path[i].clone(),
                        ])?;
                    } else {
                        leaf = hasher_gadget.hash(&[
                            path[i].clone(),
                            leaf.clone(),
                        ])?;
                    }
                }

                let mut res = Boolean::<BlsScalar>::constant(false);

                for root_i in root.iter() {
                    let is_equal = leaf.is_eq(root_i)?;
                    res = res.or(&is_equal)?;
                }

                res.enforce_equal(&Boolean::TRUE)?;
            }

            (None, None) => {
                leaf.enforce_equal(&root[0])?;
            }

            _ => {
                return Err(SynthesisError::Unsatisfiable);
            }
        }

        let result_1 = hasher_gadget.hash(&[pk, ar])?;
        let result_2 = hasher_gadget.hash(&[result_1, time])?;
        let result = hasher_gadget.hash(&[result_2, period])?;

        output.enforce_equal(&result)?;

        Ok(())
    }
}