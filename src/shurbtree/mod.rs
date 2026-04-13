use ark_bls12_381:: Fr as BlsFr;
use arkworks_native_gadgets::poseidon::{
        FieldHasher, Poseidon,
    };

use rayon::{prelude::*, range};

pub fn BuildShrubs(mut root: &mut Vec<BlsFr>, leaf: &[BlsFr], mut path: &mut Vec<BlsFr>, hasher: Poseidon::<BlsFr>) {
    let mut temp = vec![];

    for i in (0..leaf.len()).step_by(2) {
        if i == leaf.len()-1 || i == leaf.len()-2 {
            root.push(leaf[i].clone());
        }

        if i < leaf.len()-1 {
            temp.push(hasher.hash(&[leaf[i],leaf[i+1]]).unwrap());
        }
        if leaf.len() >= 2 && i == leaf.len() - 2 {
            path.push(leaf[i].clone());
        }
    }

    if !temp.is_empty() {
        BuildShrubs( &mut root, &temp, &mut path, hasher);
    }
}