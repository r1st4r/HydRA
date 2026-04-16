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

pub fn Find_Path(leaves: &[BlsFr], leaf: BlsFr, value: usize, mut path: &mut Vec<BlsFr>, mut index: &mut Vec<bool>, hasher: Poseidon::<BlsFr>) {
    // Implementation for finding the path in the Merkle tree
}

pub fn Build_Static_Shrubs(mut root: &mut Vec<BlsFr>, leaves: &[BlsFr], hasher: Poseidon::<BlsFr>) {
    let len = leaves.len();
    if len == 0 {
        return 
    }

    let temp: Vec<BlsFr> = leaves
        .par_chunks(2)
        .filter(|chunk| chunk.len() == 2)
        .map(|chunk| {
            let a = chunk[0];
            let b = chunk[1];
            hasher.hash(&[a,b]).unwrap()
        })
        .collect();
    let last_i = if len % 2 == 0 { len - 2 } else { len - 1 };
    root.push(leaves[last_i]);

    if !temp.is_empty() {
        Build_Static_Shrubs(root, &temp, hasher);
    }
}

pub fn Find_Shrubs_Path(leaves: &[BlsFr], value: usize, mut path: &mut Vec<BlsFr>, mut index: &mut Vec<bool>, hasher: Poseidon::<BlsFr>) {
    if value % 2 == 1 {
        index.push(false);
        path.push(leaves[value - 1]);
    } else {
        index.push(true);
        path.push(leaves[value + 1]);
    }
}