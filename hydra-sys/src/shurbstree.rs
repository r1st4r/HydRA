use ark_bls12_381:: Fr as BlsScalar;
use arkworks_native_gadgets::poseidon::{
		FieldHasher, Poseidon,
	};
use rayon::prelude::*;

pub fn exponents_of_two(mut x: usize) -> Vec<isize> {
    let mut exps = Vec::with_capacity(x.count_ones() as usize);
    while x != 0 {
        let tz = x.trailing_zeros(); // 当前最低位1所在的指数
        exps.push(tz as isize);
        x &= x - 1; // 清除最低位的1
    }
    exps
}

pub fn insert_shrubs_tree(
    t_root: &mut Vec<BlsScalar>,
    vect: &[BlsScalar],
    mut k: isize,
    exps: &[isize],
    mut ll: usize,
    hasher: &Poseidon<BlsScalar>,
)  {
    for i in vect.iter() {
        println!("leaves: {}", i);
    }
     println!("***********");
    let should_insert_root = ll < exps.len() && k + 2 == exps[ll];

    let mut temp = Vec::with_capacity(vect.len() / 2 + if should_insert_root { 1 } else { 0 });

    if should_insert_root {
        let root_index = k + 2;
        assert!(root_index >= 0, "k + 2 must be non-negative");

        ll += 1;
        temp.push(t_root[root_index as usize]);
    }

    let results: Vec<BlsScalar> = vect
        .par_chunks_exact(2)
        .map(|chunk| {
            hasher
                .hash(&[chunk[0], chunk[1]][..])
                .expect("Poseidon hash failed")
        })
        .collect();

    temp.extend(results);

    let last_i = vect.len() - if vect.len() % 2 == 0 { 2 } else { 1 };

    k += 1;
  
   if t_root.len () -1  >= k as usize {
        t_root[k as usize] = vect[last_i];
   } else {
        t_root.push(vect[last_i]);
   }
    
    if !temp.is_empty() {
        insert_shrubs_tree(t_root, &temp, k,  exps, ll, hasher)
    } 


}

pub fn create_batch_devices(
    root: &mut Vec<BlsScalar>,
    leaves: &[BlsScalar],
    hasher: &Poseidon<BlsScalar>,
) {
    let len = leaves.len();

    if len == 0 {
        return;
    }

    // for i in leaves.iter() {
    //     println!("leaves: {}", i);
    // }

    // println!("------------");

    let temp: Vec<BlsScalar> = leaves
        .par_chunks(2)
        .filter(|chunk| chunk.len() == 2)
        .map(|chunk| {
            let a = chunk[0];
            let b = chunk[1];

            hasher.hash(&[a, b][..]).unwrap()
        })
        .collect();

    let last_i = if len % 2 == 0 { len - 2 } else { len - 1 };

    root.push(leaves[last_i]);

    if !temp.is_empty() {
        create_batch_devices(root, &temp, hasher);
    }
}

pub fn find_shrubs_path_test(
    root: &[BlsScalar],
    leaves: &[BlsScalar],
    mut j: usize,
    value: usize,
    mut path: &mut Vec<BlsScalar>,
    mut index: &mut Vec<bool>,
    hasher: &Poseidon<BlsScalar>,
) {
    if value % 2 == 1 {
        index.push(false);
        path.push(leaves[value - 1]);
    } else {
        index.push(true);
        path.push(leaves[value + 1]);
    }

    let temp: Vec<BlsScalar> = leaves
        .par_chunks(2)
        .filter(|chunk| chunk.len() == 2)
        .map(|chunk| {
            let a = chunk[0];
            let b = chunk[1];

            hasher.hash(&[a, b][..]).unwrap()
        })
        .collect();

    if temp.len() >= 2 {
        let val = value / 2;
        j += 1;

        if temp[val] == root[j] {
            return;
        }

        find_shrubs_path_test(root, &temp, j, val, &mut path, &mut index, hasher);
    }
}


pub fn find_shrubs_path(
    root: &[BlsScalar],
    leaves: &[BlsScalar],
    j: usize,
    value: usize,
    hasher: &Poseidon<BlsScalar>,
) -> Option<(Vec<BlsScalar>, Vec<bool>)> {
    if leaves.len() >= 2 && root[0] == leaves[value] {
        return None;
    }

    if leaves.is_empty() || value >= leaves.len() {
        return None;
    }

    let mut path = Vec::<BlsScalar>::new();
    let mut index = Vec::<bool>::new();

    let sibling_index = if value % 2 == 1 {
        index.push(false);
        value.checked_sub(1)?
    } else {
        index.push(true);
        value.checked_add(1)?
    };

    let sibling = leaves.get(sibling_index)?;
    path.push(*sibling);

    let temp: Vec<BlsScalar> = leaves
        .par_chunks(2)
        .filter(|chunk| chunk.len() == 2)
        .map(|chunk| {
            let a = chunk[0];
            let b = chunk[1];

            hasher.hash(&[a, b][..]).unwrap()
        })
        .collect();

    if temp.len() >= 2 {
        let val = value / 2;
        let next_j = j + 1;

        if val >= temp.len() || next_j >= root.len() {
            return None;
        }

        if temp[val] == root[next_j] {
            return Some((path, index));
        }

        let (mut sub_path, mut sub_index) =
            find_shrubs_path(root, &temp, next_j, val, hasher)?;

        path.append(&mut sub_path);
        index.append(&mut sub_index);

        return Some((path, index));
    }

    Some((path, index))
}

pub fn find_merkle_path (leaves: &[BlsScalar],  value: usize, mut path: &mut Vec<BlsScalar>, mut index: &mut Vec<bool>, hasher: &Poseidon<BlsScalar> ) {
   
    if value % 2 == 1 {
            index.push(false);
            path.push(leaves[value-1]);
        } else {
            index.push(true);
            path.push(leaves[value+1]);
    }
    
    let temp: Vec<BlsScalar> = leaves
        .par_chunks(2)
        .filter(|chunk| chunk.len() == 2)
        .map(|chunk| {
            let a = chunk[0];
            let b = chunk[1];
            hasher.hash(&[a,b][..]).unwrap()
        })
        .collect();
    

    if temp.len() >= 2 {
           let val = value / 2;
           find_merkle_path(&temp, val, &mut path, &mut index, hasher);
    }

}

fn largest_power_two_leq(n: usize) -> usize {
    assert!(n > 0);

    let mut p = 1usize;

    while p <= n / 2 {
        p <<= 1;
    }

    p
}


pub fn find_interval_index(
    arr: &[BlsScalar],
    target: &BlsScalar,
) -> Option<(Vec<BlsScalar>, usize)> {
    if arr.is_empty() {
        return None;
    }


    let target_index = arr.iter().position(|x| x == target)?;

    let mut start = 0usize;
    let mut remaining = arr.len();

    while remaining > 0 {
        let interval_len = largest_power_two_leq(remaining);
        let end = start + interval_len;


        if target_index >= start && target_index < end {

            if interval_len == 1 {
                return None;
            }

            let interval = arr[start..end].to_vec();

            let index_in_interval: usize = target_index - start;

            return Some((interval, index_in_interval));
        }

        start = end;
        remaining -= interval_len;
    }

    None
}

fn insert_single_decive(
    leaf: BlsScalar,
    mut next_index: usize,
    root: &mut Vec<BlsScalar>,
    hasher: &Poseidon<BlsScalar>,
) -> usize {
    let _leaf_index = next_index;
    let mut current_index = next_index;
    next_index = next_index + 1;

    let mut current_level_hash = leaf;

    for i in 0..=root.len() {
        if current_index % 2 == 0 {
            if i == root.len() {
                root.push(current_level_hash);
            } else {
                root[i] = current_level_hash;
            }

            break;
        } else {
            let left = root[i];
            let right = current_level_hash;

            current_level_hash = hasher.hash(&[left, right][..]).unwrap();
            current_index = current_index / 2;
        }
    }

    return next_index;
}