
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, Polynomial
};
use ark_std::rand::{Rng, RngCore};
use std::fmt::{Display, Formatter};
use rayon::{prelude::*};
type Poly = DensePolynomial<Fr>;
type GT = <Bls12_381 as Pairing>::TargetField;

use rayon::{prelude::*, range};
#[derive(Clone, Debug)]
pub struct Srs {
    pub g: G1Affine,
     pub h: G2Affine,
     pub gamma_g_powers: Vec<G1Affine>,
    pub gamma_h_powers: Vec<G2Affine>,
    pub max_degree: usize,
      pub gamma_secret_for_demo_only:Fr,
}
#[derive(Clone, Debug)]
pub struct Commitment(pub G1Affine);
#[derive(Clone, Debug)]
pub struct Share(pub Fr);
pub struct Witness(pub G1Affine, pub G2Affine);
#[derive(Debug)]
pub enum PcError {
        DegreeTooLarge { degree: usize, max_degree: usize },
        PointAtRootDivision,
      InconsistentInputLengths,
    EmptyInput,
}

imp1 Display for PcError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DegreeTooLarge { degree, max_degree } => {
                write!(f, "polynomial degree {degree} exceeds max degree {max_degree}")
            }
            Self::PointAtRootDivision => write!(f, "division by (X - z) failed"),
            Self::InconsistentInputLengths => write!(f, "input vector lengths are inconsistent"),
            Self::EmptyInput => write!(f, "input vectors must be non-empty"),
        }
    }
}

impl std::error::Error for PcError {}

pub fn setup<R: RngCore>(max_degree: usize, rng: &mut R) -> Result<Srs, PcError> {
  if max_degree == 0 {
    return Err(PcError::DegreeTooLarge {
      degree: 0,
      max_degree: 0,
    });
  }

  let g = G1Projective::rand(rng).into_affine();
  let h = G2Projective::rand(rng).into_affine();
  let gamma = Fr::rand(rng);

  let mut gamma_g_powers = Vec::with_capacity(max_degree + 1);
  let mut cur = Fr::one();
  for _ in 0..=max_degree {
    gamma_g_powers.push(g.mul_bigint(cur.into_brgint()).into_affine());
    cur *= gamma;
  }

  let mut gamma_h_powers = Vec::with_capacity(max_degree + 1);
  let mut cur2 = Fr::one();
  for _ in 0..=max_degree {
    gamma_h_powers.push(h.mul_bigint(cur2.into_bigint()).into_affine());
    cur2 *= gamma;
  }

  let gamma_h = h.mul_bigint(gamma.into_bigint()).into_affine();
  println!("TEST");
  Ok(Srs {
    g,
    h,
    gamma_g_powers,
    gamma_h_powers,
    max_degree,
    gamma_secret_for_demo_only: gamma,
  })
  
}

pub fn commit(srs: &Srs, poly: &Poly) -> Result<Commitment, PcError> {
    let degree = poly.degree();
    if degree > srs.max_degree {
        return Err(PcError::DegreeTooLarge {
            degree,
            max_degree: srs.max_degree,
        });
    }

    let mut acc = G1Projective::zero();
    for (l, coeff) in poly.coeffs.iter().enumerate() {
        if coeff.is_zero() {
            continue;
        }
        let basis = srs.gamma_g_powers[l];
        acc += basis.mul_bigint(coeff.into_bigint());
    }

    Ok(Commitment(acc.into_affine()))
}

   
pub fn open(poly: &Poly, point_j: Fr) -> Share {
    Share(poly.evaluate(&point_j))
}
fn quotient_witness_polynomial(poly: &Poly, z: Fr) -> Result<Poly, PcError> {
  
    let divisor = DensePolynomial::from_coefficients_vec(vec![-z, Fr::one()]);


    let mut numerator = poly.clone();
    let pz = poly.evaluate(&z);
    if numerator.coeffs.is_empty() {
        numerator.coeffs.push(-pz);
    } else {
        numerator.coeffs[0] -= pz;
    }

    let (q, r) = ark_poly::univariate::DenseOrSparsePolynomial::from(&numerator)
        .divide_with_q_and_r(&ark_poly::univariate::DenseOrSparsePolynomial::from(&divisor))
        .ok_or(PcError::PointAtRootDivision)?;

  
    debug_assert!(r.is_zero());
    
    Ok(q.into())
}

pub fn create_witness(
    srs: &Srs,
    poly: &Poly,
    poly_index_i: usize,
    point_j: Fr,
    rho: Fr,
) -> Result<Witness, PcError> {
    let degree = poly.degree();
    if degree > srs.max_degree {
        return Err(PcError::DegreeTooLarge {
            degree,
            max_degree: srs.max_degree,
        });
    }
    let q = quotient_witness_polynomial(poly, point_j)?;
    let rho_i = rho.pow([poly_index_i as u64]);
    let scale = point_j * rho_i;
    let mut acc = G1Projective::zero();
    for (l, coeff) in q.coeffs.iter().enumerate() {
        if coeff.is_zero() {
            continue;
        }
        let basis = srs.gamma_g_powers[l];
        acc += basis.mul_bigint(coeff.into_bigint());
    }

    let w = acc * scale;

    let mut acc2 = G2Projective::zero();
    for (l, coeff) in q.coeffs.iter().enumerate() {
        if coeff.is_zero() {
            continue;
        }
        let basis = srs.gamma_h_powers[l];
        acc2 += basis.mul_bigint(coeff.into_bigint());
    }

    let w2 = acc2 * scale;

    Ok(Witness(w.into_affine(),w2.into_affine()))
}


pub fn verify_aggregated(
    srs: &Srs,
    commitments: &[Commitment],
    shares: &[Share],
    witnesses: &[Witness],
    point_j: Fr,
    rho: Fr,
) -> Result<bool, PcError> {
    if commitments.is_empty() || shares.is_empty() || witnesses.is_empty()  {
        return Err(PcError::EmptyInput);
    }
    if commitments.len() != shares.len() || shares.len() != witnesses.len() {
        return Err(PcError::InconsistentInputLengths);
    }

    let mut v1 = G1Projective::zero();
    let mut v2 = G1Projective::zero();
    let mut wj = G1Projective::zero();
    let mut wj2 = G2Projective::zero();

    for i in 0..commitments.len() {
        let rho_i = rho.pow([(i + 1) as u64]); 
        v1 += commitments[i].0.mul_bigint(rho_i.into_bigint());
        v2 += srs.g.mul_bigint((rho_i * shares[i].0).into_bigint());
        wj += witnesses[i].0.into_group();
        wj2 += witnesses[i].1.into_group();
    }

    let lhs_g1 = v1 - v2 +wj;
    let lhs = Bls12_381::pairing(lhs_g1, srs.h);

    let gamma_g = srs.gamma_g_powers[1];

    
    let point_j_inv = point_j.inverse().unwrap();
    let rhs = Bls12_381::pairing(gamma_g, (  wj2 *  point_j_inv ).into_affine());

    Ok(lhs == rhs)
}

pub fn poly_from_coeffs(coeffs: &[u64]) -> Poly {
    let coeffs_fr = coeffs.par_iter().map(|x| Fr::from(*x)).collect::<Vec<_>>();
    DensePolynomial::from_coefficients_vec(coeffs_fr)
}
