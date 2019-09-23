// Shamir secret sharing

use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use std::collections::{BTreeMap, HashMap};

pub struct Polynomial(FieldElementVector);

impl Polynomial {
    /// Return a randomly chosen polynomial (each coefficient is randomly chosen) of degree `degree`.
    pub fn random(degree: usize) -> Self {
        Self(FieldElementVector::random(degree + 1)) // +1 for constant term
    }

    pub fn degree(&self) -> usize {
        self.0.len() - 1
    }

    /// Return coefficients starting from lowest degree term
    pub fn coefficients(&self) -> &FieldElementVector {
        &self.0
    }

    pub fn eval(&self, x: &FieldElement) -> FieldElement {
        let mut exp = FieldElementVector::new_vandermonde_vector(x, self.degree() + 1);
        if x.is_zero() {
            // `new_vandermonde_vector` will return all elements as 0 if `x` is 0
            exp[0] = FieldElement::one()
        }
        self.0.inner_product(&exp).unwrap()
    }

    /// Return the Lagrange basis polynomial at x = 0 when the given points at x coordinate starting from
    pub fn lagrange_basis_at_0(threshold: usize, i: usize) -> FieldElement {
        let mut numerator = FieldElement::one();
        let mut denominator = FieldElement::one();
        let i_as_field_elem = FieldElement::from(i as u64);
        for j in 1..=threshold {
            if j == i {
                continue;
            }
            let neg_j = -FieldElement::from(j as u64); // -j
            numerator = &numerator * &neg_j;
            let i_minus_j = &i_as_field_elem + &neg_j; // i - j
            denominator = &denominator * &i_minus_j;
        }
        denominator.inverse_mut();
        numerator * denominator
    }
}

/// Generate a secret with its shares according to Shamir secret sharing.
/// Returns the secret and a map of share_id -> share
pub fn get_shared_secret(
    threshold: usize,
    total: usize,
) -> (FieldElement, BTreeMap<usize, FieldElement>) {
    // TODO: Replace btreemap with hashmap. Should work for missing share ids.
    let random_poly = Polynomial::random(threshold - 1);
    let secret = random_poly.coefficients()[0].clone();
    let shares = (1..=total)
        .map(|x| (x, random_poly.eval(&FieldElement::from(x as u64))))
        .collect::<BTreeMap<usize, FieldElement>>();
    (secret, shares)
}

pub fn reconstruct_secret(threshold: usize, shares: BTreeMap<usize, FieldElement>) -> FieldElement {
    let mut secret = FieldElement::zero();
    for (id, share) in shares.into_iter().take(threshold) {
        let l = Polynomial::lagrange_basis_at_0(threshold, id);
        secret += &(&l * &share)
    }
    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly() {
        for _ in 0..10 {
            let degree = 10;
            let poly = Polynomial::random(degree);
            assert_eq!(poly.degree(), degree);
            let coeffs = poly.coefficients();

            // Evaluation at 0 results in coefficient of constant term
            assert_eq!(poly.eval(&FieldElement::zero()), coeffs[0]);

            // Evaluation at 1 results in sum of all coefficients
            assert_eq!(poly.eval(&FieldElement::one()), coeffs.sum());
        }
    }

    #[test]
    fn test_secret_sharing() {
        for _ in 0..10 {
            let threshold = 5;
            let total = 10;
            let (secret, shares) = get_shared_secret(threshold, total);
            let recon_secret = reconstruct_secret(threshold, shares);
            assert_eq!(secret, recon_secret);
        }
    }
}
