// Shamir secret sharing, Pedersen Verifiable secret sharing

use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::{G1Vector, G1};

use std::collections::{HashMap, HashSet};

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

    // Evaluate polynomial at given `x`
    pub fn eval(&self, x: &FieldElement) -> FieldElement {
        if x.is_zero() {
            self.coefficients()[0].clone()
        } else {
            let exp = FieldElementVector::new_vandermonde_vector(x, self.degree() + 1);
            self.0.inner_product(&exp).unwrap()
        }
    }

    /// Return the Lagrange basis polynomial at x = 0 given the x coordinates
    pub fn lagrange_basis_at_0(x_coords: HashSet<usize>, i: usize) -> FieldElement {
        let mut numerator = FieldElement::one();
        let mut denominator = FieldElement::one();
        let i_as_field_elem = FieldElement::from(i as u64);
        for x in x_coords {
            if x == i {
                continue;
            }
            let neg_x = -FieldElement::from(x as u64); // -x
                                                       // numerator = numerator * -x
            numerator = &numerator * &neg_x;
            let i_minus_x = &i_as_field_elem + &neg_x; // i - x
                                                       // denominator = denominator * (i - x)
            denominator = &denominator * &i_minus_x;
        }
        denominator.inverse_mut();
        // (-x_coords[0]) * (-x_coords[1]) * ... / ((i - x_coords[0]) * (i - x_coords[1]) * ...)
        numerator * denominator
    }
}

/// Generate a random polynomial with the secret at the polynomial evaluation at 0.
fn get_shared_secret_with_polynomial(
    threshold: usize,
    total: usize,
) -> (FieldElement, HashMap<usize, FieldElement>, Polynomial) {
    let random_poly = Polynomial::random(threshold - 1);
    let secret = random_poly.eval(&FieldElement::zero());
    let shares = (1..=total)
        .map(|x| (x, random_poly.eval(&FieldElement::from(x as u64))))
        .collect::<HashMap<usize, FieldElement>>();
    (secret, shares, random_poly)
}

/// Generate a secret with its shares according to Shamir secret sharing.
/// Returns the secret and a map of share_id -> share
pub fn get_shared_secret(
    threshold: usize,
    total: usize,
) -> (FieldElement, HashMap<usize, FieldElement>) {
    let (secret, shares, _) = get_shared_secret_with_polynomial(threshold, total);
    (secret, shares)
}

pub fn reconstruct_secret(threshold: usize, shares: HashMap<usize, FieldElement>) -> FieldElement {
    assert!(shares.len() >= threshold);
    let mut secret = FieldElement::zero();
    let share_ids = shares
        .iter()
        .take(threshold)
        .map(|(i, _)| *i)
        .collect::<HashSet<usize>>();
    for id in share_ids.clone() {
        let share = shares.get(&id).unwrap();
        let l = Polynomial::lagrange_basis_at_0(share_ids.clone(), id);
        secret += &(&l * share)
    }
    secret
}

// Pedersen Verifiable secret sharing. Based on the paper "Non-interactive and information-theoretic
// secure verifiable secret sharing". https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF

/// Generators used for commitment.
pub fn PedersenVSS_gens(label: &[u8]) -> (G1, G1) {
    // For NUMS.
    let g = G1::from_msg_hash(&[label, " : g".as_bytes()].concat());
    let h = G1::from_msg_hash(&[label, " : h".as_bytes()].concat());
    (g, h)
}

/// Executed by dealer. Output commitment to secret, commitment to coefficients of both polynomials
/// and shares for each participant. Each participant has access to all commitments to coefficients
/// but only to its own share.
pub fn PedersenVSS_deal(
    threshold: usize,
    total: usize,
    g: &G1,
    h: &G1,
) -> (
    FieldElement,
    FieldElement,
    HashMap<usize, G1>,
    HashMap<usize, FieldElement>,
    HashMap<usize, FieldElement>,
) {
    let (s, s_shares, s_poly) = get_shared_secret_with_polynomial(threshold, total);
    let (t, t_shares, t_poly) = get_shared_secret_with_polynomial(threshold, total);
    let commitment_coeffs = (0..threshold)
        .map(|i| {
            (
                i,
                g.binary_scalar_mul(&h, &s_poly.coefficients()[i], &t_poly.coefficients()[i]),
            )
        })
        .collect::<HashMap<usize, G1>>();
    (s, t, commitment_coeffs, s_shares, t_shares)
}

/// Executed by each participant to verify its share received from the dealer.
pub fn PedersenVSS_verify_share(
    threshold: usize,
    id: usize,
    share: (&FieldElement, &FieldElement),
    commitment_coeffs: &HashMap<usize, G1>,
    g: &G1,
    h: &G1,
) -> bool {
    assert!(commitment_coeffs.len() >= threshold);
    // Check commitment_coeffs[0] * commitment_coeffs[1]^id * commitment_coeffs[2]^{id^2} * ... commitment_coeffs[threshold-1]^{id^threshold-1} == g^share.0 * h^share.1
    // => commitment_coeffs[0] * commitment_coeffs[1]^id * commitment_coeffs[2]^{id^2} * ... commitment_coeffs[threshold-1]^{id^threshold-1} * {g^share.0 * h^share.1}^-1 == 1

    // exp will be [1, id, id^2, ... id^threshold-1]
    let mut exp =
        FieldElementVector::new_vandermonde_vector(&FieldElement::from(id as u64), threshold);

    // add share.0 and share.1 to exp
    exp.push(share.0.clone());
    exp.push(share.1.clone());

    let mut bases = G1Vector::with_capacity(threshold + 2);
    for i in 0..threshold {
        bases.push(commitment_coeffs[&i].clone())
    }

    // g^share.0 and h^share.1 will need to be inverted. To do one multi-scalar multiplication,invert g and h
    bases.push(g.negation());
    bases.push(h.negation());

    bases.multi_scalar_mul_var_time(&exp).unwrap().is_identity()
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
            assert_eq!(shares.len(), total);
            let recon_secret = reconstruct_secret(threshold, shares);
            assert_eq!(secret, recon_secret);
        }
    }

    #[test]
    fn test_secret_sharing_1() {
        {
            let threshold = 5;
            let total = 10;
            let (secret, shares) = get_shared_secret(threshold, total);
            let mut some_shares = HashMap::<usize, FieldElement>::new();
            for i in vec![1, 3, 4, 7, 9] {
                some_shares.insert(i, shares.get(&i).unwrap().clone());
            }
            let recon_secret = reconstruct_secret(threshold, some_shares);
            assert_eq!(secret, recon_secret);
        }

        {
            let threshold = 3;
            let total = 5;
            let (secret, shares) = get_shared_secret(threshold, total);
            let mut some_shares = HashMap::<usize, FieldElement>::new();
            for i in vec![1, 2, 4] {
                some_shares.insert(i, shares.get(&i).unwrap().clone());
            }
            let recon_secret = reconstruct_secret(threshold, some_shares);
            assert_eq!(secret, recon_secret);
        }

        {
            let threshold = 2;
            let total = 5;
            let (secret, shares) = get_shared_secret(threshold, total);
            let mut some_shares = HashMap::<usize, FieldElement>::new();
            for i in vec![1, 4] {
                some_shares.insert(i, shares.get(&i).unwrap().clone());
            }
            let recon_secret = reconstruct_secret(threshold, some_shares);
            assert_eq!(secret, recon_secret);
        }

        {
            let threshold = 3;
            let total = 5;
            let (secret, shares) = get_shared_secret(threshold, total);
            let mut some_shares = HashMap::<usize, FieldElement>::new();
            for i in vec![1, 2, 4, 5] {
                some_shares.insert(i, shares.get(&i).unwrap().clone());
            }
            let recon_secret = reconstruct_secret(threshold, some_shares);
            assert_eq!(secret, recon_secret);
        }
    }

    #[test]
    fn test_Pedersen_VSS() {
        let threshold = 5;
        let total = 10;
        let (g, h) = PedersenVSS_gens("test".as_bytes());
        let (secret, _, comm_coeffs, s_shares, t_shares) =
            PedersenVSS_deal(threshold, total, &g, &h);
        assert_eq!(s_shares.len(), total);
        assert_eq!(t_shares.len(), total);
        assert_eq!(comm_coeffs.len(), threshold);
        for i in 1..=total {
            assert!(PedersenVSS_verify_share(
                threshold,
                i,
                (&s_shares[&i], &t_shares[&i]),
                &comm_coeffs,
                &g,
                &h
            ));
        }
        let recon_secret = reconstruct_secret(threshold, s_shares);
        assert_eq!(secret, recon_secret);
    }
}
