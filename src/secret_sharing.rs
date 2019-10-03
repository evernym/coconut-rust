// Shamir secret sharing, Pedersen Verifiable secret sharing, Pedersen Decentralized Verifiable secret sharing

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
        let neg_i = -i_as_field_elem; // -i
        for x in x_coords {
            if x == i {
                continue;
            }
            // numerator = numerator * x
            let x_as_field_elem = FieldElement::from(x as u64);
            numerator = &numerator * &x_as_field_elem;
            let x_minus_i = &x_as_field_elem + &neg_i;
            // denominator = denominator * (x - i)
            denominator = &denominator * &x_minus_i;
        }
        denominator.inverse_mut();
        // (x_coords[0]) * (x_coords[1]) * ... / ((x_coords[0] - i) * (x_coords[1] - i) * ...)
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
// secure verifiable secret sharing", section 4. https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF.
/* The basic idea is the following
    Dealer wants to share a secret s in k-of-n manner with n participants
    Dealer commits to secret s with randomness t so C_0 = C(s, t) = g^s.h^t
    Create polynomial F(x) = s + F_1.x + F_2.x^2 + ... F_{k-1}.x^{k-1} such that F(0) = s.
    Create polynomial G(x) = t + G_1.x + G_2.x^2 + ... G_{k-1}.x^{k-1} such that G(0) = t.
    Commits to coefficients as C_1 = C(F_1, G_1), C_2 = C(F_2, G_2),... till C_k = C(F_k, G_k), broadcast to all n participants
    Dealer sends (F(i), G(i)) to participant i
    Each participant verifies C(F(i), G(i)) = C_0 * C_1^i * C_2^{i^2} * ... C_{k-1}^{k-1}
*/
pub struct PedersenVSS {}

impl PedersenVSS {
    /// Generators used for commitment.
    pub fn gens(label: &[u8]) -> (G1, G1) {
        // For NUMS.
        let g = G1::from_msg_hash(&[label, " : g".as_bytes()].concat());
        let h = G1::from_msg_hash(&[label, " : h".as_bytes()].concat());
        (g, h)
    }

    /// Executed by dealer. Output commitment to secret, commitment to coefficients of both polynomials
    /// and shares for each participant. Each participant has access to all commitments to coefficients
    /// but only to its own share.
    pub fn deal(
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
    pub fn verify_share(
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
}

// Pedersen Decentralized Verifiable secret sharing. Based on the paper "Non-interactive and information-theoretic
// secure verifiable secret sharing", section 5. https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF
// Does not involve a trusted third party but assumes that all participants (and not just threshold) participate till the end.
// Even if one participant aborts, the protocol needs to be restarted. A workaround is for each participant to ignore the 
// faulty participant's share essentially making it such that the faulty participant was never there.
/*
    n participants want to generate a shared secret s k-of-n manner
    Each of the n participants chooses a secret and runs a VSS for that secret in k-of-n manner. Say participant i chooses a secret s_i_0
    The shared secret s the becomes sum of secrets chosen by all n participants so s = s_1_0 + s_2_0 + s_3_0 + ... s_n_0
    After each of the n participants has successfully runs a VSS, they generate their corresponding share of s by adding
    their shares of each s_i_0 for i in 1 to n.
*/
// TODO: Model the state machine better
pub struct PedersenDVSSParticipant {
    pub id: usize,
    pub secret: FieldElement,
    pub comm_coeffs: HashMap<usize, G1>,
    pub s_shares: HashMap<usize, FieldElement>,
    pub t_shares: HashMap<usize, FieldElement>,
    all_comm_coeffs: HashMap<usize, HashMap<usize, G1>>,
    all_shares: HashMap<usize, (FieldElement, FieldElement)>,
    // XXX: Should be in a different struct if the protocol is modelled as a state machine
    pub final_comm_coeffs: HashMap<usize, G1>,
    pub secret_share: FieldElement,
}

impl PedersenDVSSParticipant {
    /// Generates a new secret and verifiable shares of that secret for every participant
    pub fn new(id: usize, threshold: usize, total: usize, g: &G1, h: &G1) -> Self {
        let (secret, _, comm_coeffs, s_shares, t_shares) =
            PedersenVSS::deal(threshold, total, &g, &h);
        // TODO: As mentioned in the paper, there should be a signature from the participant for non-repudiation
        Self {
            id,
            secret,
            comm_coeffs,
            s_shares,
            t_shares,
            all_comm_coeffs: HashMap::new(),
            all_shares: HashMap::new(),
            final_comm_coeffs: HashMap::new(),
            secret_share: FieldElement::new(),
        }
    }

    /// Called by a participant when it receives a share from another participant with id `sender_id`
    pub fn received_share(
        &mut self,
        sender_id: usize,
        comm_coeffs: HashMap<usize, G1>,
        share: (FieldElement, FieldElement),
        threshold: usize,
        total: usize,
        g: &G1,
        h: &G1,
    ) {
        assert!(sender_id <= total);
        assert!(!self.all_comm_coeffs.contains_key(&sender_id));
        assert!(!self.all_shares.contains_key(&sender_id));
        // Verify received share
        assert!(PedersenVSS::verify_share(
            threshold,
            self.id,
            (&share.0, &share.1),
            &comm_coeffs,
            &g,
            &h
        ));
        self.all_comm_coeffs.insert(sender_id, comm_coeffs);
        self.all_shares.insert(sender_id, share);
    }

    /// Called by a participant when it has received shares from all participants. Computes the final
    /// share of the distributed secret
    pub fn compute_final_comm_coeffs_and_shares(
        &mut self,
        threshold: usize,
        total: usize,
        g: &G1,
        h: &G1,
    ) {
        assert_eq!(self.all_comm_coeffs.len(), total - 1);
        assert_eq!(self.all_shares.len(), total - 1);

        // Compute own share and commitment to coefficients of the distributed secret.
        for i in 0..threshold {
            let mut cm = G1::identity();
            for j in 1..=total {
                if j != self.id {
                    cm += self.all_comm_coeffs[&j].get(&i).unwrap();
                } else {
                    cm += self.comm_coeffs.get(&i).unwrap();
                }
            }
            self.final_comm_coeffs.insert(i, cm);
        }

        let mut final_s_share = FieldElement::zero();
        let mut final_t_share = FieldElement::zero();
        for i in 1..=total {
            let (s, t) = if i != self.id {
                let tpl = &self.all_shares[&i];
                (&tpl.0, &tpl.1)
            } else {
                (&self.s_shares[&i], &self.t_shares[&i])
            };
            final_s_share += s;
            final_t_share += t;
        }

        // Verify computed share of the distributed secret
        assert!(PedersenVSS::verify_share(
            threshold,
            self.id,
            (&final_s_share, &final_t_share),
            &self.final_comm_coeffs,
            &g,
            &h
        ));

        self.secret_share = final_s_share;
    }
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
            let recon_secret = reconstruct_secret(
                threshold,
                shares
                    .into_iter()
                    .take(threshold)
                    .collect::<HashMap<usize, FieldElement>>(),
            );
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
        let (g, h) = PedersenVSS::gens("test".as_bytes());
        let (secret, _, comm_coeffs, s_shares, t_shares) =
            PedersenVSS::deal(threshold, total, &g, &h);
        assert_eq!(s_shares.len(), total);
        assert_eq!(t_shares.len(), total);
        assert_eq!(comm_coeffs.len(), threshold);
        for i in 1..=total {
            assert!(PedersenVSS::verify_share(
                threshold,
                i,
                (&s_shares[&i], &t_shares[&i]),
                &comm_coeffs,
                &g,
                &h
            ));
        }
        let recon_secret = reconstruct_secret(
            threshold,
            s_shares
                .into_iter()
                .take(threshold)
                .collect::<HashMap<usize, FieldElement>>(),
        );
        assert_eq!(secret, recon_secret);
    }

    #[test]
    fn test_Pedersen_DVSS() {
        let threshold = 5;
        let total = 10;
        let (g, h) = PedersenVSS::gens("test".as_bytes());
        let mut participants = vec![];

        // Each participant generates a new secret and verifiable shares of that secret for everyone.
        for i in 1..=total {
            let p = PedersenDVSSParticipant::new(i, threshold, total, &g, &h);
            participants.push(p);
        }

        // Every participant gives shares of its secret to others
        for i in 0..total {
            for j in 0..total {
                if i == j {
                    continue;
                }
                let (id, comm_coeffs, (s, t)) = (
                    participants[j].id.clone(),
                    participants[j].comm_coeffs.clone(),
                    (
                        participants[j].s_shares[&(i + 1)].clone(),
                        participants[j].t_shares[&(i + 1)].clone(),
                    ),
                );

                let recv_p = &mut participants[i];
                recv_p.received_share(id, comm_coeffs, (s, t), threshold, total, &g, &h);
            }
        }

        // Every participant computes its share to the distributed secret.
        for i in 0..total {
            participants[i].compute_final_comm_coeffs_and_shares(threshold, total, &g, &h);
        }

        let mut expected_shared_secret = FieldElement::zero();
        for p in &participants {
            expected_shared_secret += &p.secret;
        }
        let mut shares = HashMap::new();
        for i in 0..threshold {
            shares.insert(participants[i].id, participants[i].secret_share.clone());
        }

        // Verify that the secret can be recomputed.
        let recon_secret = reconstruct_secret(threshold, shares);

        assert_eq!(expected_shared_secret, recon_secret);
    }
}
