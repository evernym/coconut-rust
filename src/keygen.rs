use secret_sharing::shamir_secret_sharing::get_shared_secret;
use secret_sharing::pedersen_vss::PedersenVSS;

use crate::signature::{Params, Sigkey, Verkey};
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem_g1::G1;
use std::collections::HashMap;
use secret_sharing::pedersen_dvss::PedersenDVSSParticipant;

pub struct Signer {
    pub id: usize,
    pub sigkey: Sigkey,
    pub verkey: Verkey,
}

/// Takes shares for x and y and generate signing and verification keys
fn keygen_from_shares(
    num_signers: usize,
    mut x_shares: HashMap<usize, FieldElement>,
    mut y_shares: Vec<HashMap<usize, FieldElement>>,
    params: &Params,
) -> Vec<Signer> {
    let mut signers = vec![];
    for i in 0..num_signers {
        let id = i + 1;
        let x_i = x_shares.remove(&id).unwrap();
        let alpha_i = &params.g_tilde * &x_i;
        let mut y_i = vec![];
        let mut beta_i = vec![];
        for j in 0..params.msg_count() {
            y_i.push(y_shares[j].remove(&id).unwrap());
            beta_i.push(&params.g_tilde * &y_i[j]);
        }

        signers.push(Signer {
            id,
            sigkey: Sigkey { x: x_i, y: y_i },
            verkey: Verkey {
                X_tilde: alpha_i,
                Y_tilde: beta_i,
            },
        })
    }
    signers
}

/// Keygen done by trusted party using Shamir secret sharing. Creates signing and verification
/// keys for each signer. The trusted party will know every signer's secret keys and the
/// aggregate secret keys and can create signatures.
/// Outputs 3 items, first 2 are shared secrets and should be destroyed.
/// The last vector contains the keys, 1 item corresponding to each signer.
/// "TTPKeyGen" from paper
pub fn trusted_party_SSS_keygen(
    threshold: usize,
    total: usize,
    params: &Params,
) -> (FieldElement, FieldElementVector, Vec<Signer>) {
    let (secret_x, x_shares) = get_shared_secret(threshold, total);
    let mut y = vec![];
    let mut secret_y = FieldElementVector::with_capacity(params.msg_count());
    for _ in 0..params.msg_count() {
        let (sec_y, y_shares) = get_shared_secret(threshold, total);
        secret_y.push(sec_y);
        y.push(y_shares);
    }
    (
        secret_x,
        secret_y,
        keygen_from_shares(total, x_shares, y, params),
    )
}

/// Keygen done by trusted party using Pedersen verifiable secret sharing.
pub fn trusted_party_PVSS_keygen(
    threshold: usize,
    total: usize,
    params: &Params,
    g: &G1,
    h: &G1,
) -> (
    FieldElement,       // shared secret for x
    FieldElementVector, // shared secret for each y
    Vec<Signer>,
    FieldElement,       // blinding for x
    HashMap<usize, G1>, // commitment to coefficients for polynomial for x
    HashMap<usize, FieldElement>,
    HashMap<usize, FieldElement>,
    FieldElementVector,      // blindings for each y
    Vec<HashMap<usize, G1>>, // commitment to coefficients for polynomial for each y
    Vec<HashMap<usize, FieldElement>>,
    Vec<HashMap<usize, FieldElement>>,
) {
    let (secret_x, secret_x_t, comm_coeff_x, x_shares, x_t_shares) =
        PedersenVSS::deal(threshold, total, g, h);
    let mut y = vec![];
    let mut secret_y = FieldElementVector::with_capacity(params.msg_count());
    let mut secret_y_t = FieldElementVector::with_capacity(params.msg_count());
    let mut comm_coeff_y_vec = vec![];
    let mut y_t = vec![];
    for _ in 0..params.msg_count() {
        let (sec_y, sec_y_t, comm_coeff_y, y_shares, y_t_shares) =
            PedersenVSS::deal(threshold, total, g, h);
        secret_y.push(sec_y);
        secret_y_t.push(sec_y_t);
        comm_coeff_y_vec.push(comm_coeff_y);
        y.push(y_shares);
        y_t.push(y_t_shares);
    }
    (
        secret_x,
        secret_y,
        keygen_from_shares(total, x_shares.clone(), y.clone(), params),
        secret_x_t,
        comm_coeff_x,
        x_shares,
        x_t_shares,
        secret_y_t,
        comm_coeff_y_vec,
        y,
        y_t,
    )
}

/// Create participants that take part in a decentralized secret sharing and perform the secret sharing.
#[cfg(test)]
pub fn share_secret_for_testing(
    threshold: usize,
    total: usize,
    g: &G1,
    h: &G1,
) -> Vec<PedersenDVSSParticipant> {
    let mut participants = vec![];

    // Each participant generates a new secret and verifiable shares of that secret for everyone.
    for i in 1..=total {
        let p = PedersenDVSSParticipant::new(i, threshold, total, g, h);
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
            recv_p.received_share(id, comm_coeffs, (s, t), threshold, total, g, h);
        }
    }

    // Every participant computes its share to the distributed secret.
    for i in 0..total {
        participants[i].compute_final_comm_coeffs_and_shares(threshold, total, g, h);
    }
    participants
}

/// Create signers with their keys generated using Pedersen decentralized secret sharing
#[cfg(test)]
pub(crate) fn setup_signers_for_test(
    threshold: usize,
    total: usize,
    params: &Params,
    g: &G1,
    h: &G1,
) -> (FieldElement, FieldElementVector, Vec<Signer>) {

    let mut secret_x = FieldElement::zero();
    let mut secret_y = FieldElementVector::with_capacity(params.msg_count());

    let mut x_shares: HashMap<usize, FieldElement> = HashMap::new();
    let mut y_shares: Vec<HashMap<usize, FieldElement>> = vec![];

    // Each participant generates its share for `x`
    let participants_x = share_secret_for_testing(threshold, total, &g, &h);
    for i in 0..total {
        x_shares.insert(participants_x[i].id, participants_x[i].secret_share.clone());
        secret_x += &participants_x[i].secret;
    }

    for _ in 0..params.msg_count() {
        let mut y: HashMap<usize, FieldElement> = HashMap::new();
        let mut sec_y = FieldElement::zero();
        // Each participant generates its share for a `y`
        let participants_y = share_secret_for_testing(threshold, total, &g, &h);
        for i in 0..total {
            y.insert(participants_y[i].id, participants_y[i].secret_share.clone());
            sec_y += &participants_y[i].secret;
        }
        y_shares.push(y);
        secret_y.push(sec_y);
    }

    let signers = keygen_from_shares(total, x_shares, y_shares, params);
    (secret_x, secret_y, signers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secret_sharing::polynomial::Polynomial;
    use secret_sharing::shamir_secret_sharing::reconstruct_secret;
    use crate::OtherGroupVec;
    use amcl_wrapper::group_elem::GroupElementVector;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_keygen() {
        let threshold = 3;
        let total = 5;
        let msg_count = 7;
        let params = Params::new(msg_count, "test".as_bytes());
        let (_, _, signers) = trusted_party_SSS_keygen(threshold, total, &params);
        assert_eq!(signers.len(), total);
        for i in 0..total {
            assert_eq!(signers[i].id, i + 1);
            assert_eq!(signers[i].sigkey.y.len(), msg_count);
            assert_eq!(signers[i].verkey.Y_tilde.len(), msg_count);
        }
    }

    fn check_reconstructed_keys(
        threshold: usize,
        msg_count: usize,
        secret_x: FieldElement,
        secret_y: FieldElementVector,
        signers: &[Signer],
        params: &Params,
    ) {
        // Reconstruct secret key
        let mut shares_x = HashMap::<usize, FieldElement>::new();
        let mut shares_y = vec![HashMap::<usize, FieldElement>::new(); msg_count];
        for i in 0..threshold {
            shares_x.insert(signers[i].id, signers[i].sigkey.x.clone());
            for j in 0..msg_count {
                shares_y[j].insert(signers[i].id, signers[i].sigkey.y[j].clone());
            }
        }
        let recon_sec_x = reconstruct_secret(threshold, shares_x);
        assert_eq!(secret_x, recon_sec_x);

        for i in 0..msg_count {
            let recon_sec_y = reconstruct_secret(threshold, shares_y[i].clone());
            assert_eq!(secret_y[i], recon_sec_y);
        }

        // Reconstruct public key
        let mut recon_X_tilde_bases = OtherGroupVec::with_capacity(threshold);
        let mut recon_X_tilde_exps = FieldElementVector::with_capacity(threshold);

        let mut recon_Y_tilde_bases = vec![OtherGroupVec::with_capacity(threshold); msg_count];
        let mut recon_Y_tilde_exps = vec![FieldElementVector::with_capacity(threshold); msg_count];

        let signer_ids = signers
            .iter()
            .take(threshold)
            .map(|s| s.id)
            .collect::<HashSet<usize>>();

        for signer in signers.into_iter().take(threshold) {
            let l = Polynomial::lagrange_basis_at_0(signer_ids.clone(), signer.id);
            recon_X_tilde_bases.push(signer.verkey.X_tilde.clone());
            recon_X_tilde_exps.push(l.clone());

            for j in 0..msg_count {
                recon_Y_tilde_bases[j].push(signer.verkey.Y_tilde[j].clone());
                recon_Y_tilde_exps[j].push(l.clone());
            }
        }

        let expected_X_tilde = &params.g_tilde * &secret_x;
        assert_eq!(
            expected_X_tilde,
            recon_X_tilde_bases
                .multi_scalar_mul_var_time(&recon_X_tilde_exps)
                .unwrap()
        );

        for i in 0..msg_count {
            let expected_Y_tilde_i = &params.g_tilde * &secret_y[i];
            assert_eq!(
                expected_Y_tilde_i,
                recon_Y_tilde_bases[i]
                    .multi_scalar_mul_var_time(&recon_Y_tilde_exps[i])
                    .unwrap()
            );
        }
    }

    #[test]
    fn test_keygen_reconstruction_shamir_secret_sharing() {
        let threshold = 3;
        let total = 5;
        let msg_count = 7;
        let params = Params::new(msg_count, "test".as_bytes());

        let (secret_x, secret_y, signers) = trusted_party_SSS_keygen(threshold, total, &params);

        check_reconstructed_keys(threshold, msg_count, secret_x, secret_y, &signers, &params);
    }

    #[test]
    fn test_keygen_reconstruction_verifiable_secret_sharing() {
        let threshold = 3;
        let total = 5;
        let msg_count = 7;
        let params = Params::new(msg_count, "test".as_bytes());
        let (g, h) = PedersenVSS::gens("testPVSS".as_bytes());

        let (
            secret_x,
            secret_y,
            signers,
            _,
            comm_coeff_x,
            x_shares,
            x_t_shares,
            _,
            comm_coeff_y,
            y_shares,
            y_t_shares,
        ) = trusted_party_PVSS_keygen(threshold, total, &params, &g, &h);

        for i in 1..=total {
            assert!(PedersenVSS::verify_share(
                threshold,
                i,
                (&x_shares[&i], &x_t_shares[&i]),
                &comm_coeff_x,
                &g,
                &h,
            ));
            for j in 0..msg_count {
                assert!(PedersenVSS::verify_share(
                    threshold,
                    i,
                    (&y_shares[j][&i], &y_t_shares[j][&i]),
                    &comm_coeff_y[j],
                    &g,
                    &h,
                ));
            }
        }

        check_reconstructed_keys(threshold, msg_count, secret_x, secret_y, &signers, &params);
    }

    #[test]
    fn test_keygen_reconstruction_decentralized_verifiable_secret_sharing() {
        let threshold = 3;
        let total = 5;
        let msg_count = 7;
        let params = Params::new(msg_count, "test".as_bytes());
        let (g, h) = PedersenVSS::gens("testPVSS".as_bytes());

        let (secret_x, secret_y, signers) =
            setup_signers_for_test(threshold, total, &params, &g, &h);

        check_reconstructed_keys(threshold, msg_count, secret_x, secret_y, &signers, &params);
    }
}
