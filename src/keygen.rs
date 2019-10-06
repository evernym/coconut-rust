use crate::secret_sharing::{get_shared_secret, PedersenVSS};
use crate::signature::{Params, Sigkey, Verkey};
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem_g1::G1;
use std::collections::HashMap;

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
        let alpha_i = &params.g2 * &x_i;
        let mut y_i = vec![];
        let mut beta_i = vec![];
        for j in 0..params.msg_count() {
            y_i.push(y_shares[j].remove(&id).unwrap());
            beta_i.push(&params.g2 * &y_i[j]);
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
    FieldElement,
    FieldElementVector,
    Vec<Signer>,
    FieldElement,
    HashMap<usize, G1>,
    HashMap<usize, FieldElement>,
    HashMap<usize, FieldElement>,
    FieldElementVector,
    Vec<HashMap<usize, G1>>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_sharing::{reconstruct_secret, Polynomial};
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

        let expected_X_tilde = &params.g2 * &secret_x;
        assert_eq!(
            expected_X_tilde,
            recon_X_tilde_bases
                .multi_scalar_mul_var_time(&recon_X_tilde_exps)
                .unwrap()
        );

        for i in 0..msg_count {
            let expected_Y_tilde_i = &params.g2 * &secret_y[i];
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
                &h
            ));
            for j in 0..msg_count {
                assert!(PedersenVSS::verify_share(
                    threshold,
                    i,
                    (&y_shares[j][&i], &y_t_shares[j][&i]),
                    &comm_coeff_y[j],
                    &g,
                    &h
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
        // TODO: Use PedersenDVSSParticipant to show keygen works
    }
}
