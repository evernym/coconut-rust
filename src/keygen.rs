use crate::ps_sig::{Params, Sigkey, Verkey};
use crate::sss::get_shared_secret;
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};

/// Keygen done by trusted party using Shamir secret sharing. Creates signing and verification
/// keys for each signer. The trusted party will know every signer's secret keys and the
/// aggregate secret keys and can create signatures.
pub fn trusted_party_keygen(
    threshold: usize,
    total: usize,
    params: &Params,
) -> (
    FieldElement,
    FieldElementVector,
    Vec<(usize, Sigkey, Verkey)>,
) {
    let (secret_x, mut x) = get_shared_secret(threshold, total);
    let mut y = vec![];
    let mut secret_y = FieldElementVector::with_capacity(params.msg_count());
    for i in 0..params.msg_count() {
        let (sec_y, b) = get_shared_secret(threshold, total);
        secret_y.push(sec_y);
        y.push(b);
    }
    let mut res = vec![];
    for i in 0..total {
        let id = i + 1;
        let x_i = x.remove(&id).unwrap();
        let alpha_i = &params.g2 * &x_i;
        let mut y_i = vec![];
        let mut beta_i = vec![];
        for j in 0..params.msg_count() {
            y_i.push(y[j].remove(&id).unwrap());
            beta_i.push(&params.g2 * &y_i[j]);
        }

        res.push((
            id,
            Sigkey { x: x_i, y: y_i },
            Verkey {
                X_tilde: alpha_i,
                Y_tilde: beta_i,
            },
        ))
    }
    (secret_x, secret_y, res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sss::{reconstruct_secret, Polynomial};
    use crate::OtherGroupVec;
    use amcl_wrapper::group_elem::GroupElementVector;
    use std::collections::BTreeMap;

    #[test]
    fn test_keygen() {
        let threshold = 3;
        let total = 5;
        let msg_count = 7;
        let params = Params::new(msg_count, "test".as_bytes());
        let (_, _, keys) = trusted_party_keygen(threshold, total, &params);
        assert_eq!(keys.len(), total);
        for i in 0..total {
            assert_eq!(keys[i].0, i + 1);
            assert_eq!(keys[i].1.y.len(), msg_count);
            assert_eq!(keys[i].2.Y_tilde.len(), msg_count);
        }
    }

    #[test]
    fn test_keygen_reconstruction() {
        let threshold = 3;
        let total = 5;
        let msg_count = 7;
        let params = Params::new(msg_count, "test".as_bytes());
        let (secret_x, secret_y, keys) = trusted_party_keygen(threshold, total, &params);

        // Reconstruct secret key
        let mut shares_x = BTreeMap::<usize, FieldElement>::new();
        let mut shares_y = vec![BTreeMap::<usize, FieldElement>::new(); msg_count];
        for i in 0..threshold {
            shares_x.insert(keys[i].0, keys[i].1.x.clone());
            for j in 0..msg_count {
                shares_y[j].insert(keys[i].0, keys[i].1.y[j].clone());
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

        for (id, _, vk) in keys.into_iter().take(threshold) {
            let l = Polynomial::lagrange_basis_at_0(threshold, id);
            recon_X_tilde_bases.push(vk.X_tilde.clone());
            recon_X_tilde_exps.push(l.clone());

            for j in 0..msg_count {
                recon_Y_tilde_bases[j].push(vk.Y_tilde[j].clone());
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
}
