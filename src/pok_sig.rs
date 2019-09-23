// Proof of knowledge of signature. Uses `PoKOfSignature` from PS sig crate.

use crate::signature::{Params, Signature, Verkey};
use crate::{OtherGroup, OtherGroupVec, SignatureGroup, SignatureGroupVec};
use amcl_wrapper::group_elem::GroupElement;
use ps_sig::keys::Verkey as PSVerkey;
use ps_sig::pok_sig::PoKOfSignature;
use ps_sig::signature::Signature as PSSignature;

// Transform the verkey to Verkey struct of ps_sig crate so that it can be used in the proof of knowledge protocol (PoKOfSignature).
pub fn transform_to_PS_verkey(vk: &Verkey, params: &Params) -> PSVerkey {
    PSVerkey {
        g: params.g1.clone(),
        g_tilde: params.g2.clone(),
        X_tilde: vk.X_tilde.clone(),
        Y: vec![SignatureGroup::new(); vk.Y_tilde.len()],
        Y_tilde: vk.Y_tilde.clone(),
    }
}

// Transform the signature to Signature struct of ps_sig crate so that it can be used in the proof of knowledge protocol (PoKOfSignature).
pub fn transform_to_PS_sig(sig: &Signature) -> PSSignature {
    PSSignature {
        sigma_1: sig.sigma_1.clone(),
        sigma_2: sig.sigma_2.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::trusted_party_keygen;
    use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_PoK_sig() {
        // Test proof of knowledge of signature
        let threshold = 3;
        let total = 5;
        let msg_count = 6;
        let count_hidden = 2;
        let params = Params::new(msg_count, "test".as_bytes());
        let (_, _, keys) = trusted_party_keygen(threshold, total, &params);

        let msgs = FieldElementVector::random(msg_count);
        let (elg_sk, elg_pk) = elgamal_keygen!(&params.g1);

        let sig_req = Signature::request(&msgs, count_hidden, &elg_pk, &params);

        let mut blinded_sigs = vec![];
        for i in 0..threshold {
            blinded_sigs.push(Signature::new_blinded(&sig_req, &keys[i].1, &params));
        }

        let mut unblinded_sigs = vec![];
        for i in 0..threshold {
            let unblinded_sig = Signature::new_unblinded(blinded_sigs[i].clone(), &elg_sk);
            unblinded_sigs.push((keys[i].0, unblinded_sig));
        }

        let aggr_sig = Signature::aggregate(threshold, unblinded_sigs, &params);

        let aggr_vk = Verkey::aggregate(
            threshold,
            keys.iter()
                .map(|k| (k.0, &k.2))
                .collect::<Vec<(usize, &Verkey)>>(),
            &params,
        );

        assert!(aggr_sig.verify(&msgs, &aggr_vk, &params));

        let ps_verkey = transform_to_PS_verkey(&aggr_vk, &params);
        let ps_sig = transform_to_PS_sig(&aggr_sig);

        let pok =
            PoKOfSignature::init(&ps_sig, &ps_verkey, msgs.as_slice(), HashSet::new()).unwrap();
        let chal = FieldElement::from_msg_hash(&pok.to_bytes());
        let proof = pok.gen_proof(&chal).unwrap();

        assert!(proof.verify(&ps_verkey, HashMap::new(), &chal).unwrap());
    }
}
