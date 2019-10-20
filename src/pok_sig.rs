// Proof of knowledge of signature. Uses `PoKOfSignature` from PS sig crate.

use crate::signature::{Params, Signature, Verkey};
use crate::{OtherGroup, OtherGroupVec, SignatureGroup, SignatureGroupVec};
use amcl_wrapper::group_elem::GroupElement;
use ps_sig::keys::Params as PSParams;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::trusted_party_SSS_keygen;
    use crate::signature::{BlindSignature, SignatureRequest, SignatureRequestPoK, transform_to_PS_params, transform_to_PS_verkey, transform_to_PS_sig};
    use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
    use ps_sig::pok_sig::PoKOfSignature;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_PoK_sig() {
        // Test proof of knowledge of signature and reveal some of the messages
        let threshold = 3;
        let total = 5;
        let msg_count = 6;
        let count_hidden = 2;
        let params = Params::new(msg_count, "test".as_bytes());
        let (_, _, signers) = trusted_party_SSS_keygen(threshold, total, &params);

        let msgs = FieldElementVector::random(msg_count);
        let (elg_sk, elg_pk) = elgamal_keygen!(&params.g);
        let (sig_req, randomness) = SignatureRequest::new(&msgs, count_hidden, &elg_pk, &params);

        // Initiate proof of knowledge of various items of Signature request
        let sig_req_pok = SignatureRequestPoK::init(&sig_req, &elg_pk, &params);

        // The challenge can include other things also (if proving other predicates)
        let challenge = FieldElement::from_msg_hash(&sig_req_pok.to_bytes());

        // Create proof once the challenge is finalized
        let hidden_msgs: FieldElementVector = msgs
            .iter()
            .take(count_hidden)
            .map(|m| m.clone())
            .collect::<Vec<FieldElement>>()
            .into();
        let sig_req_proof = sig_req_pok
            .gen_proof(&hidden_msgs, randomness, &elg_sk, &challenge)
            .unwrap();

        let mut blinded_sigs = vec![];
        for i in 0..threshold {
            // Each signer verifier proof of knowledge of items of signature request before signing
            assert!(sig_req_proof
                .verify(&sig_req, &elg_pk, &challenge, &params)
                .unwrap());
            blinded_sigs.push(BlindSignature::new(&sig_req, &signers[i].sigkey));
        }

        let mut unblinded_sigs = vec![];
        for i in 0..threshold {
            let unblinded_sig = blinded_sigs.remove(0).unblind(&elg_sk);
            unblinded_sigs.push((signers[i].id, unblinded_sig));
        }

        let aggr_sig = Signature::aggregate(threshold, unblinded_sigs);

        let aggr_vk = Verkey::aggregate(
            threshold,
            signers
                .iter()
                .map(|s| (s.id, &s.verkey))
                .collect::<Vec<(usize, &Verkey)>>(),
        );

        assert!(aggr_sig.verify(msgs.as_slice(), &aggr_vk, &params));

        let ps_params = transform_to_PS_params(&params);
        let ps_verkey = transform_to_PS_verkey(&aggr_vk);

        let ps_sig = transform_to_PS_sig(&aggr_sig);

        // Reveal the following messages to the verifier
        let mut revealed_msg_indices = HashSet::new();
        revealed_msg_indices.insert(3);
        revealed_msg_indices.insert(5);

        let pok = PoKOfSignature::init(
            &ps_sig,
            &ps_verkey,
                &ps_params,
            msgs.as_slice(),
            None,
            revealed_msg_indices.clone(),
        )
        .unwrap();
        let chal = FieldElement::from_msg_hash(&pok.to_bytes());
        let proof = pok.gen_proof(&chal).unwrap();

        // The prover reveals these messages
        let mut revealed_msgs = HashMap::new();
        for i in &revealed_msg_indices {
            revealed_msgs.insert(i.clone(), msgs[*i].clone());
        }

        assert!(proof
            .verify(&ps_verkey, &ps_params, revealed_msgs.clone(), &chal)
            .unwrap());
    }
}
