use crate::errors::CoconutError;
use secret_sharing::polynomial::Polynomial;
use crate::{ate_2_pairing, OtherGroup, OtherGroupVec, SignatureGroup, SignatureGroupVec};
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use ps_sig::errors::PSError;
use ps_sig::keys::Params as PSParams;
use ps_sig::keys::Verkey as PSVerkey;
use ps_sig::signature::Signature as PSSignature;
use std::collections::HashSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Params {
    pub g: SignatureGroup,
    pub g_tilde: OtherGroup,
    pub h: SignatureGroupVec,
}

impl Params {
    /// Generate g1, g2 and 1 h for each message. These are shared by all signers and users.
    /// "Setup" from paper.
    pub fn new(msg_count: usize, label: &[u8]) -> Self {
        let g = SignatureGroup::from_msg_hash(&[label, " : g".as_bytes()].concat());
        let g_tilde = OtherGroup::from_msg_hash(&[label, " : g_tilde".as_bytes()].concat());
        let mut h = SignatureGroupVec::with_capacity(msg_count);
        for i in 0..msg_count {
            h.push(SignatureGroup::from_msg_hash(
                &[label, " : y".as_bytes(), i.to_string().as_bytes()].concat(),
            ));
        }
        Self { g, g_tilde, h }
    }

    pub fn msg_count(&self) -> usize {
        self.h.len()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sigkey {
    pub x: FieldElement,
    pub y: Vec<FieldElement>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Verkey {
    pub X_tilde: OtherGroup,
    pub Y_tilde: Vec<OtherGroup>,
}

/// Created by entity requesting a signature
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureRequest {
    pub known_messages: FieldElementVector,
    pub commitment: SignatureGroup,
    pub ciphertexts: Vec<(SignatureGroup, SignatureGroup)>,
}

/// Created by the signer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindSignature {
    pub h: SignatureGroup,
    pub blinded: (SignatureGroup, SignatureGroup),
}

/// Result of the unblinding of the blind signature. Is in the form of PS signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub sigma_1: SignatureGroup,
    pub sigma_2: SignatureGroup,
}

impl_PoK_VC!(
    ProverCommittingSignatureGroup,
    ProverCommittedSignatureGroup,
    ProofSignatureGroup,
    SignatureGroup,
    SignatureGroupVec
);

// TODO: Following transformations result in clonings. Fix them.
// Transform the params to Params struct of ps_sig crate
pub fn transform_to_PS_params(params: &Params) -> PSParams {
    PSParams {
        g: params.g.clone(),
        g_tilde: params.g_tilde.clone(),
    }
}

// Transform the verkey to Verkey struct of ps_sig crate
pub fn transform_to_PS_verkey(vk: &Verkey) -> PSVerkey {
    PSVerkey {
        X_tilde: vk.X_tilde.clone(),
        Y_tilde: vk.Y_tilde.clone(),
    }
}

// Transform the signature to Signature struct of ps_sig crate
pub fn transform_to_PS_sig(sig: &Signature) -> PSSignature {
    PSSignature {
        sigma_1: sig.sigma_1.clone(),
        sigma_2: sig.sigma_2.clone(),
    }
}

/// Created by entity requesting a signature to prove knowledge of hidden elements used in SignatureRequest.
/// Represents the commitment phase of Schnoor protocol
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureRequestPoK {
    pub pok_vc_elgamal_sk: ProverCommittedSignatureGroup,
    pub pok_vc_commitment: ProverCommittedSignatureGroup,
    pub pok_vc_ciphertext: Vec<(ProverCommittedSignatureGroup, ProverCommittedSignatureGroup)>,
}

/// Created by entity requesting a signature to prove knowledge of hidden elements used in SignatureRequest.
/// Represents the response phase of Schnoor protocol
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureRequestProof {
    pub proof_elgamal_sk: ProofSignatureGroup,
    pub proof_commitment: ProofSignatureGroup,
    pub proof_ciphertexts: Vec<(ProofSignatureGroup, ProofSignatureGroup)>,
}

impl SignatureRequest {
    /// First `count_hidden` messages are hidden from signer and thus need to be encrypted using Elgamal.
    /// "PrepareBlindSign" from paper.
    pub fn new(
        messages: &FieldElementVector,
        count_hidden: usize,
        elgamal_pubkey: &SignatureGroup,
        params: &Params,
    ) -> (Self, FieldElementVector) {
        assert!(messages.len() >= count_hidden);
        assert_eq!(messages.len(), params.h.len());

        // Randomness for commitment and ciphertexts. Used to prove knowleddge later on
        let mut randomness = FieldElementVector::with_capacity(count_hidden + 1);

        // Commit to the hidden messages
        let mut bases: SignatureGroupVec = params
            .h
            .iter()
            .take(count_hidden)
            .map(|g| g.clone())
            .collect::<Vec<SignatureGroup>>()
            .into();
        bases.push(params.g.clone());
        let mut exponents: FieldElementVector = messages
            .iter()
            .take(count_hidden)
            .map(|f| f.clone())
            .collect::<Vec<FieldElement>>()
            .into();
        let r = FieldElement::random();
        exponents.push(r.clone());
        // commitment = h_1^m_1.h_2^m_2...h_count_hidden^m_count_hidden.g_1^r
        let commitment = bases.multi_scalar_mul_const_time(&exponents).unwrap();

        randomness.push(r);

        let known_messages = messages
            .iter()
            .skip(count_hidden)
            .map(|f| f.clone())
            .collect::<Vec<FieldElement>>();

        // Each element of `ciphertexts` is the elgamal ciphertext and the randomness used during encryption.
        // The randomness is used for proof of knowledge
        let ciphertexts = if count_hidden > 0 {
            let h = Self::compute_h(&commitment, &known_messages);
            messages
                .iter()
                .take(count_hidden)
                .map(|m| {
                    let (c1, c2, k) = elgamal_encrypt!(&params.g, elgamal_pubkey, &(&h * m));
                    randomness.push(k);
                    (c1, c2)
                })
                .collect::<Vec<(SignatureGroup, SignatureGroup)>>()
        } else {
            vec![]
        };

        (
            Self {
                known_messages: known_messages.into(),
                commitment,
                ciphertexts,
            },
            randomness,
        )
    }

    /// Compute a generator in SignatureGroup by hashing commitment to hidden messages and all known messages.
    /// It is important that the for computing h, all messages in the signature are taken into account to
    /// prevent malleability.
    pub fn compute_h(
        commitment: &SignatureGroup,
        known_messages: &[FieldElement],
    ) -> SignatureGroup {
        let mut bytes = commitment.to_bytes();
        for m in known_messages {
            bytes.append(&mut m.to_bytes());
        }
        SignatureGroup::from_msg_hash(&bytes)
    }
}

impl SignatureRequestPoK {
    // Proof of knowledge using Schnorr protocol. There are multiple proof of knowledge protocols being done.
    // 1 for knowledge of Elgamal secret key, 1 for knowledge of hidden messages and randomness in the
    // commitment and 2 for each ciphertext. The protocol is broken down in 2 steps, pre-challenge and post challenge
    // so that it can be used in combination with other protocols
    // XXX Optimization idea: Since there are multiple Schnorr protocol executions resulting in a linear cost,
    // the inner product argument protocol from Bulletproofs can be used to make the cost logarithmic.
    pub fn init(
        sig_req: &SignatureRequest,
        elgamal_pk: &SignatureGroup,
        params: &Params,
    ) -> SignatureRequestPoK {
        assert_eq!(
            sig_req.known_messages.len() + sig_req.ciphertexts.len(),
            params.h.len()
        );

        // For knowledge of Elgamal secret key
        let mut committing_elgamal_sk = ProverCommittingSignatureGroup::new();
        committing_elgamal_sk.commit(&params.g, None);
        let committed_elgamal_sk = committing_elgamal_sk.finish();

        // For knowledge of hidden messages and randomness in the commitment
        let mut committing_comm = ProverCommittingSignatureGroup::new();
        // Since the hidden messages are same inside this commitment and ciphertexts, same blinding needs to be used.
        let mut hidden_msg_blindings = vec![];
        for h in params.h.iter().take(sig_req.ciphertexts.len()) {
            let b = FieldElement::random();
            committing_comm.commit(h, Some(&b));
            hidden_msg_blindings.push(b);
        }
        // For randomness
        committing_comm.commit(&params.g, None);
        let committed_comm = committing_comm.finish();

        let ciphertext_commts = if sig_req.ciphertexts.len() > 0 {
            // XXX: This computation can be avoided if h is persisted from `new`
            let h = SignatureRequest::compute_h(&sig_req.commitment, sig_req.known_messages.as_slice());

            let mut ciphertext_commts = vec![];
            for i in 0..sig_req.ciphertexts.len() {
                let mut committing_1 = ProverCommittingSignatureGroup::new();
                committing_1.commit(&params.g, None);

                let mut committing_2 = ProverCommittingSignatureGroup::new();
                committing_2.commit(elgamal_pk, None);
                // Use the same blinding for the hidden message used in the commitment
                committing_2.commit(&h, Some(&hidden_msg_blindings[i]));
                ciphertext_commts.push((committing_1.finish(), committing_2.finish()));
            }
            ciphertext_commts
        } else {
            vec![]
        };

        SignatureRequestPoK {
            pok_vc_elgamal_sk: committed_elgamal_sk,
            pok_vc_commitment: committed_comm,
            pok_vc_ciphertext: ciphertext_commts,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.append(&mut self.pok_vc_elgamal_sk.to_bytes());
        bytes.append(&mut self.pok_vc_commitment.to_bytes());
        for (pok_vc_1, pok_vc_2) in &self.pok_vc_ciphertext {
            bytes.append(&mut pok_vc_1.to_bytes());
            bytes.append(&mut pok_vc_2.to_bytes());
        }
        bytes
    }

    pub fn gen_proof(
        self,
        hidden_messages: &FieldElementVector,
        randomness: FieldElementVector,
        elgamal_sk: &FieldElement,
        challenge: &FieldElement,
    ) -> Result<SignatureRequestProof, CoconutError> {
        assert_eq!(self.pok_vc_ciphertext.len(), hidden_messages.len());
        assert_eq!(self.pok_vc_ciphertext.len(), randomness.len() - 1);

        // Proof of knowledge of Elgamal secret key.
        let proof_elgamal_sk = self
            .pok_vc_elgamal_sk
            .gen_proof(challenge, &[elgamal_sk.clone()])?;

        let mut secrets_commitment = vec![];
        for i in 0..hidden_messages.len() {
            secrets_commitment.push(hidden_messages[i].clone());
        }
        secrets_commitment.push(randomness[0].clone());
        let proof_commitment = self
            .pok_vc_commitment
            .gen_proof(challenge, &secrets_commitment)?;

        let mut proof_ciphertexts = vec![];
        for (i, (pok_vc_1, pok_vc_2)) in self.pok_vc_ciphertext.into_iter().enumerate() {
            let proof_1 = pok_vc_1.gen_proof(challenge, &[randomness[i + 1].clone()])?;
            let proof_2 = pok_vc_2.gen_proof(
                challenge,
                &[randomness[i + 1].clone(), hidden_messages[i].clone()],
            )?;
            proof_ciphertexts.push((proof_1, proof_2));
        }
        Ok(SignatureRequestProof {
            proof_elgamal_sk,
            proof_commitment,
            proof_ciphertexts,
        })
    }
}

impl SignatureRequestProof {
    pub fn verify(
        &self,
        sig_req: &SignatureRequest,
        elgamal_pk: &SignatureGroup,
        challenge: &FieldElement,
        params: &Params,
    ) -> Result<bool, CoconutError> {
        assert_eq!(self.proof_ciphertexts.len(), sig_req.ciphertexts.len());
        assert_eq!(
            self.proof_commitment.responses.len(),
            self.proof_ciphertexts.len() + 1
        );

        // Verify proof of knowledge of Elgamal secret key
        if !self
            .proof_elgamal_sk
            .verify(&[params.g.clone()], elgamal_pk, challenge)?
        {
            return Ok(false);
        }

        // Verify proof of knowledge of hidden messages in the commitment
        let mut bases = params
            .h
            .iter()
            .take(sig_req.ciphertexts.len())
            .map(|h| h.clone())
            .collect::<Vec<SignatureGroup>>();
        bases.push(params.g.clone());
        if !self
            .proof_commitment
            .verify(&bases, &sig_req.commitment, challenge)?
        {
            return Ok(false);
        }

        // XXX: This computation can be avoided if h is persisted`
        let h = SignatureRequest::compute_h(&sig_req.commitment, sig_req.known_messages.as_slice());
        let bases = vec![elgamal_pk.clone(), h];
        for (i, (proof_1, proof_2)) in self.proof_ciphertexts.iter().enumerate() {
            // The response for the hidden message should be same as that in the commitment.
            if proof_2.responses[1] != self.proof_commitment.responses[i] {
                return Ok(false);
            }

            if !proof_1.verify(&[params.g.clone()], &sig_req.ciphertexts[i].0, challenge)? {
                return Ok(false);
            }
            if !proof_2.verify(&bases, &sig_req.ciphertexts[i].1, challenge)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl BlindSignature {
    /// Signed creates a blinded signature. "BlindSign" from paper.
    pub fn new(sig_request: &SignatureRequest, sigkey: &Sigkey) -> Self {
        let hidden_msg_count = sig_request.ciphertexts.len();

        assert_eq!(
            hidden_msg_count + sig_request.known_messages.len(),
            sigkey.y.len()
        );

        let h = SignatureRequest::compute_h(
            &sig_request.commitment,
            sig_request.known_messages.as_slice(),
        );

        // The blinded signature is (h, c_tilde).
        // c_tilde = (a_1^y_1.a_2^y_2...a_hidden_msg_count^y_hidden_msg_count, b_1^y_1.b_2^y_2....b_hidden_msg_count^y_hidden_msg_count . h^(x + y_{hidden_msg_count+1}*m_{hidden_msg_count+1} + y_{hidden_msg_count+2}*m_{hidden_msg_count+2} + .. y_n*m_n))
        // where each (a_i, b_i) forms an element in `sig_request.ciphertexts`

        // c_tilde_1 = a_1^y_1.a_2^y_2...a_hidden_msg_count^y_hidden_msg_count
        let mut c_tilde_1_bases = SignatureGroupVec::with_capacity(hidden_msg_count);
        let mut c_tilde_1_exps = FieldElementVector::with_capacity(hidden_msg_count);

        // c_tilde_2 = b_1^y_1.b_2^y_2....b_hidden_msg_count^y_hidden_msg_count . h^(x + y_{hidden_msg_count+1}*m_{hidden_msg_count+1} + y_{hidden_msg_count+2}*m_{hidden_msg_count+2} + .. y_n*m_n)
        let mut c_tilde_2_bases = SignatureGroupVec::with_capacity(hidden_msg_count + 1);
        let mut c_tilde_2_exps = FieldElementVector::with_capacity(hidden_msg_count + 1);

        for (i, (a, b)) in sig_request.ciphertexts.iter().enumerate() {
            c_tilde_1_bases.push(a.clone());
            c_tilde_1_exps.push(sigkey.y[i].clone());

            c_tilde_2_bases.push(b.clone());
            c_tilde_2_exps.push(sigkey.y[i].clone());
        }

        // h^(x + y_j*m_j + y_{j+1}*m_{j+1}) for all known messages
        c_tilde_2_bases.push(h.clone());
        let mut exp = sigkey.x.clone();
        for i in 0..sig_request.known_messages.len() {
            exp += &sigkey.y[hidden_msg_count + i] * &sig_request.known_messages[i];
        }
        c_tilde_2_exps.push(exp);

        let c_tilde_1 = c_tilde_1_bases
            .multi_scalar_mul_const_time(&c_tilde_1_exps)
            .unwrap();
        let c_tilde_2 = c_tilde_2_bases
            .multi_scalar_mul_const_time(&c_tilde_2_exps)
            .unwrap();
        Self {
            h,
            blinded: (c_tilde_1, c_tilde_2),
        }
    }

    /// User unblinds the blinded signature received from a signer. "Unblind" from paper.
    pub fn unblind(self, elgamal_sk: &FieldElement) -> Signature {
        let a_sk = &self.blinded.0 * elgamal_sk;
        let sigma_2 = &self.blinded.1 - &a_sk;
        Signature {
            sigma_1: self.h,
            sigma_2,
        }
    }
}

impl Signature {
    /// Create an aggregated signature from signatures from various signers. "AggCred" from paper.
    pub fn aggregate(threshold: usize, sigs: Vec<(usize, Signature)>) -> Signature {
        assert!(sigs.len() >= threshold);
        let mut s_bases = SignatureGroupVec::with_capacity(threshold);
        let mut s_exps = FieldElementVector::with_capacity(threshold);
        let sigma_1 = sigs[0].1.sigma_1.clone();

        let signer_ids = sigs
            .iter()
            .take(threshold)
            .map(|(i, _)| *i)
            .collect::<HashSet<usize>>();
        for (id, sig) in sigs.into_iter().take(threshold) {
            let l = Polynomial::lagrange_basis_at_0(signer_ids.clone(), id);
            s_bases.push(sig.sigma_2.clone());
            s_exps.push(l);
        }
        // s = sigma_2[i]^l for all i
        let s = s_bases.multi_scalar_mul_const_time(&s_exps).unwrap();
        Signature {
            sigma_1,
            sigma_2: s,
        }
    }

    /// Verify a signature. Can verify unblinded sig received from a signer and the aggregate sig as well.
    pub fn verify(&self, messages: &[FieldElement], vk: &Verkey, params: &Params) -> bool {
        let p = transform_to_PS_params(params);
        let vk = transform_to_PS_verkey(vk);
        // TODO: Remove unwrap
        PSSignature::verify(&transform_to_PS_sig(&self), messages, &vk, &p).unwrap()
    }
}

impl Verkey {
    /// Create an aggregated verkey.
    pub fn aggregate(threshold: usize, keys: Vec<(usize, &Verkey)>) -> Verkey {
        assert!(keys.len() >= threshold);
        let q = keys[0].1.Y_tilde.len();
        for i in 1..keys.len() {
            assert_eq!(q, keys[i].1.Y_tilde.len());
        }

        let mut X_tilde_bases = OtherGroupVec::with_capacity(threshold);
        let mut X_tilde_exps = FieldElementVector::with_capacity(threshold);

        let mut Y_tilde_bases = vec![OtherGroupVec::with_capacity(threshold); q];
        let mut Y_tilde_exps = vec![FieldElementVector::with_capacity(threshold); q];

        let signer_ids = keys
            .iter()
            .take(threshold)
            .map(|(i, _)| *i)
            .collect::<HashSet<usize>>();
        for (id, vk) in keys.into_iter().take(threshold) {
            let l = Polynomial::lagrange_basis_at_0(signer_ids.clone(), id);
            X_tilde_bases.push(vk.X_tilde.clone());
            X_tilde_exps.push(l.clone());
            for j in 0..q {
                Y_tilde_bases[j].push(vk.Y_tilde[j].clone());
                Y_tilde_exps[j].push(l.clone());
            }
        }

        // X_tilde = X_tilde_1^l_1 * X_tilde_2^l_2 * ... X_tilde_i^l_i for i in threshold
        let X_tilde = X_tilde_bases
            .multi_scalar_mul_var_time(&X_tilde_exps)
            .unwrap();

        // Y_tilde = [Y_tilde_1^l_1 * Y_tilde_2^l_2 * ... Y_tilde_i^l_i for i in threshold, .. for all q]
        let mut Y_tilde = vec![];
        for i in 0..q {
            Y_tilde.push(
                Y_tilde_bases[i]
                    .multi_scalar_mul_var_time(&Y_tilde_exps[i])
                    .unwrap(),
            );
        }
        Self { X_tilde, Y_tilde }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::{
        setup_signers_for_test, trusted_party_PVSS_keygen, trusted_party_SSS_keygen, Signer,
    };
    use secret_sharing::pedersen_vss::PedersenVSS;

    fn check_key_aggregation(
        threshold: usize,
        msg_count: usize,
        secret_x: FieldElement,
        secret_y: FieldElementVector,
        signers: &[Signer],
        params: &Params,
    ) {
        let aggr_vk = Verkey::aggregate(
            threshold,
            signers
                .iter()
                .take(threshold)
                .map(|s| (s.id, &s.verkey))
                .collect::<Vec<(usize, &Verkey)>>(),
        );

        let expected_X_tilde = &params.g_tilde * &secret_x;
        assert_eq!(expected_X_tilde, aggr_vk.X_tilde);

        for i in 0..msg_count {
            let expected_Y_tilde_i = &params.g_tilde * &secret_y[i];
            assert_eq!(expected_Y_tilde_i, aggr_vk.Y_tilde[i]);
        }
    }

    fn check_key_aggregation_gaps_in_ids(
        threshold: usize,
        msg_count: usize,
        secret_x: FieldElement,
        secret_y: FieldElementVector,
        keys_to_aggr: Vec<(usize, &Verkey)>,
        params: &Params,
    ) {
        let aggr_vk = Verkey::aggregate(threshold, keys_to_aggr);

        let expected_X_tilde = &params.g_tilde * &secret_x;
        assert_eq!(expected_X_tilde, aggr_vk.X_tilde);

        for i in 0..msg_count {
            let expected_Y_tilde_i = &params.g_tilde * &secret_y[i];
            assert_eq!(expected_Y_tilde_i, aggr_vk.Y_tilde[i]);
        }
    }

    fn check_signing_on_random_msgs(
        threshold: usize,
        msg_count: usize,
        count_hidden: usize,
        signers: &[Signer],
        params: &Params,
    ) {
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
            assert!(unblinded_sig.verify(msgs.as_slice(), &signers[i].verkey, &params));
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
    }

    #[test]
    fn test_verkey_aggregation_shamir_secret_sharing_keygen() {
        let threshold = 3;
        let total = 5;
        let msg_count = 7;
        let params = Params::new(msg_count, "test".as_bytes());

        let (secret_x, secret_y, signers) = trusted_party_SSS_keygen(threshold, total, &params);

        check_key_aggregation(threshold, msg_count, secret_x, secret_y, &signers, &params)
    }

    #[test]
    fn test_verkey_aggregation_verifiable_secret_sharing_keygen() {
        let threshold = 3;
        let total = 5;
        let msg_count = 7;
        let params = Params::new(msg_count, "test".as_bytes());
        let (g, h) = PedersenVSS::gens("testPVSS".as_bytes());

        let keygen_res = trusted_party_PVSS_keygen(threshold, total, &params, &g, &h);
        let secret_x = keygen_res.0;
        let secret_y = keygen_res.1;
        let signers = keygen_res.2;

        check_key_aggregation(threshold, msg_count, secret_x, secret_y, &signers, &params)
    }

    #[test]
    fn test_sign_verify_shamir_secret_sharing_keygen() {
        let threshold = 3;
        let total = 5;
        let msg_count = 6;
        let count_hidden = 2;
        let params = Params::new(msg_count, "test".as_bytes());

        let (_, _, signers) = trusted_party_SSS_keygen(threshold, total, &params);

        check_signing_on_random_msgs(threshold, msg_count, count_hidden, &signers, &params)
    }

    #[test]
    fn test_sign_verify_verifiable_secret_sharing_keygen() {
        let threshold = 3;
        let total = 5;
        let msg_count = 6;
        let count_hidden = 2;
        let params = Params::new(msg_count, "test".as_bytes());
        let (g, h) = PedersenVSS::gens("testPVSS".as_bytes());

        let keygen_res = trusted_party_PVSS_keygen(threshold, total, &params, &g, &h);
        let signers = keygen_res.2;

        check_signing_on_random_msgs(threshold, msg_count, count_hidden, &signers, &params)
    }

    #[test]
    fn test_sign_verify_decentralized_verifiable_secret_sharing_keygen() {
        let threshold = 3;
        let total = 5;
        let msg_count = 6;
        let count_hidden = 2;
        let params = Params::new(msg_count, "test".as_bytes());
        let (g, h) = PedersenVSS::gens("testPVSS".as_bytes());

        let (_, _, signers) = setup_signers_for_test(threshold, total, &params, &g, &h);

        check_signing_on_random_msgs(threshold, msg_count, count_hidden, &signers, &params)
    }

    #[test]
    fn test_verkey_aggregation_gaps_in_ids_shamir_secret_sharing_keygen() {
        let threshold = 3;
        let total = 5;
        let msg_count = 7;
        let params = Params::new(msg_count, "test".as_bytes());
        let (secret_x, secret_y, signers) = trusted_party_SSS_keygen(threshold, total, &params);

        let mut keys_to_aggr = vec![];
        keys_to_aggr.push((signers[0].id, &signers[0].verkey));
        keys_to_aggr.push((signers[2].id, &signers[2].verkey));
        keys_to_aggr.push((signers[4].id, &signers[4].verkey));

        check_key_aggregation_gaps_in_ids(
            threshold,
            msg_count,
            secret_x,
            secret_y,
            keys_to_aggr,
            &params,
        );
    }

    #[test]
    fn test_verkey_aggregation_gaps_in_ids_verifiable_secret_sharing_keygen() {
        let threshold = 3;
        let total = 5;
        let msg_count = 7;
        let params = Params::new(msg_count, "test".as_bytes());
        let (g, h) = PedersenVSS::gens("testPVSS".as_bytes());

        let keygen_res = trusted_party_PVSS_keygen(threshold, total, &params, &g, &h);
        let secret_x = keygen_res.0;
        let secret_y = keygen_res.1;
        let signers = keygen_res.2;

        let mut keys_to_aggr = vec![];
        keys_to_aggr.push((signers[0].id, &signers[0].verkey));
        keys_to_aggr.push((signers[2].id, &signers[2].verkey));
        keys_to_aggr.push((signers[4].id, &signers[4].verkey));

        check_key_aggregation_gaps_in_ids(
            threshold,
            msg_count,
            secret_x,
            secret_y,
            keys_to_aggr,
            &params,
        );
    }

    #[test]
    fn test_sign_verify_1() {
        // Request signature from 1 threshold group of signers and form aggregate verkey from
        // different threshold group of signers.
        let threshold = 3;
        let total = 6;
        let msg_count = 6;
        let count_hidden = 2;
        let params = Params::new(msg_count, "test".as_bytes());
        let (_, _, signers) = trusted_party_SSS_keygen(threshold, total, &params);

        let msgs = FieldElementVector::random(msg_count);
        let (elg_sk, elg_pk) = elgamal_keygen!(&params.g);

        let (sig_req, randomness) = SignatureRequest::new(&msgs, count_hidden, &elg_pk, &params);

        // Signers from which signature will be requested.
        let mut signer_ids = HashSet::new();
        signer_ids.insert(1);
        signer_ids.insert(3);
        signer_ids.insert(5);

        let sig_req_pok = SignatureRequestPoK::init(&sig_req, &elg_pk, &params);
        let challenge = FieldElement::from_msg_hash(&sig_req_pok.to_bytes());
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
        for i in &signer_ids {
            assert!(sig_req_proof
                .verify(&sig_req, &elg_pk, &challenge, &params)
                .unwrap());
            // Keys at index i have id i+1
            blinded_sigs.push(BlindSignature::new(&sig_req, &signers[*i - 1].sigkey));
        }

        let mut unblinded_sigs = vec![];
        for i in &signer_ids {
            let unblinded_sig = blinded_sigs.remove(0).unblind(&elg_sk);
            // Keys at index i have id i+1
            assert!(unblinded_sig.verify(msgs.as_slice(), &signers[*i - 1].verkey, &params));
            unblinded_sigs.push((signers[*i - 1].id, unblinded_sig));
        }

        let aggr_sig = Signature::aggregate(threshold, unblinded_sigs);

        let mut keys_to_aggr = vec![];
        keys_to_aggr.push((signers[1].id, &signers[1].verkey));
        keys_to_aggr.push((signers[3].id, &signers[3].verkey));
        keys_to_aggr.push((signers[5].id, &signers[5].verkey));

        let aggr_vk = Verkey::aggregate(threshold, keys_to_aggr);

        assert!(aggr_sig.verify(msgs.as_slice(), &aggr_vk, &params));
    }
}
