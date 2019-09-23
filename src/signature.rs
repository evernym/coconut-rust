use crate::errors::CoconutError;
use crate::sss::Polynomial;
use crate::{ate_2_pairing, OtherGroup, OtherGroupVec, SignatureGroup, SignatureGroupVec};
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Params {
    pub g1: SignatureGroup,
    pub g2: OtherGroup,
    pub h: SignatureGroupVec,
}

impl Params {
    /// Generate g1, g2 and 1 h for each message. These are shared by all signers and users.
    /// "Setup" from paper.
    pub fn new(msg_count: usize, label: &[u8]) -> Self {
        let g1 = SignatureGroup::from_msg_hash(&[label, " : g1".as_bytes()].concat());
        let g2 = OtherGroup::from_msg_hash(&[label, " : g2".as_bytes()].concat());
        let mut h = SignatureGroupVec::with_capacity(msg_count);
        for i in 0..msg_count {
            h.push(SignatureGroup::from_msg_hash(
                &[label, " : y".as_bytes(), i.to_string().as_bytes()].concat(),
            ));
        }
        Self { g1, g2, h }
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub sigma_1: SignatureGroup,
    pub sigma_2: SignatureGroup,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindSignature {
    pub h: SignatureGroup,
    pub blinded: (SignatureGroup, SignatureGroup),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureRequest {
    pub known_messages: FieldElementVector,
    pub commitment: SignatureGroup,
    pub ciphertexts: Vec<(SignatureGroup, SignatureGroup)>,
}

impl Signature {
    /// First `count_hidden` messages are hidden from signer and thus need to be encrypted using Elgamal.
    /// "PrepareBlindSign" from paper.
    pub fn request(
        messages: &FieldElementVector,
        count_hidden: usize,
        elgamal_pubkey: &SignatureGroup,
        params: &Params,
    ) -> SignatureRequest {
        // TODO: Accept blindings for each hidden message
        assert!(messages.len() >= count_hidden);
        assert_eq!(messages.len(), params.h.len());

        // Commit to the hidden messages
        let mut bases: SignatureGroupVec = params
            .h
            .iter()
            .take(count_hidden)
            .map(|g| g.clone())
            .collect::<Vec<SignatureGroup>>()
            .into();
        bases.push(params.g1.clone());
        let mut exponents: FieldElementVector = messages
            .iter()
            .take(count_hidden)
            .map(|f| f.clone())
            .collect::<Vec<FieldElement>>()
            .into();
        let r = FieldElement::random();
        exponents.push(r);
        // commitment = h_1^m_1.h_2^m_2...h_count_hidden^m_count_hidden.g_1^r
        let commitment = bases.multi_scalar_mul_const_time(&exponents).unwrap();

        let h = SignatureGroup::from_msg_hash(&commitment.to_bytes());

        // Each element of `ciphertexts` is the elgamal ciphertext and the randomness used during encryption.
        // The randomness is used for proof of knowledge
        let ciphertexts = messages
            .iter()
            .take(count_hidden)
            .map(|m| elgamal_encrypt!(&params.g1, elgamal_pubkey, &(&h * m)))
            .collect::<Vec<(SignatureGroup, SignatureGroup, FieldElement)>>();

        // TODO: Add proof of knowledge of various forms.
        SignatureRequest {
            known_messages: messages
                .iter()
                .skip(count_hidden)
                .map(|f| f.clone())
                .collect::<Vec<FieldElement>>()
                .into(),
            commitment,
            // Don't output the randomness
            ciphertexts: ciphertexts
                .into_iter()
                .map(|c| (c.0, c.1))
                .collect::<Vec<(SignatureGroup, SignatureGroup)>>(),
        }
    }

    /// Signed creates a blinded signature. "BlindSign" from paper.
    pub fn new_blinded(
        sig_request: &SignatureRequest,
        sigkey: &Sigkey,
        params: &Params,
    ) -> BlindSignature {
        // TODO: Verify proof of knowledge of various forms.

        let hidden_msg_count = sig_request.ciphertexts.len();

        assert_eq!(
            hidden_msg_count + sig_request.known_messages.len(),
            sigkey.y.len()
        );

        let h = SignatureGroup::from_msg_hash(&sig_request.commitment.to_bytes());

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
        BlindSignature {
            h,
            blinded: (c_tilde_1, c_tilde_2),
        }
    }

    /// User unblinds the blinded signature received from a signer. "Unblind" from paper.
    pub fn new_unblinded(sig: BlindSignature, elgamal_sk: &FieldElement) -> Signature {
        let a_sk = &sig.blinded.0 * elgamal_sk;
        let sigma_2 = &sig.blinded.1 - &a_sk;
        Signature {
            sigma_1: sig.h,
            sigma_2,
        }
    }

    /// Create an aggregated signature. "AggCred" from paper.
    pub fn aggregate(
        threshold: usize,
        sigs: Vec<(usize, Signature)>,
        params: &Params,
    ) -> Signature {
        assert!(sigs.len() >= threshold);
        let mut s_bases = SignatureGroupVec::with_capacity(threshold);
        let mut s_exps = FieldElementVector::with_capacity(threshold);
        let sigma_1 = sigs[0].1.sigma_1.clone();

        for (id, sig) in sigs.into_iter().take(threshold) {
            let l = Polynomial::lagrange_basis_at_0(threshold, id);
            s_bases.push(sig.sigma_2.clone());
            s_exps.push(l);
        }
        let s = s_bases.multi_scalar_mul_const_time(&s_exps).unwrap();
        Signature {
            sigma_1,
            sigma_2: s,
        }
    }

    /// Verify a signature. Can verify unblinded sig received from a signer and the aggregate sig as well.
    pub fn verify(&self, messages: &FieldElementVector, vk: &Verkey, params: &Params) -> bool {
        assert_eq!(messages.len(), vk.Y_tilde.len());
        if self.sigma_1.is_identity() || self.sigma_2.is_identity() {
            return false;
        }
        let mut Y_m_bases = OtherGroupVec::with_capacity(messages.len());
        let mut Y_m_exps = FieldElementVector::with_capacity(messages.len());
        for i in 0..messages.len() {
            Y_m_bases.push(vk.Y_tilde[i].clone());
            Y_m_exps.push(messages[i].clone());
        }
        let Y_m = &vk.X_tilde + &(Y_m_bases.multi_scalar_mul_var_time(&Y_m_exps).unwrap());
        let e = ate_2_pairing(&self.sigma_1, &Y_m, &(self.sigma_2.negation()), &params.g2);
        e.is_one()
    }
}

impl Verkey {
    /// Create an aggregated verley.
    pub fn aggregate(threshold: usize, keys: Vec<(usize, &Verkey)>, params: &Params) -> Verkey {
        assert!(keys.len() >= threshold);
        let q = keys[0].1.Y_tilde.len();
        for i in 1..keys.len() {
            assert_eq!(q, keys[i].1.Y_tilde.len());
        }

        let mut X_tilde_bases = OtherGroupVec::with_capacity(threshold);
        let mut X_tilde_exps = FieldElementVector::with_capacity(threshold);

        //let mut Y_tilde_bases = Vec::<OtherGroupVec>::with_capacity(q);
        let mut Y_tilde_bases = vec![OtherGroupVec::with_capacity(threshold); q];
        let mut Y_tilde_exps = vec![FieldElementVector::with_capacity(threshold); q];

        for (id, vk) in keys.into_iter().take(threshold) {
            let l = Polynomial::lagrange_basis_at_0(threshold, id);
            X_tilde_bases.push(vk.X_tilde.clone());
            X_tilde_exps.push(l.clone());
            for j in 0..q {
                Y_tilde_bases[j].push(vk.Y_tilde[j].clone());
                Y_tilde_exps[j].push(l.clone());
            }
        }

        let X_tilde = X_tilde_bases
            .multi_scalar_mul_var_time(&X_tilde_exps)
            .unwrap();
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
    use crate::keygen::trusted_party_keygen;

    #[test]
    fn test_verkey_aggregation() {
        let threshold = 3;
        let total = 5;
        let msg_count = 7;
        let params = Params::new(msg_count, "test".as_bytes());
        let (secret_x, secret_y, keys) = trusted_party_keygen(threshold, total, &params);

        let aggr_vk = Verkey::aggregate(
            threshold,
            keys.iter()
                .map(|k| (k.0, &k.2))
                .collect::<Vec<(usize, &Verkey)>>(),
            &params,
        );

        let expected_X_tilde = &params.g2 * &secret_x;
        assert_eq!(expected_X_tilde, aggr_vk.X_tilde);

        for i in 0..msg_count {
            let expected_Y_tilde_i = &params.g2 * &secret_y[i];
            assert_eq!(expected_Y_tilde_i, aggr_vk.Y_tilde[i]);
        }
    }

    #[test]
    fn test_sign_verify() {
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
            assert!(unblinded_sig.verify(&msgs, &keys[i].2, &params));
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
    }
}
