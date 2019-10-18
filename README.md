# Coconut: Threshold Issuance Selective Disclosure Credentials with Applications to Distributed Ledgers

Based on the Coconut paper, [arxiv link](https://arxiv.org/pdf/1802.07344.pdf), [NDSS submission](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_06A-1_Sonnino_paper.pdf). Can use Shamir secret sharing 
or Pedersen verifiable secret sharing (centalized and decentralized versions available) for key generation. 
Centralized keygen is done by a trusted third party. This trusted party's role ends at key generation. 
The decentralized version of Pedersen's secret sharing can be used to avoid the trusted third party.

## API
1. Generate system parameters.
    ```rust
    let threshold = 3;     // threshold number of participants
    let total = 5;         // total number of participants
    let msg_count = 6;     // total attributes in credential
    let count_hidden = 2;  // number of attributes hidden from issuers.
    let params = Params::new(msg_count, "test-label".as_bytes());
    ```

1. Keygen for issuer. This could be a distributed keygen procedure or something done by a 
trusted third party. For prototyping, the code used the latter.
    ```rust
       // Below is an example of keys generated with Shamir secret sharing
       // signers is a vector of struct `Signer` which corresponds to a single signer and contains a signer id, a signing and a 
       // verification key
        pub struct Signer {
             pub id: usize,
             pub sigkey: Sigkey,
             pub verkey: Verkey,
        }
        let (_, _, signers: Vec<Signer>) = trusted_party_SSS_keygen(threshold, total, &params);
       
       // Below is an example of Pedersen verifiable secret sharing
       let (g, h) = PedersenVSS::gens("testPVSS-label".as_bytes());
       // `secret_x` and `secret_y` are the combined secrets and should never be given away. Only use for testing.
       // `x_shares` an `y_shares` are shares of the secrets x and y (vector)
       // `comm_coeff_x` and `comm_coeff_y` are commitments to coefficients of polynomial used to share `secret_x` and `secret_y`
       // `signers` is a vector of struct `Signer` like above
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
       
       // Each participant can verify its share as
       PedersenVSS::verify_share(
           threshold,
           participant_id,
           (&x_shares[&i], &x_t_shares[&i]),
           &comm_coeff_x,
           &g,
           &h
       )
       
       PedersenVSS::verify_share(
           threshold,
           participant_id,
           (&y_shares[j][&i], &y_t_shares[j][&i]),
           &comm_coeff_y[j],
           &g,
           &h
       ) 
    ```
    Also provided a decentralized (no trusted third party) verifiable secret sharing which 
    can be used for keygen. Use `PedersenDVSSParticipant`. Look at tests `test_Pedersen_DVSS`, `test_keygen_reconstruction_decentralized_verifiable_secret_sharing`,
    `test_sign_verify_decentralized_verifiable_secret_sharing_keygen` for examples of secret sharing, key generation and signing respectively
           
1. User takes his attributes, generates an Elgamal keypair and creates a signature request 
to be sent to Signers (Issuers)
    ```rust
   let msgs = FieldElementVector::random(msg_count);
   let (elg_sk, elg_pk) = elgamal_keygen!(&params.g1);
   // sig_req is the signature request. randomness will be used to create proof of knowledge of 
   // various elements in the signature request 
   let (sig_req, randomness) = SignatureRequest::new(&msgs, count_hidden, &elg_pk, &params);
    ```

1. Create a proof of knowledge of hidden messages, elgamal secret key and others.
    ```rust
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
    ```

1. Each signer will verify the proof and create a blind signature which is sent back to user.
    ```rust
   assert!(sig_req_proof.verify(&sig_req, &elg_pk, &challenge, &params));
   let blinded_sig = BlindSignature::new(&sig_req, &sig_key);
    ```
   
1. User unblinds the signature and verifies correctness of signature
    ```rust
    let unblinded_sig = blinded_sig.unblind(&elg_sk);
    unblinded_sig.verify(&msgs, &verkey, &params);
    ```

1.  User aggregates the unblinded signatures and verifies correctness of the 
    aggregated signature
    ```rust
    let aggr_sig = Signature::aggregate(threshold, unblinded_sigs);
    // keys is a vector of tuples containing signer id and verification key (usize, Verkey)
    let aggr_vk = Verkey::aggregate(
                threshold,
                keys
            );
    assert!(aggr_sig.verify(&msgs, &aggr_vk, &params));
    ```

1. To prove knowledge of signature, transform the verkey and signature to 
an appropriate structure and then use the Schnorr protocol similar to above
    ```rust
   let ps_verkey = transform_to_PS_verkey(&aggr_vk, &params);
   let ps_sig = transform_to_PS_sig(&aggr_sig);
   
   // Empty HashSet indicates that no message is being revealed, only knowledge of signature is proved
   let pok =
       PoKOfSignature::init(&ps_sig, &ps_verkey, msgs.as_slice(), HashSet::new()).unwrap();
   
   let chal = FieldElement::from_msg_hash(&pok.to_bytes());
   
   let proof = pok.gen_proof(&chal).unwrap();
   
   // The verifier verifies the proof. Empty HashMap indicates the no message was revealed
   assert!(proof.verify(&ps_verkey, HashMap::new(), &chal).unwrap());
    ```

1. To prove knowledge of signature and reveal some of the messages, the prover specifies 
the indices of the messages being revealed to `PoKOfSignature`.
    ```rust
       let ps_verkey = transform_to_PS_verkey(&aggr_vk, &params);
       let ps_sig = transform_to_PS_sig(&aggr_sig);
       
       // Reveal the following messages to the verifier
       let mut revealed_msg_indices = HashSet::new();
       revealed_msg_indices.insert(3);
       revealed_msg_indices.insert(5);
       
       let pok =
           PoKOfSignature::init(&ps_sig, &ps_verkey, msgs.as_slice(), revealed_msg_indices.clone()).unwrap();
   
       let chal = FieldElement::from_msg_hash(&pok.to_bytes());
   
       let proof = pok.gen_proof(&chal).unwrap();
       
       // The prover reveals these messages
       let mut revealed_msgs = HashMap::new();
       for i in &revealed_msg_indices {
           revealed_msgs.insert(i.clone(), msgs[*i].clone());
       }
       
       // The verifier verifies the proof, passing the revealed messages
       assert!(proof.verify(&ps_verkey, revealed_msgs.clone(), &chal).unwrap());
    ```

## Pending
1. Error handling. Start with asserts in non-test code.
1. Documentation
1. Benchmarking

