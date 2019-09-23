# Coconut: Threshold Issuance Selective Disclosure Credentials with Applications to Distributed Ledgers

Based on the [Coconut paper](https://arxiv.org/pdf/1802.07344.pdf). Uses Shamir secret sharing for key generation. 
This is done by a trusted third party. This trusted party's role ends at key generation.

## Pending
1. Add proof of knowledge of signature. Use code from [here](https://github.com/lovesh/signature-schemes/blob/master/ps/src/pok_sig.rs)
1. Error handling. Start with asserts in non-test code.
1. Complete other TODOs in code
