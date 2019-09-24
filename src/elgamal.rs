#[macro_export]
macro_rules! elgamal_keygen {
    ( $base:expr ) => {{
        // Return (sk, $base^sk)
        let sk = FieldElement::random();
        let pk = $base * &sk;
        (sk, pk)
    }};
}

#[macro_export]
macro_rules! elgamal_encrypt {
( $base:expr, $pk:expr, $msg: expr ) => {{
        // Return ($base^k, $pk^k * $msg, k). k is needed when knowledge of k needs to be proven in the ciphertext
        let k = FieldElement::random();
        let c1 = $base * &k;
        let c2 = &($pk * &k) + $msg;
        (c1, c2, k)
    }}
}

#[macro_export]
macro_rules! elgamal_decrypt {
    ( $c1:expr, $c2:expr, $sk:expr ) => {{
        let pk_k = $c1 * $sk;
        $c2 - pk_k
    }};
}

#[cfg(test)]
mod tests {
    use amcl_wrapper::field_elem::FieldElement;
    use amcl_wrapper::group_elem::GroupElement;
    use amcl_wrapper::group_elem_g1::G1;
    use amcl_wrapper::group_elem_g2::G2;

    #[test]
    fn test_elgamal_G1() {
        // Elgamal encryption in G1
        let g = G1::random();
        let (sk, pk) = elgamal_keygen!(&g);

        let msg = G1::random();
        let (c1, c2, _) = elgamal_encrypt!(&g, &pk, &msg);

        let decrypted = elgamal_decrypt!(&c1, &c2, &sk);

        assert_eq!(msg, decrypted)
    }

    #[test]
    fn test_elgamal_G2() {
        // Elgamal encryption in G2
        let g = G2::random();
        let (sk, pk) = elgamal_keygen!(&g);

        let msg = G2::random();
        let (c1, c2, _) = elgamal_encrypt!(&g, &pk, &msg);

        let decrypted = elgamal_decrypt!(&c1, &c2, &sk);

        assert_eq!(msg, decrypted)
    }
}
