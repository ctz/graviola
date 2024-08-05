#![allow(non_upper_case_globals)]

use super::asn1_oid;

asn1_oid! {
    id_md5      OBJECT IDENTIFIER ::= {
           iso (1) member_body (2) us (840) rsadsi (113549)
           digestAlgorithm (2) 5
    }
}

asn1_oid! {
    id_ecPublicKey OBJECT IDENTIFIER ::= {
        iso(1) member_body(2) us(840) 10045 keyType(2) 1
    }
}

asn1_oid! {
    id_prime256v1 OBJECT IDENTIFIER ::= {
        iso(1) member_body(2) us(840) 10045 curves(3) prime(1) 7
    }
}

asn1_oid! {
    rsaEncryption  OBJECT IDENTIFIER  ::=  { iso(1) member_body(2)
                              us(840) rsadsi(113549) pkcs(1) 1 rsaEncryption(1) }
}
