/// This is EMSA-PKCS1-v1_5-ENCODE
///
/// `out` is the modulus-size output buffer.
/// `digest_info` is a constant like `DIGESTINFO_SHA256`.
/// `hash` is the hash of the message.
///
/// panics if the encoding cannot fit.  this is not reachable
/// for the combinations of hash functions / key sizes that
/// we support.
pub(crate) fn encode_pkcs1_sig(out: &mut [u8], digest_info: &[u8], hash: &[u8]) {
    // 1.  Apply the hash function to the message M to produce a hash
    //     value H:
    // (done by caller)

    // 2.  Encode the algorithm ID for the hash function (...)
    // (in fact, we do the common cheat of concatenating the fixed encoding
    // in `digest_info` and the hash.  see `digestinfos_are_correct` below
    // for cross-checking with a full DER encoder.)

    // 3.  If emLen < tLen + 11, output "intended encoded message length
    //     too short" and stop.
    let t_len = digest_info.len() + hash.len();
    let em_len = out.len();
    assert!(em_len >= t_len + 11);

    // 4. Generate an octet string PS consisting of emLen - tLen - 3
    //    octets with hexadecimal value 0xff.  The length of PS will be
    //    at least 8 octets.
    //
    //  5.  Concatenate PS, the DER encoding T, and other padding to form
    //      the encoded message EM as
    //
    //         EM = 0x00 || 0x01 || PS || 0x00 || T.
    //
    // (we do this in a slightly more obvious way, and minimising
    // bounds checks...)

    let (padding, digest_info_out) = out.split_at_mut(em_len - t_len);
    let (prefix_out, hash_out) = digest_info_out.split_at_mut(digest_info.len());
    let (leader, rest) = padding.split_first_mut().unwrap();
    let (top_sep, rest) = rest.split_first_mut().unwrap();
    let (bot_sep, ps) = rest.split_last_mut().unwrap();

    *leader = 0x00;
    *top_sep = 0x01;
    ps.fill(0xff);
    *bot_sep = 0x00;
    prefix_out.copy_from_slice(digest_info);
    hash_out.copy_from_slice(hash);
}

pub(crate) static DIGESTINFO_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

pub(crate) static DIGESTINFO_SHA384: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];

pub(crate) static DIGESTINFO_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::high::asn1::{self, oid, pkix, Type};

    #[test]
    fn digestinfo_sha256_is_correct() {
        let hash = [0xaa; 32];

        let di = pkix::DigestInfo {
            digestAlgorithm: pkix::AlgorithmIdentifier {
                algorithm: oid::id_sha256.clone(),
                parameters: Some(asn1::Any::Null(asn1::Null)),
            },
            digest: asn1::OctetString::new(&hash),
        };

        let mut correct = vec![0; di.encoded_len()];
        di.encode(&mut asn1::Encoder::new(&mut correct)).unwrap();

        let actual = {
            let mut v = Vec::new();
            v.extend_from_slice(DIGESTINFO_SHA256);
            v.extend_from_slice(&hash);
            v
        };

        println!("correct: {:#04x?}", correct);
        assert_eq!(actual, correct);
    }

    #[test]
    fn digestinfo_sha384_is_correct() {
        let hash = [0xaa; 48];

        let di = pkix::DigestInfo {
            digestAlgorithm: pkix::AlgorithmIdentifier {
                algorithm: oid::id_sha384.clone(),
                parameters: Some(asn1::Any::Null(asn1::Null)),
            },
            digest: asn1::OctetString::new(&hash),
        };

        let mut correct = vec![0; di.encoded_len()];
        di.encode(&mut asn1::Encoder::new(&mut correct)).unwrap();

        let actual = {
            let mut v = Vec::new();
            v.extend_from_slice(DIGESTINFO_SHA384);
            v.extend_from_slice(&hash);
            v
        };

        println!("correct: {:#04x?}", correct);
        assert_eq!(actual, correct);
    }

    #[test]
    fn digestinfo_sha512_is_correct() {
        let hash = [0xaa; 64];

        let di = pkix::DigestInfo {
            digestAlgorithm: pkix::AlgorithmIdentifier {
                algorithm: oid::id_sha512.clone(),
                parameters: Some(asn1::Any::Null(asn1::Null)),
            },
            digest: asn1::OctetString::new(&hash),
        };

        let mut correct = vec![0; di.encoded_len()];
        di.encode(&mut asn1::Encoder::new(&mut correct)).unwrap();

        let actual = {
            let mut v = Vec::new();
            v.extend_from_slice(DIGESTINFO_SHA512);
            v.extend_from_slice(&hash);
            v
        };

        println!("correct: {:#04x?}", correct);
        assert_eq!(actual, correct);
    }
}
