#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn main() {
    println!("only for x86_64 and aarch64 architectures");
}

#[cfg(target_arch = "x86_64")]
fn main() {
    let aes = is_x86_feature_detected!("aes");
    let pclmulqdq = is_x86_feature_detected!("pclmulqdq");
    let bmi1 = is_x86_feature_detected!("bmi1");
    let bmi2 = is_x86_feature_detected!("bmi2");
    let adx = is_x86_feature_detected!("adx");
    let avx = is_x86_feature_detected!("avx");
    let avx2 = is_x86_feature_detected!("avx2");
    let sha = is_x86_feature_detected!("sha");
    let ssse3 = is_x86_feature_detected!("ssse3");

    let avx512f = is_x86_feature_detected!("avx512f");
    let avx512bw = is_x86_feature_detected!("avx512bw");
    let avx512vl = is_x86_feature_detected!("avx512vl");
    let vaes = is_x86_feature_detected!("vaes");
    let vpclmulqdq = is_x86_feature_detected!("vpclmulqdq");

    let compatible = aes && pclmulqdq && bmi1 && bmi2 && adx && avx && avx2 && ssse3;
    let avx512_aes_gcm = avx512f && avx512bw && avx512vl && vaes && vpclmulqdq;

    println!(
        "{{ \"cpuid\": {{ \"aes\": {}, \"pclmulqdq\": {}, \"bmi1\": {},\
         \"bmi2\": {}, \"adx\": {}, \"avx\": {}, \"avx2\": {},\
         \"ssse3\": {}, \"sha\": {}, \"avx512f\": {}, \"avx512bw\": {}, \"avx512vl\": {},\
         \"vaes\": {}, \"vpclmulqdq\": {} }},\
         \"compatible\": {}, \"supports_avx512_aes_gcm\": {} }}",
        aes as u8,
        pclmulqdq as u8,
        bmi1 as u8,
        bmi2 as u8,
        adx as u8,
        avx as u8,
        avx2 as u8,
        ssse3 as u8,
        sha as u8,
        avx512f as u8,
        avx512bw as u8,
        avx512vl as u8,
        vaes as u8,
        vpclmulqdq as u8,
        compatible as u8,
        avx512_aes_gcm as u8,
    );
}

#[cfg(target_arch = "aarch64")]
fn main() {
    use std::arch::is_aarch64_feature_detected;

    let aes = is_aarch64_feature_detected!("aes");
    let dit = is_aarch64_feature_detected!("dit");
    let neon = is_aarch64_feature_detected!("neon");
    let pmull = is_aarch64_feature_detected!("pmull");
    let sha2 = is_aarch64_feature_detected!("sha2");
    let sha3 = is_aarch64_feature_detected!("sha3");

    let compatible = aes && neon && pmull && sha2;

    println!(
        "{{ \"cpuid\": {{ \"aes\": {}, \"dit\": {}, \"neon\": {}, \"pmull\": {}, \
        \"sha2\": {}, \"sha3\": {} }}, \
        \"compatible\": {} }}",
        aes as u8, dit as u8, neon as u8, pmull as u8, sha2 as u8, sha3 as u8, compatible as u8,
    );
}
