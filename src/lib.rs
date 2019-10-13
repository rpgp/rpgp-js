mod utils;

use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);

    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
pub fn greet() {
    alert("Hello, rpgp-js!");
}

#[wasm_bindgen]
pub fn create_key() -> Result<String, JsValue> {
    use pgp::composed::*;
    use pgp::crypto::*;
    use pgp::types::SecretKeyTrait;
    use pgp::types::*;
    use smallvec::smallvec;

    let key_params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::EdDSA)
        .can_create_certificates(true)
        .can_sign(true)
        .primary_user_id("Me-X <me-x25519@mail.com>".into())
        .passphrase(None)
        .preferred_symmetric_algorithms(smallvec![
            SymmetricKeyAlgorithm::AES256,
            SymmetricKeyAlgorithm::AES192,
            SymmetricKeyAlgorithm::AES128,
        ])
        .preferred_hash_algorithms(smallvec![
            HashAlgorithm::SHA2_256,
            HashAlgorithm::SHA2_384,
            HashAlgorithm::SHA2_512,
            HashAlgorithm::SHA2_224,
            HashAlgorithm::SHA1,
        ])
        .preferred_compression_algorithms(smallvec![
            CompressionAlgorithm::ZLIB,
            CompressionAlgorithm::ZIP,
        ])
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(KeyType::ECDH)
                .can_encrypt(true)
                .passphrase(None)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let key = key_params
        .generate()
        .map_err(|err| format!("failed to generate secret key: {:?}", err))?;

    let signed_key = key.sign(|| "".into()).expect("failed to sign key");

    let armor = signed_key
        .to_armored_string(None)
        .expect("failed to serialize key");

    let (signed_key2, _headers) =
        SignedSecretKey::from_string(&armor).expect("failed to parse key");
    signed_key2.verify().expect("invalid key");

    assert_eq!(signed_key, signed_key2);

    let public_key = signed_key.public_key();

    let public_signed_key = public_key
        .sign(&signed_key, || "".into())
        .expect("failed to sign public key");

    public_signed_key.verify().expect("invalid public key");

    let armor = public_signed_key
        .to_armored_string(None)
        .expect("failed to serialize public key");

    let (signed_key2, _headers) =
        SignedPublicKey::from_string(&armor).expect("failed to parse public key");
    signed_key2.verify().expect("invalid public key");

    log(&armor);

    Ok(armor)
}
