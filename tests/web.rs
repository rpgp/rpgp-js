//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_create_rsa_key() {
    let key = rpgp_js::create_rsa_key().unwrap();
    assert!(!key.is_empty());
}

#[wasm_bindgen_test]
fn test_create_x25519_key() {
    let key = rpgp_js::create_x25519_key().unwrap();
    assert!(!key.is_empty());
}
