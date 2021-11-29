#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate bamboo_rs_core_ed25519_yasmf;

use bamboo_rs_core_ed25519_yasmf::entry::decode;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let _ = decode(data);
});
