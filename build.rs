extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=sodium");

    let bindings = bindgen::Builder::default()
                    .no_unstable_rust()
                    .header("libsodium/src/libsodium/include/sodium.h")
                    .generate()
                    .expect("Unable to generate libsodium bindings!");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
