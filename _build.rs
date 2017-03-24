extern crate bindgen;

use std::env;
use std::path::Path;

fn main() {
  let out_dir = env::var("OUT_DIR").unwrap();
  let _ = bindgen::builder()
    .header("nginx/src/event/ngx_event_openssl.h")
    .no_unstable_rust()
    .clang_arg("-Inginx/objs/ -Inginx/src/core -Inginx/src/event -Inginx/src/http -Inginx/src/mail -Inginx/src/misc -Inginx/src/os -Inginx/src/os/unix/ -Inginx/src/stream/")
    .generate().unwrap()
    .write_to_file(Path::new(&out_dir).join("example.rs"));
}
