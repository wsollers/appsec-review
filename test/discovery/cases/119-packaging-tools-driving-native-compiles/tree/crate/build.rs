fn main() {
    cc::Build::new().file("csrc/hash.c").compile("fasthash");
    println!("cargo:rerun-if-changed=csrc/hash.c");
}
