fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-env=IMGTOOL_BUILD=1");
}
