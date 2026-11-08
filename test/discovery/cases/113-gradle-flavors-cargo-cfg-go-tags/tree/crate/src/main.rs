#[cfg(windows)]
fn platform() -> &'static str {
    winshim::name()
}

#[cfg(not(windows))]
fn platform() -> &'static str {
    "posix"
}

fn main() {
    println!("{}", platform());
}
