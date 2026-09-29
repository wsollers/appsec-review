fn helper(value: i32) -> i32 {
    value + 1
}

fn main() {
    std::process::exit(if helper(41) == 42 { 0 } else { 1 });
}
