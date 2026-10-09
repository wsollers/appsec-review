fn main() {
    let value = time::now_utc();
    println!("{}", value.rfc3339());
}
