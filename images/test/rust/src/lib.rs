pub fn message() -> &'static str {
    "hello from rust"
}

#[cfg(test)]
mod tests {
    use super::message;

    #[test]
    fn returns_message() {
        assert_eq!(message(), "hello from rust");
    }
}
