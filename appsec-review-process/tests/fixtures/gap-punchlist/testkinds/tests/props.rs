use proptest::prelude::*;

proptest! {
    #[test]
    fn rev(x in 0..10) {}
}
