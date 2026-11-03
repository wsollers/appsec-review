use std::collections::HashMap;

const LIMIT: usize = 4; // ANCHOR:none

pub struct Store {
    items: HashMap<String, String>,
}

impl Store {
    pub fn get<'a>(&'a self, key: &'a str) -> Option<&'a String> { // BEGIN:get
        let found = self.items.get(key); // ANCHOR:get
        let brace = '{';
        found.filter(|value| {
            value.len() < LIMIT && !value.contains(brace) // ANCHOR:get
        })
    } // END:get
}

fn helper(value: usize) -> usize { // BEGIN:helper
    value * 2 // ANCHOR:helper
} // END:helper
