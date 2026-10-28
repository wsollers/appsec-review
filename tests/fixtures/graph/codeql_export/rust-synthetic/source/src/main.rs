//! Synthetic Rust program for the appsec-review/graph-export-rust pack (see ../../provenance.json).
use std::env;
use std::fs;
use std::process::Command;

use reqwest::blocking::Client;
use rusqlite::Connection;

trait Store {
    fn save(&self, key: &str) -> usize;
}

struct SqlStore {
    conn: Connection,
}

impl Store for SqlStore {
    fn save(&self, key: &str) -> usize {
        let query = as_owned(key);
        self.conn.execute(&query, ())
    }
}

struct NullStore;

impl Store for NullStore {
    fn save(&self, key: &str) -> usize {
        key.len()
    }
}

fn as_owned(key: &str) -> String {
    key.to_string()
}

fn fetch_body(url: &str) -> &'static str {
    let response = reqwest::blocking::get(url).unwrap();
    response.text().unwrap()
}

fn run_tool(tool: &str) {
    let _child = Command::new(tool);
}

fn guarded_tool(tool: &str) {
    if tool.len() < 16 {
        let _child = Command::new(tool);
    }
}

fn read_file(name: &str) -> String {
    fs::read_to_string(name).unwrap()
}

fn read_canonical(name: &str) -> String {
    let path = fs::canonicalize(name).unwrap();
    fs::read_to_string(path).unwrap()
}

fn fetch_url(url: &str) {
    let client = Client::new();
    let _request = client.request("GET", url);
}

fn decode(body: &str) -> usize {
    serde_json::from_str(body)
}

fn pick_store(conn: Option<Connection>) -> Box<dyn Store> {
    match conn {
        Some(conn) => Box::new(SqlStore { conn }),
        None => Box::new(NullStore),
    }
}

fn main() {
    let body = fetch_body("http://example.invalid/");
    let store = pick_store(Connection::open_in_memory().ok());
    store.save(body);
    run_tool(body);
    fetch_url(body);
    decode(body);
    let arg = env::args().nth(1).unwrap();
    guarded_tool(&arg);
    read_canonical(&arg);
    let name = env::var("CONFIG").unwrap();
    read_file(&name);
    let bump = |count: usize| count + 1;
    bump(body.len());
}
