//! Offline stand-in for the rusqlite API surface the fixture uses (models: <rusqlite::Connection>::execute).
pub struct Connection;

impl Connection {
    pub fn open_in_memory() -> Result<Connection, ()> {
        Ok(Connection)
    }

    pub fn execute<P>(&self, sql: &str, params: P) -> usize {
        let _ = (sql, params);
        0
    }
}
