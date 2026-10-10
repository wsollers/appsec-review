package store

import (
	"database/sql"
	"os"
)

type DB struct{ conn *sql.DB }

func (d *DB) Save(value string) error {
	tx, err := d.conn.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT INTO audit VALUES (?)", value); err != nil {
		tx.Rollback()
		return err
	}
	if err := os.WriteFile("/tmp/audit.log", []byte(value), 0o600); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Command is a local helper; calling it is not process execution.
func (d *DB) Command(name string) string {
	return d.Label(name)
}

func (d *DB) Label(name string) string { return "db:" + name }
