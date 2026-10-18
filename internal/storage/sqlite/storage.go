// Package sqlite implements the storage contracts on top of an embedded
// SQLite database file, using the pure-Go modernc.org/sqlite driver. Only the
// dialect (schema DDL, placeholder syntax, connection setup) lives here; all
// statement semantics live in the shared generic SQL store.
package sqlite

import (
	"database/sql"

	_ "modernc.org/sqlite"

	"thebasstoon.com/wgenrol/internal/storage"
)

// Store is a SQLite-backed peer and session store. The db handle is exposed
// for the package's tests, which inject corrupt rows via raw SQL.
type Store struct {
	*storage.SQLStore
	db *sql.DB
}

var _ storage.PeerStore = (*Store)(nil)
var _ storage.SessionStore = (*Store)(nil)

// dialect: SQLite uses "?" placeholders and BLOB/INTEGER columns. There is no
// unique-violation mapping: with a single connection the in-tx duplicate
// pre-checks cannot race past each other, so INSERT constraint conflicts are
// unreachable here.
var dialect = storage.Dialect{
	Placeholder: func(int) string { return "?" },
	Schema: []string{
		`CREATE TABLE IF NOT EXISTS peers (
			pubkey      BLOB NOT NULL PRIMARY KEY,
			psk         BLOB,
			comment     TEXT NOT NULL DEFAULT '',
			allowed_ips TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS pending_peers (
			token_hash  BLOB NOT NULL PRIMARY KEY,
			comment     TEXT NOT NULL DEFAULT '',
			allowed_ips TEXT NOT NULL DEFAULT '',
			created_at  INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token   TEXT PRIMARY KEY,
			expires INTEGER NOT NULL
		)`,
	},
	IsDuplicate: nil,
}

// Open opens or creates the peer database at path and ensures its schema.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// A single connection serializes all statements; together with the busy
	// timeout this avoids spurious "database is locked" errors. The app
	// additionally serializes store access with its own request mutex.
	db.SetMaxOpenConns(1)
	store, err := storage.NewSQLStore(db, dialect)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{SQLStore: store, db: db}, nil
}
