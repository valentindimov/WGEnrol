// Package postgres implements the storage contracts on top of a PostgreSQL
// server, using the pgx/v5 database/sql driver. Only the dialect (schema DDL,
// placeholder syntax, connection setup, unique-violation mapping) lives here;
// all statement semantics live in the shared generic SQL store. Behavior must
// stay in lockstep with the sqlite driver; internal/storage/conformance
// enforces the shared contract.
package postgres

import (
	"database/sql"
	"errors"
	"strconv"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"

	"thebasstoon.com/wgenrol/internal/storage"
)

// Store is a PostgreSQL-backed peer and session store. The db handle is
// exposed for the package's tests, which inject corrupt rows via raw SQL.
type Store struct {
	*storage.SQLStore
	db *sql.DB
}

var _ storage.PeerStore = (*Store)(nil)
var _ storage.SessionStore = (*Store)(nil)

// dialect: PostgreSQL uses "$n" placeholders and BYTEA/BIGINT columns.
// Multiple app instances can share the database; their in-tx duplicate
// pre-checks can race past each other, so the unique constraint is the true
// arbiter and gets mapped to the same error sentences.
var dialect = storage.Dialect{
	Placeholder: func(i int) string { return "$" + strconv.Itoa(i+1) },
	Schema: []string{
		`CREATE TABLE IF NOT EXISTS peers (
			pubkey      BYTEA NOT NULL PRIMARY KEY,
			psk         BYTEA,
			comment     TEXT NOT NULL DEFAULT '',
			allowed_ips TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS pending_peers (
			token_hash  BYTEA NOT NULL PRIMARY KEY,
			comment     TEXT NOT NULL DEFAULT '',
			allowed_ips TEXT NOT NULL DEFAULT '',
			created_at  BIGINT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token   TEXT PRIMARY KEY,
			expires BIGINT NOT NULL
		)`,
	},
	IsDuplicate: isDuplicate,
}

// isDuplicate reports whether err is a PostgreSQL unique-constraint violation.
func isDuplicate(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// Open connects to the PostgreSQL server at dsn and ensures the schema. The
// connection itself is lazy; the schema creation forces it, so unreachable
// servers fail here rather than on first use.
func Open(dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	// The app serializes store access with its own request mutex per
	// instance; a modest pool suffices.
	db.SetMaxOpenConns(8)
	store, err := storage.NewSQLStore(db, dialect)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{SQLStore: store, db: db}, nil
}
