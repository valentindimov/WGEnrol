// The generic SQL store: a database/sql implementation of the storage
// contracts shared by all SQL-speaking drivers. The per-driver packages
// (sqlite, postgres) supply a Dialect — schema DDL, placeholder syntax, and
// the unique-violation mapping — and own the connection setup; everything
// about statement semantics lives here exactly once.
package storage

import (
	"database/sql"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"thebasstoon.com/wgenrol/internal/wireguard"
)

// Dialect carries everything a specific SQL backend answers for: the dialect
// DDL, the placeholder syntax of its driver, and the unique-constraint
// violation mapping (nil when the driver cannot race past the in-tx
// pre-checks, as with a single-connection SQLite store).
type Dialect struct {
	// Placeholder returns the i-th query parameter marker.
	Placeholder func(i int) string
	// Schema creates all tables (idempotent CREATE statements).
	Schema []string
	// IsDuplicate maps a driver error to a unique-constraint violation; nil
	// when there is nothing to map.
	IsDuplicate func(err error) bool
}

// The statement catalog with placeholders rendered once per dialect.
type storeStatements struct {
	peerGet, peerInsert, peerUpdateComment, peerDelete      string
	pendingGet, pendingInsert, pendingUpdate, pendingDelete string

	sessionInsert, sessionTouch, sessionDelete, sessionGetExpiry, sessionPrune string
}

// render replaces the {n} markers with the dialect's placeholders. Each
// parameter index occurs at most once per statement.
func render(stmt string, placeholder func(int) string) string {
	for i := 0; i < 5; i++ {
		stmt = strings.ReplaceAll(stmt, "{"+strconv.Itoa(i)+"}", placeholder(i))
	}
	return stmt
}

// SQLStore is the generic SQL implementation of the storage contracts.
type SQLStore struct {
	db      *sql.DB
	dialect Dialect
	stmts   storeStatements
}

var _ PeerStore = (*SQLStore)(nil)
var _ SessionStore = (*SQLStore)(nil)

// NewSQLStore ensures the schema and returns the store over db. The
// connection itself (DSN, pool sizing, pragmas) is the driver's business.
func NewSQLStore(db *sql.DB, d Dialect) (*SQLStore, error) {
	for _, statement := range d.Schema {
		if _, err := db.Exec(statement); err != nil {
			return nil, err
		}
	}
	stmts := storeStatements{
		peerGet:           render("SELECT "+PeerColumns+" FROM peers WHERE pubkey = {0}", d.Placeholder),
		peerInsert:        render("INSERT INTO peers (pubkey, psk, comment, allowed_ips) VALUES ({0}, {1}, {2}, {3})", d.Placeholder),
		peerUpdateComment: render("UPDATE peers SET comment = {0} WHERE pubkey = {1}", d.Placeholder),
		peerDelete:        render("DELETE FROM peers WHERE pubkey = {0}", d.Placeholder),

		pendingGet:    render("SELECT "+PendingColumns+" FROM pending_peers WHERE token_hash = {0}", d.Placeholder),
		pendingInsert: render("INSERT INTO pending_peers (token_hash, comment, allowed_ips, created_at) VALUES ({0}, {1}, {2}, {3})", d.Placeholder),
		pendingUpdate: render("UPDATE pending_peers SET comment = {0}, allowed_ips = {1} WHERE token_hash = {2}", d.Placeholder),
		pendingDelete: render("DELETE FROM pending_peers WHERE token_hash = {0}", d.Placeholder),

		sessionInsert:    render("INSERT INTO sessions (token, expires) VALUES ({0}, {1})", d.Placeholder),
		sessionTouch:     render("UPDATE sessions SET expires = {0} WHERE token = {1} AND expires > {2}", d.Placeholder),
		sessionDelete:    render("DELETE FROM sessions WHERE token = {0}", d.Placeholder),
		sessionGetExpiry: render("SELECT expires FROM sessions WHERE token = {0}", d.Placeholder),
		sessionPrune:     render("DELETE FROM sessions WHERE expires <= {0}", d.Placeholder),
	}
	return &SQLStore{db: db, dialect: d, stmts: stmts}, nil
}

func (s *SQLStore) tx(fn func(tx *sql.Tx) error) error {
	return InTx(s.db, fn)
}

func (s *SQLStore) listPeers() ([]wireguard.WgPeer, error) {
	var peers []wireguard.WgPeer
	err := s.tx(func(tx *sql.Tx) error {
		rows, err := tx.Query("SELECT " + PeerColumns + " FROM peers ORDER BY comment")
		if err != nil {
			return err
		}
		peers, err = ListPeers(rows)
		return err
	})
	return peers, err
}

func (s *SQLStore) listPending() ([]wireguard.PendingPeer, error) {
	var pending []wireguard.PendingPeer
	err := s.tx(func(tx *sql.Tx) error {
		rows, err := tx.Query("SELECT " + PendingColumns + " FROM pending_peers ORDER BY comment")
		if err != nil {
			return err
		}
		pending, err = ListPending(rows)
		return err
	})
	return pending, err
}

// mapInsertError maps an INSERT error: first to a unique-constraint
// violation (when the dialect can detect them, e.g. cross-instance races the
// pre-checks cannot see), otherwise as-is.
func (s *SQLStore) mapInsertError(err error, message string) error {
	if err == nil {
		return nil
	}
	if s.dialect.IsDuplicate != nil && s.dialect.IsDuplicate(err) {
		return errors.New(message)
	}
	return err
}

func (s *SQLStore) ListPeers() ([]wireguard.WgPeer, error) {
	return s.listPeers()
}

func (s *SQLStore) ListPendingPeers() ([]wireguard.PendingPeer, error) {
	return s.listPending()
}

func (s *SQLStore) GetPeer(pubkey wireguard.Key) (wireguard.WgPeer, bool, error) {
	var peer wireguard.WgPeer
	var ok bool
	err := s.tx(func(tx *sql.Tx) error {
		var err error
		peer, ok, err = ScanPeer(tx.QueryRow(s.stmts.peerGet, []byte(pubkey[:])))
		return err
	})
	if err != nil {
		return wireguard.WgPeer{}, false, err
	}
	return peer, ok, nil
}

func (s *SQLStore) GetPendingPeer(tokenHash wireguard.Key) (wireguard.PendingPeer, bool, error) {
	var pending wireguard.PendingPeer
	var ok bool
	err := s.tx(func(tx *sql.Tx) error {
		var err error
		pending, ok, err = ScanPending(tx.QueryRow(s.stmts.pendingGet, []byte(tokenHash[:])))
		return err
	})
	if err != nil {
		return wireguard.PendingPeer{}, false, err
	}
	return pending, ok, nil
}

func (s *SQLStore) CreatePeer(peer wireguard.WgPeer) error {
	if len(peer.AllowedIps) <= 0 {
		return errors.New("AllowedIPs cannot be empty.")
	}
	return s.tx(func(tx *sql.Tx) error {
		if _, ok, err := ScanPeer(tx.QueryRow(s.stmts.peerGet, []byte(peer.Pubkey[:]))); err != nil {
			return err
		} else if ok {
			return errors.New("A peer with this public key already exists.")
		}
		_, err := tx.Exec(s.stmts.peerInsert,
			[]byte(peer.Pubkey[:]), PskOrNull(peer.PresharedKey), peer.Comment, SerializeAllowedIPs(peer.AllowedIps))
		return s.mapInsertError(err, "A peer with this public key already exists.")
	})
}

func (s *SQLStore) CreatePendingPeer(peer wireguard.PendingPeer) error {
	if len(peer.AllowedIps) <= 0 {
		return errors.New("AllowedIPs cannot be empty.")
	}
	return s.tx(func(tx *sql.Tx) error {
		if _, ok, err := ScanPending(tx.QueryRow(s.stmts.pendingGet, []byte(peer.TokenHash[:]))); err != nil {
			return err
		} else if ok {
			return errors.New("A pending enrollment with this token hash already exists.")
		}
		_, err := tx.Exec(s.stmts.pendingInsert,
			[]byte(peer.TokenHash[:]), peer.Comment, SerializeAllowedIPs(peer.AllowedIps), peer.CreatedAt.Unix())
		return s.mapInsertError(err, "A pending enrollment with this token hash already exists.")
	})
}

func (s *SQLStore) UpdatePeerComment(pubkey wireguard.Key, comment string) error {
	return s.tx(func(tx *sql.Tx) error {
		result, err := tx.Exec(s.stmts.peerUpdateComment, comment, []byte(pubkey[:]))
		if err != nil {
			return err
		}
		if affected, err := result.RowsAffected(); err != nil {
			return err
		} else if affected == 0 {
			return errors.New("The peer " + pubkey.String() + " does not exist.")
		}
		return nil
	})
}

func (s *SQLStore) UpdatePendingPeer(tokenHash wireguard.Key, comment string, allowedIPs []netip.Prefix) error {
	if len(allowedIPs) <= 0 {
		return errors.New("AllowedIPs cannot be empty.")
	}
	return s.tx(func(tx *sql.Tx) error {
		result, err := tx.Exec(s.stmts.pendingUpdate,
			comment, SerializeAllowedIPs(allowedIPs), []byte(tokenHash[:]))
		if err != nil {
			return err
		}
		if affected, err := result.RowsAffected(); err != nil {
			return err
		} else if affected == 0 {
			return errors.New("The pending enrollment " + tokenHash.String() + " does not exist.")
		}
		return nil
	})
}

func (s *SQLStore) PromotePendingPeer(tokenHash wireguard.Key, pubkey wireguard.Key, psk *wireguard.Key, apply DeviceApplyFn) error {
	return s.tx(func(tx *sql.Tx) error {
		pending, ok, err := ScanPending(tx.QueryRow(s.stmts.pendingGet, []byte(tokenHash[:])))
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("The pending enrollment " + tokenHash.String() + " does not exist.")
		}
		if _, ok, err := ScanPeer(tx.QueryRow(s.stmts.peerGet, []byte(pubkey[:]))); err != nil {
			return err
		} else if ok {
			return errors.New("A peer with this public key already exists.")
		}
		_, err = tx.Exec(s.stmts.peerInsert,
			[]byte(pubkey[:]), PskOrNull(psk), pending.Comment, SerializeAllowedIPs(pending.AllowedIps))
		if err := s.mapInsertError(err, "A peer with this public key already exists."); err != nil {
			return err
		}
		if _, err := tx.Exec(s.stmts.pendingDelete, []byte(tokenHash[:])); err != nil {
			return err
		}
		if apply != nil {
			rows, err := tx.Query("SELECT " + PeerColumns + " FROM peers ORDER BY comment")
			if err != nil {
				return err
			}
			peers, err := ListPeers(rows)
			if err != nil {
				return err
			}
			if err := apply(peers); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *SQLStore) DeletePeer(pubkey wireguard.Key, apply DeviceApplyFn) error {
	return s.tx(func(tx *sql.Tx) error {
		result, err := tx.Exec(s.stmts.peerDelete, []byte(pubkey[:]))
		if err != nil {
			return err
		}
		if affected, err := result.RowsAffected(); err != nil {
			return err
		} else if affected == 0 {
			return errors.New("The peer " + pubkey.String() + " does not exist.")
		}
		if apply != nil {
			rows, err := tx.Query("SELECT " + PeerColumns + " FROM peers ORDER BY comment")
			if err != nil {
				return err
			}
			peers, err := ListPeers(rows)
			if err != nil {
				return err
			}
			if err := apply(peers); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *SQLStore) DeletePendingPeer(tokenHash wireguard.Key) error {
	return s.tx(func(tx *sql.Tx) error {
		result, err := tx.Exec(s.stmts.pendingDelete, []byte(tokenHash[:]))
		if err != nil {
			return err
		}
		if affected, err := result.RowsAffected(); err != nil {
			return err
		} else if affected == 0 {
			return errors.New("The pending enrollment " + tokenHash.String() + " does not exist.")
		}
		return nil
	})
}

func (s *SQLStore) Close() error {
	return s.db.Close()
}

func (s *SQLStore) CreateSession(token string, expiry time.Time) error {
	return s.tx(func(tx *sql.Tx) error {
		_, err := tx.Exec(s.stmts.sessionInsert, token, expiry.Unix())
		return s.mapInsertError(err, "A session with this token already exists.")
	})
}

func (s *SQLStore) TouchSession(token string, expiry time.Time) (bool, error) {
	// One conditional UPDATE is atomic and covers both the authentication
	// check and the sliding extension: it only matches sessions whose stored
	// expiry is still in the future.
	var updated bool
	err := s.tx(func(tx *sql.Tx) error {
		result, err := tx.Exec(s.stmts.sessionTouch,
			expiry.Unix(), token, time.Now().Unix())
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		updated = affected == 1
		return nil
	})
	if err != nil {
		return false, err
	}
	return updated, nil
}

func (s *SQLStore) DeleteSession(token string) error {
	return s.tx(func(tx *sql.Tx) error {
		_, err := tx.Exec(s.stmts.sessionDelete, token)
		return err
	})
}

func (s *SQLStore) SessionExpiry(token string) (time.Time, bool, error) {
	var expires int64
	err := s.tx(func(tx *sql.Tx) error {
		if err := tx.QueryRow(s.stmts.sessionGetExpiry, token).Scan(&expires); err != nil {
			return err
		}
		return nil
	})
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return time.Unix(expires, 0), true, nil
}

func (s *SQLStore) DeleteExpiredSessions(now time.Time) (int64, error) {
	var removed int64
	err := s.tx(func(tx *sql.Tx) error {
		result, err := tx.Exec(s.stmts.sessionPrune, now.Unix())
		if err != nil {
			return err
		}
		var err2 error
		removed, err2 = result.RowsAffected()
		return err2
	})
	if err != nil {
		return 0, err
	}
	return removed, nil
}
