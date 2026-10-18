// Package storage holds the plumbing shared by the storage drivers
// (internal/storage/sqlite, internal/storage/postgres): the peer and pending
// row codecs, database/sql scanners, and the transaction wrapper. The drivers
// provide the dialect-specific parts: connections, schema, and statement
// syntax (placeholders in particular).
package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"thebasstoon.com/wgenrol/internal/wireguard"
)

// Column lists shared by every driver; keep in sync with the driver schemas.
const (
	PeerColumns    = "pubkey, psk, comment, allowed_ips"
	PendingColumns = "token_hash, comment, allowed_ips, created_at"
)

// SerializeAllowedIPs encodes prefixes as a canonical CSV (trimmed, masked).
func SerializeAllowedIPs(ips []netip.Prefix) string {
	parts := make([]string, 0, len(ips))
	for _, prefix := range ips {
		parts = append(parts, prefix.Masked().String())
	}
	return strings.Join(parts, ",")
}

// ParseAllowedIPs decodes the CSV encoding produced by SerializeAllowedIPs.
func ParseAllowedIPs(s string) ([]netip.Prefix, error) {
	ips := make([]netip.Prefix, 0)
	for addr := range strings.SplitSeq(s, ",") {
		addr = strings.Trim(addr, " ")
		if len(addr) == 0 {
			continue
		}
		prefix, err := netip.ParsePrefix(addr)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse stored AllowedIPs: %s", err.Error())
		}
		ips = append(ips, prefix.Masked())
	}
	return ips, nil
}

// KeyFromBlob converts a key column value, reporting the column on failure so
// corrupt reads are attributable.
func KeyFromBlob(blob []byte, column string) (wireguard.Key, error) {
	key, err := wireguard.KeyFromBytes(blob)
	if err != nil {
		return wireguard.Key{}, fmt.Errorf("Stored data is corrupt (%s): %s", column, err.Error())
	}
	return key, nil
}

// PskOrNull maps a nil preshared key to a NULL parameter.
func PskOrNull(psk *wireguard.Key) any {
	if psk == nil {
		return nil
	}
	return []byte(psk[:])
}

// InTx runs fn inside a transaction; an fn error rolls the transaction back
// and is returned, so partial mutations never commit.
func InTx(db *sql.DB, fn func(tx *sql.Tx) error) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ScanPeer decodes a single peer row. A missing row yields ok=false.
// All callers look up by primary-key byte equality, so the pubkey decode
// failure below is unreachable for them and exists purely defensively: a row
// is selectable only when its key column equals a 32-byte typed Key. The
// check mirrors the list scanners, which must validate every stored row, and
// keeps this helper safe for any future non-keyed caller.
func ScanPeer(row *sql.Row) (wireguard.WgPeer, bool, error) {
	var peer wireguard.WgPeer
	var pubkeyBlob, pskBlob []byte
	var allowedIPsStr string
	err := row.Scan(&pubkeyBlob, &pskBlob, &peer.Comment, &allowedIPsStr)
	if errors.Is(err, sql.ErrNoRows) {
		return wireguard.WgPeer{}, false, nil
	}
	if err != nil {
		return wireguard.WgPeer{}, false, err
	}
	peer.Pubkey, err = KeyFromBlob(pubkeyBlob, "pubkey")
	if err != nil {
		return wireguard.WgPeer{}, false, err
	}
	if pskBlob != nil {
		psk, err := KeyFromBlob(pskBlob, "psk")
		if err != nil {
			return wireguard.WgPeer{}, false, err
		}
		peer.PresharedKey = &psk
	}
	if peer.AllowedIps, err = ParseAllowedIPs(allowedIPsStr); err != nil {
		return wireguard.WgPeer{}, false, err
	}
	return peer, true, nil
}

// ListPeers decodes a peer query result; it takes ownership of rows.
func ListPeers(rows *sql.Rows) ([]wireguard.WgPeer, error) {
	defer rows.Close()
	peers := make([]wireguard.WgPeer, 0)
	for rows.Next() {
		var peer wireguard.WgPeer
		var pubkeyBlob, pskBlob []byte
		var allowedIPsStr string
		var err error
		if err = rows.Scan(&pubkeyBlob, &pskBlob, &peer.Comment, &allowedIPsStr); err != nil {
			return nil, err
		}
		if peer.Pubkey, err = KeyFromBlob(pubkeyBlob, "pubkey"); err != nil {
			return nil, err
		}
		if pskBlob != nil {
			psk, err := KeyFromBlob(pskBlob, "psk")
			if err != nil {
				return nil, err
			}
			peer.PresharedKey = &psk
		}
		if peer.AllowedIps, err = ParseAllowedIPs(allowedIPsStr); err != nil {
			return nil, err
		}
		peers = append(peers, peer)
	}
	return peers, rows.Err()
}

// ScanPending decodes a single pending-enrollment row. A missing row yields
// ok=false; created_at is stored with second precision. As in ScanPeer, the
// token_hash decode failure is defensive: keyed callers can by
// construction only select rows whose key column equals a valid 32-byte key.
func ScanPending(row *sql.Row) (wireguard.PendingPeer, bool, error) {
	var pending wireguard.PendingPeer
	var hashBlob []byte
	var allowedIPsStr string
	var createdAt int64
	err := row.Scan(&hashBlob, &pending.Comment, &allowedIPsStr, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return wireguard.PendingPeer{}, false, nil
	}
	if err != nil {
		return wireguard.PendingPeer{}, false, err
	}
	pending.TokenHash, err = KeyFromBlob(hashBlob, "token_hash")
	if err != nil {
		return wireguard.PendingPeer{}, false, err
	}
	if pending.AllowedIps, err = ParseAllowedIPs(allowedIPsStr); err != nil {
		return wireguard.PendingPeer{}, false, err
	}
	pending.CreatedAt = time.Unix(createdAt, 0)
	return pending, true, nil
}

// ListPending decodes a pending-enrollment query result; it takes ownership
// of rows.
func ListPending(rows *sql.Rows) ([]wireguard.PendingPeer, error) {
	defer rows.Close()
	pending := make([]wireguard.PendingPeer, 0)
	for rows.Next() {
		var entry wireguard.PendingPeer
		var hashBlob []byte
		var allowedIPsStr string
		var createdAt int64
		var err error
		if err = rows.Scan(&hashBlob, &entry.Comment, &allowedIPsStr, &createdAt); err != nil {
			return nil, err
		}
		if entry.TokenHash, err = KeyFromBlob(hashBlob, "token_hash"); err != nil {
			return nil, err
		}
		if entry.AllowedIps, err = ParseAllowedIPs(allowedIPsStr); err != nil {
			return nil, err
		}
		entry.CreatedAt = time.Unix(createdAt, 0)
		pending = append(pending, entry)
	}
	return pending, rows.Err()
}
