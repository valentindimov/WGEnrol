// The storage contracts: the interfaces every storage driver must implement
// and the device-apply callback they invoke for store/device consistency.
// The domain types they carry (Key, WgPeer, PendingPeer) live in the
// wireguard package; storage depends on wireguard, never the reverse.
package storage

import (
	"net/netip"
	"time"

	"thebasstoon.com/wgenrol/internal/wireguard"
)

// DeviceApplyFn applies a complete peer list to the WireGuard device. It is
// passed into store methods that change the peer set, so that the device can
// be updated between the mutation and the store's commit.
type DeviceApplyFn func(peers []wireguard.WgPeer) error

// PeerStore persists real peers and pending enrollments. All mutating methods
// are transactional: a method either succeeds completely or has no effect.
// Methods that change the peer set accept a DeviceApplyFn; when it is
// non-nil, the store invokes it with the resulting peer list before
// committing, and rolls the mutation back if it returns an error. This keeps
// device state and the store consistent: the device is only updated if the
// store can fully commit, and the store only commits if the device accepted
// the new peer list.
type PeerStore interface {
	ListPeers() ([]wireguard.WgPeer, error)
	ListPendingPeers() ([]wireguard.PendingPeer, error)
	GetPeer(pubkey wireguard.Key) (wireguard.WgPeer, bool, error)
	GetPendingPeer(tokenHash wireguard.Key) (wireguard.PendingPeer, bool, error)
	CreatePeer(peer wireguard.WgPeer) error
	CreatePendingPeer(peer wireguard.PendingPeer) error
	UpdatePeerComment(pubkey wireguard.Key, comment string) error
	UpdatePendingPeer(tokenHash wireguard.Key, comment string, allowedIPs []netip.Prefix) error
	PromotePendingPeer(tokenHash wireguard.Key, pubkey wireguard.Key, psk *wireguard.Key, apply DeviceApplyFn) error
	DeletePeer(pubkey wireguard.Key, apply DeviceApplyFn) error
	DeletePendingPeer(tokenHash wireguard.Key) error
	Close() error
}

// SessionStore persists admin login sessions in the peer database, so they
// survive restarts (and, with a shared PostgreSQL backend, are visible to
// every app instance). Implementations must live in the same database as the
// PeerStore implementation of a driver; driver types implement both.
type SessionStore interface {
	// CreateSession stores a fresh login session with its expiry.
	CreateSession(token string, expiry time.Time) error
	// TouchSession authenticates a token: when a session with this token
	// exists and its stored expiry is still in the future, it returns ok=true
	// and slides the stored expiry forward to the given value (sliding one
	// hour after last activity). A missing or expired session yields ok=false
	// and leaves the store unchanged.
	TouchSession(token string, expiry time.Time) (bool, error)
	// DeleteSession removes a session. Deleting an unknown token is a no-op.
	DeleteSession(token string) error
	// SessionExpiry reports a session's stored expiry. Unknown sessions yield
	// ok=false. Not used on the hot path; it exists so the sliding-expiry and
	// pruning behavior can be asserted and observed.
	SessionExpiry(token string) (time.Time, bool, error)
	// DeleteExpiredSessions removes all sessions whose expiry is in the past,
	// returning how many were removed.
	DeleteExpiredSessions(now time.Time) (int64, error)
}
