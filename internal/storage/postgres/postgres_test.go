package postgres

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"thebasstoon.com/wgenrol/internal/storage"
	"thebasstoon.com/wgenrol/internal/storage/conformance"
	"thebasstoon.com/wgenrol/internal/wireguard"
)

const testDSNEnv = "WGENROL_TEST_POSTGRES_DSN"

func testDSN(t *testing.T) (string, bool) {
	t.Helper()
	dsn := os.Getenv(testDSNEnv)
	if dsn == "" {
		t.Skipf("%s is not set: skipping PostgreSQL store tests (set the variable to a live database to run them)", testDSNEnv)
	}
	return dsn, true
}

func openStore(t *testing.T) storage.PeerStore {
	t.Helper()
	store := openDriverStore(t)
	return store
}

func openDriverStore(t *testing.T) *Store {
	t.Helper()
	dsn, _ := testDSN(t)
	store, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	// Conformance tests expect isolated stores; the shared database is
	// emptied at every open instead.
	if _, err := store.db.Exec("DELETE FROM pending_peers"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("DELETE FROM peers"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("DELETE FROM sessions"); err != nil {
		t.Fatal(err)
	}
	return store
}

// The full driver-agnostic PeerStore contract, run against PostgreSQL.
func TestPostgresConformance(t *testing.T) {
	if _, ok := testDSN(t); !ok {
		return
	}
	conformance.RunPeerStoreSuite(t, func(t *testing.T) conformance.DriverStore {
		return openDriverStore(t)
	})
}

// Open must fail fast for a well-formed DSN pointing at nothing.
func TestOpenUnreachableServer(t *testing.T) {
	testDSN(t) // still gated: runs only when the feature is exercised
	if _, err := Open("postgres://wgenrol-test@127.0.0.1:1/wgenrol"); err == nil {
		t.Fatal("expected a connection error for an unreachable PostgreSQL server")
	}
}

// isDuplicate recognizes unique-violation errors regardless of wrapping.
func TestIsDuplicate(t *testing.T) {
	if !isDuplicate(&pgconn.PgError{Code: "23505"}) {
		t.Fatal("a 23505 PgError must be recognized as a duplicate")
	}
	wrapped := errWrap(&pgconn.PgError{Code: "23505"})
	if !isDuplicate(wrapped) {
		t.Fatal("a wrapped 23505 PgError must be recognized as a duplicate")
	}
	if isDuplicate(&pgconn.PgError{Code: "23503"}) {
		t.Fatal("other constraint violations must not count as duplicates")
	}
	if isDuplicate(errors.New("regular error")) {
		t.Fatal("a non-PgError must not count as a duplicate")
	}
}

type wrappedError struct{ inner error }

func (w *wrappedError) Error() string { return w.inner.Error() }
func (w *wrappedError) Unwrap() error { return w.inner }

func errWrap(err error) error { return &wrappedError{inner: err} }

// insertRawPeer writes a row bypassing all validation, simulating corrupt
// data (e.g. written by a tool with different expectations).
func insertRawPeer(t *testing.T, store *Store, pubkey []byte, psk []byte, allowedIPs string) {
	t.Helper()
	if _, err := store.db.Exec("INSERT INTO peers (pubkey, psk, comment, allowed_ips) VALUES ($1, $2, 'Broken', $3)",
		pubkey, psk, allowedIPs); err != nil {
		t.Fatal(err)
	}
}

// Corrupt data must surface as errors, mirroring the SQLite driver's behavior.
func TestCorruptRows(t *testing.T) {
	store := openStore(t).(*Store)

	insertRawPeer(t, store, bytes.Repeat([]byte{7}, 32), nil, "not-a-cidr")
	if _, err := store.ListPeers(); err == nil || !strings.Contains(err.Error(), "Failed to parse stored AllowedIPs") {
		t.Fatalf("expected an AllowedIPs parse error from ListPeers, got %v", err)
	}
	hash := wireguard.Key{}
	copy(hash[:], bytes.Repeat([]byte{7}, 32))
	if _, _, err := store.GetPeer(hash); err == nil || !strings.Contains(err.Error(), "Failed to parse stored AllowedIPs") {
		t.Fatalf("expected an AllowedIPs parse error from GetPeer, got %v", err)
	}
	if _, err := store.db.Exec("DELETE FROM peers"); err != nil {
		t.Fatal(err)
	}
	insertRawPeer(t, store, []byte("short"), nil, "")
	if _, err := store.ListPeers(); err == nil || !strings.Contains(err.Error(), "Stored data is corrupt") {
		t.Fatalf("expected a corrupt-data error from ListPeers, got %v", err)
	}
}

// offlineEntry builds a valid-looking pending entry (no store interaction).
func offlineEntry(seed byte) wireguard.PendingPeer {
	var hash wireguard.Key
	hash[0] = seed
	return wireguard.PendingPeer{
		TokenHash:  hash,
		Comment:    "x",
		AllowedIps: []netip.Prefix{netip.MustParsePrefix("10.64.0.2/32")},
		CreatedAt:  time.Now(),
	}
}

// Every store operation must fail once the database is closed (full-method
// sweep, covering each method's begin-failure return).
func TestStoreClosedErrors(t *testing.T) {
	store := openStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListPeers(); err == nil {
		t.Fatal("expected ListPeers to fail on a closed store")
	}
	if _, err := store.ListPendingPeers(); err == nil {
		t.Fatal("expected ListPendingPeers to fail on a closed store")
	}
	if err := store.CreatePeer(wireguard.WgPeer{
		Pubkey:     wireguard.Key{3},
		AllowedIps: []netip.Prefix{netip.MustParsePrefix("10.64.0.2/32")},
	}); err == nil {
		t.Fatal("expected CreatePeer to fail on a closed store")
	}
	if err := store.CreatePendingPeer(offlineEntry(4)); err == nil {
		t.Fatal("expected CreatePendingPeer to fail on a closed store")
	}
	if _, _, err := store.GetPeer(wireguard.Key{5}); err == nil {
		t.Fatal("expected GetPeer to fail on a closed store")
	}
	if _, _, err := store.GetPendingPeer(wireguard.Key{6}); err == nil {
		t.Fatal("expected GetPendingPeer to fail on a closed store")
	}
	if err := store.UpdatePeerComment(wireguard.Key{7}, "x"); err == nil {
		t.Fatal("expected UpdatePeerComment to fail on a closed store")
	}
	if err := store.UpdatePendingPeer(wireguard.Key{8}, "x", []netip.Prefix{netip.MustParsePrefix("10.64.0.2/32")}); err == nil {
		t.Fatal("expected UpdatePendingPeer to fail on a closed store")
	}
	if err := store.PromotePendingPeer(wireguard.Key{9}, wireguard.Key{10}, nil, nil); err == nil {
		t.Fatal("expected PromotePendingPeer to fail on a closed store")
	}
	if err := store.DeletePeer(wireguard.Key{11}, nil); err == nil {
		t.Fatal("expected DeletePeer to fail on a closed store")
	}
	if err := store.DeletePendingPeer(wireguard.Key{12}); err == nil {
		t.Fatal("expected DeletePendingPeer to fail on a closed store")
	}
}

// insertRawPending writes a pending row bypassing all validation.
func insertRawPending(t *testing.T, store *Store, hashBlob []byte, allowedIPs string) {
	t.Helper()
	if _, err := store.db.Exec("INSERT INTO pending_peers (token_hash, comment, allowed_ips, created_at) VALUES ($1, 'Broken', $2, 0)",
		hashBlob, allowedIPs); err != nil {
		t.Fatal(err)
	}
}

// A corrupt preshared key or preimage hash must surface as an error on their
// read paths, mirroring the SQLite driver. Keyed lookups can never select a
// row whose key column is a mismatched-length blob (a typed Key never equals
// it); the list path is what reports those rows as corrupt.
func TestCorruptPSKAndPendingHashRows(t *testing.T) {
	store := openStore(t).(*Store)

	insertRawPeer(t, store, bytes.Repeat([]byte{7}, 32), []byte("short-psk"), "")
	if _, err := store.ListPeers(); err == nil || !strings.Contains(err.Error(), "psk") {
		t.Fatalf("expected a corrupt-PSK error from ListPeers, got %v", err)
	}
	hash := wireguard.Key{}
	copy(hash[:], bytes.Repeat([]byte{7}, 32))
	if _, _, err := store.GetPeer(hash); err == nil || !strings.Contains(err.Error(), "psk") {
		t.Fatalf("expected a corrupt-PSK error from GetPeer, got %v", err)
	}
	if _, err := store.db.Exec("DELETE FROM peers"); err != nil {
		t.Fatal(err)
	}

	insertRawPending(t, store, []byte("short"), "")
	if _, err := store.ListPendingPeers(); err == nil || !strings.Contains(err.Error(), "token_hash") {
		t.Fatalf("expected a corrupt-token_hash error from ListPendingPeers, got %v", err)
	}
	if _, ok, err := store.GetPendingPeer(wireguard.Key{1}); err != nil || ok {
		t.Fatalf("corrupt-hash row must be invisible to keyed lookups: ok=%v err=%v", ok, err)
	}
}
