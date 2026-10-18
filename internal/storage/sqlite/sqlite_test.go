package sqlite

import (
	"bytes"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"thebasstoon.com/wgenrol/internal/storage/conformance"
	"thebasstoon.com/wgenrol/internal/wireguard"
)

func openStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// The full driver-agnostic PeerStore contract, run against SQLite.
func TestSQLiteConformance(t *testing.T) {
	conformance.RunPeerStoreSuite(t, func(t *testing.T) conformance.DriverStore {
		return openStore(t)
	})
}

func TestOpenReopensExistingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store2, err := Open(path)
	if err != nil {
		t.Fatalf("reopening an existing database failed: %v", err)
	}
	store2.Close()
}

// Open must fail when the containing directory does not exist.
func TestOpenUnwritablePath(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "no_such_dir", "peers.db")); err == nil {
		t.Fatal("expected an error for a non-existent directory")
	}
}

// Every store operation must fail once the database is closed (this walks
// all eleven PeerStore methods, so each method's begin-failure return is
// exercised).
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

// insertRawPeer writes a row bypassing all validation, simulating corrupt
// data on disk (e.g. written by another tool or a bug in an older version).
func insertRawPeer(t *testing.T, store *Store, pubkey []byte, psk []byte, allowedIPs string) {
	t.Helper()
	if _, err := store.db.Exec("INSERT INTO peers (pubkey, psk, comment, allowed_ips) VALUES (?, ?, 'Broken', ?)",
		pubkey, psk, allowedIPs); err != nil {
		t.Fatal(err)
	}
}

// A stored row with a too-short public key must be reported as corrupt, and
// must not break reads of the healthy rows around it.
func TestCorruptPubkeyRow(t *testing.T) {
	store := openStore(t)
	peer := wireguard.WgPeer{
		Pubkey:     wireguard.Key{1},
		Comment:    "Healthy",
		AllowedIps: []netip.Prefix{netip.MustParsePrefix("10.64.0.2/32")},
	}
	if err := store.CreatePeer(peer); err != nil {
		t.Fatal(err)
	}
	insertRawPeer(t, store, []byte("short"), nil, "")
	if _, err := store.ListPeers(); err == nil || !strings.Contains(err.Error(), "Stored data is corrupt") {
		t.Fatalf("expected a corrupt-data error from ListPeers, got %v", err)
	}
	if _, ok, err := store.GetPeer(peer.Pubkey); err != nil || !ok {
		t.Fatalf("healthy row must stay readable: ok=%v err=%v", ok, err)
	}
	if _, ok, _ := store.GetPeer(wireguard.Key{44}); ok {
		t.Fatal("corrupt row must not be returned as a peer")
	}
}

func TestCorruptPSKRow(t *testing.T) {
	store := openStore(t)
	insertRawPeer(t, store, bytes.Repeat([]byte{7}, 32), []byte("short-psk"), "")
	if _, err := store.ListPeers(); err == nil || !strings.Contains(err.Error(), "psk") {
		t.Fatalf("expected a corrupt-PSK error from ListPeers, got %v", err)
	}
	hash := wireguard.Key{}
	copy(hash[:], bytes.Repeat([]byte{7}, 32))
	if _, _, err := store.GetPeer(hash); err == nil || !strings.Contains(err.Error(), "psk") {
		t.Fatalf("expected a corrupt-PSK error from GetPeer, got %v", err)
	}
}

func TestCorruptAllowedIPsRow(t *testing.T) {
	store := openStore(t)
	insertRawPeer(t, store, bytes.Repeat([]byte{7}, 32), nil, "not-a-cidr")
	if _, err := store.ListPeers(); err == nil || !strings.Contains(err.Error(), "Failed to parse stored AllowedIPs") {
		t.Fatalf("expected an AllowedIPs parse error from ListPeers, got %v", err)
	}
	hash := wireguard.Key{}
	copy(hash[:], bytes.Repeat([]byte{7}, 32))
	if _, _, err := store.GetPeer(hash); err == nil || !strings.Contains(err.Error(), "Failed to parse stored AllowedIPs") {
		t.Fatalf("expected an AllowedIPs parse error from GetPeer, got %v", err)
	}
}

// A pending row with garbage AllowedIPs must surface as an error on read.
func TestCorruptPendingRow(t *testing.T) {
	store := openStore(t)
	if _, err := store.db.Exec("INSERT INTO pending_peers (token_hash, comment, allowed_ips, created_at) VALUES (?, 'Broken', 'not-a-cidr', 0)",
		bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListPendingPeers(); err == nil || !strings.Contains(err.Error(), "Failed to parse stored AllowedIPs") {
		t.Fatalf("expected an AllowedIPs parse error from ListPendingPeers, got %v", err)
	}
	hash := wireguard.Key{}
	copy(hash[:], bytes.Repeat([]byte{7}, 32))
	if _, _, err := store.GetPendingPeer(hash); err == nil {
		t.Fatal("expected GetPendingPeer to fail on a corrupt row")
	}
}

// A pending row whose preimage hash is not 32 bytes must be reported as
// corrupt by the list path. Keyed lookups (GetPendingPeer) can never select
// such a row at all — a typed Key never equals a mismatched-length blob —
// which this test documents deliberately.
func TestCorruptPendingHashRow(t *testing.T) {
	store := openStore(t)
	if _, err := store.db.Exec("INSERT INTO pending_peers (token_hash, comment, allowed_ips, created_at) VALUES (?, 'Broken', '', 0)",
		[]byte("short")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListPendingPeers(); err == nil || !strings.Contains(err.Error(), "token_hash") {
		t.Fatalf("expected a corrupt-token_hash error from ListPendingPeers, got %v", err)
	}
	if _, ok, err := store.GetPendingPeer(wireguard.Key{1}); err != nil || ok {
		t.Fatalf("corrupt-hash row must be invisible to keyed lookups: ok=%v err=%v", ok, err)
	}
}

// A pre-v3 database (pending column named preimage_hash) is renamed and its
// data stays readable after Open.
