// Package conformance runs driver-agnostic PeerStore protocol tests. Storage
// driver packages invoke RunPeerStoreSuite from their test files with a
// factory returning a fresh, isolated store; the suite asserts the contract
// documented on the PeerStore interface for every driver, so behavioral
// parity cannot drift between backends.
package conformance

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"thebasstoon.com/wgenrol/internal/storage"
	"thebasstoon.com/wgenrol/internal/wireguard"
)

func peer(comment string, ipPrefixes ...string) wireguard.WgPeer {
	p := wireguard.WgPeer{Comment: comment, AllowedIps: make([]netip.Prefix, 0)}
	for _, prefix := range ipPrefixes {
		p.AllowedIps = append(p.AllowedIps, netip.MustParsePrefix(prefix))
	}
	return p
}

// peers returns entries with pairwise-distinct (but deterministic) keys.
func peers(count int) []wireguard.WgPeer {
	out := make([]wireguard.WgPeer, 0)
	for i := range count {
		p := peer("deterministic", "10.60.0.0/32")
		p.Pubkey[0] = byte(i)
		p.Pubkey[1] = 0xAA
		out = append(out, p)
	}
	return out
}

func pendingEntry(hashSeed byte, comment string, prefix string) wireguard.PendingPeer {
	var hash wireguard.Key
	hash[0] = hashSeed
	return wireguard.PendingPeer{
		TokenHash:  hash,
		Comment:    comment,
		AllowedIps: []netip.Prefix{netip.MustParsePrefix(prefix)},
		CreatedAt:  time.Now().Truncate(time.Second),
	}
}

// DriverStore is the per-driver surface verified by the suite: a driver must
// implement the peer store and the session store over the same database.
type DriverStore interface {
	storage.PeerStore
	storage.SessionStore
}

// RunPeerStoreSuite executes the full PeerStore contract on the store
// returned by open. Every subtest opens its own store for isolation.
func RunPeerStoreSuite(t *testing.T, open func(t *testing.T) DriverStore) {
	t.Run("PeerRoundTrip", func(t *testing.T) {
		store := open(t)
		psk := wireguard.Key{9}
		peerA := wireguard.WgPeer{
			Pubkey:       wireguard.Key{1},
			PresharedKey: &psk,
			AllowedIps:   []netip.Prefix{netip.MustParsePrefix("10.64.0.2/32"), netip.MustParsePrefix("fd00::2/128")},
			Comment:      "Alice",
		}
		peerB := wireguard.WgPeer{
			Pubkey:     wireguard.Key{2},
			AllowedIps: []netip.Prefix{netip.MustParsePrefix("10.64.0.3/32")},
			Comment:    "Bob",
		}
		if err := store.CreatePeer(peerA); err != nil {
			t.Fatal(err)
		}
		if err := store.CreatePeer(peerB); err != nil {
			t.Fatal(err)
		}

		list, err := store.ListPeers()
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 2 || list[0].Comment != "Alice" || list[1].Comment != "Bob" {
			t.Fatalf("unexpected list (must be ordered by comment): %+v", list)
		}

		got, ok, err := store.GetPeer(peerA.Pubkey)
		if err != nil || !ok {
			t.Fatalf("GetPeer failed: ok=%v err=%v", ok, err)
		}
		if !reflect.DeepEqual(got, peerA) {
			t.Fatalf("round-trip mismatch (with PSK): %+v != %+v", got, peerA)
		}
		got, ok, err = store.GetPeer(peerB.Pubkey)
		if err != nil || !ok {
			t.Fatalf("GetPeer failed: ok=%v err=%v", ok, err)
		}
		if got.PresharedKey != nil {
			t.Fatalf("expected nil PSK, got %+v", got.PresharedKey)
		}
		if !reflect.DeepEqual(got, peerB) {
			t.Fatalf("round-trip mismatch (no PSK): %+v != %+v", got, peerB)
		}
		if _, ok, err := store.GetPeer(wireguard.Key{42}); err != nil || ok {
			t.Fatalf("expected miss: ok=%v err=%v", ok, err)
		}
	})

	t.Run("RejectsDuplicatePeer", func(t *testing.T) {
		store := open(t)
		first := peer("Alice", "10.64.0.2/32")
		first.Pubkey[3] = 0x11
		if err := store.CreatePeer(first); err != nil {
			t.Fatal(err)
		}
		dup := peer("Bob", "10.64.0.3/32")
		dup.Pubkey = first.Pubkey
		if err := store.CreatePeer(dup); err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("expected duplicate error, got %v", err)
		}
	})

	t.Run("RejectsPeerWithoutAllowedIPs", func(t *testing.T) {
		store := open(t)
		if err := store.CreatePeer(wireguard.WgPeer{Pubkey: wireguard.Key{4}, Comment: "x"}); err == nil || !strings.Contains(err.Error(), "AllowedIPs cannot be empty") {
			t.Fatalf("expected AllowedIPs error, got %v", err)
		}
	})

	t.Run("UpdatePeerComment", func(t *testing.T) {
		store := open(t)
		p := peer("Alice", "10.64.0.2/32")
		p.Pubkey[3] = 0x12
		if err := store.CreatePeer(p); err != nil {
			t.Fatal(err)
		}
		if err := store.UpdatePeerComment(p.Pubkey, "Renamed"); err != nil {
			t.Fatal(err)
		}
		got, ok, _ := store.GetPeer(p.Pubkey)
		if !ok || got.Comment != "Renamed" {
			t.Fatalf("comment not updated: %v ok=%v", got.Comment, ok)
		}
		if err := store.UpdatePeerComment(wireguard.Key{77}, "Nobody"); err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("expected missing-peers error, got %v", err)
		}
	})

	t.Run("DeletePeerAppliesRemainingList", func(t *testing.T) {
		store := open(t)
		both := peers(2)
		for _, p := range both {
			if err := store.CreatePeer(p); err != nil {
				t.Fatal(err)
			}
		}
		var applied []wireguard.WgPeer
		if err := store.DeletePeer(both[0].Pubkey, func(list []wireguard.WgPeer) error {
			applied = list
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := store.GetPeer(both[0].Pubkey); ok {
			t.Fatal("peer still present after deletion")
		}
		if len(applied) != 1 || applied[0].Pubkey != both[1].Pubkey {
			t.Fatalf("apply callback got wrong list: %+v", applied)
		}
	})

	t.Run("DeletePeerRollsBackOnApplyFailure", func(t *testing.T) {
		store := open(t)
		p := peers(1)[0]
		if err := store.CreatePeer(p); err != nil {
			t.Fatal(err)
		}
		sentinel := errors.New("device apply failed")
		if err := store.DeletePeer(p.Pubkey, func([]wireguard.WgPeer) error { return sentinel }); err == nil {
			t.Fatal("expected device apply error to propagate")
		}
		if _, ok, _ := store.GetPeer(p.Pubkey); !ok {
			t.Fatal("peer disappeared although the device apply failed")
		}
	})

	t.Run("DeletePeerMissingSkipsApply", func(t *testing.T) {
		store := open(t)
		applyInvoked := false
		if err := store.DeletePeer(wireguard.Key{55}, func([]wireguard.WgPeer) error {
			applyInvoked = true
			return nil
		}); err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("expected missing-peers error, got %v", err)
		}
		if applyInvoked {
			t.Fatal("apply callback must not run for a missing peer")
		}
	})

	t.Run("PendingRoundTrip", func(t *testing.T) {
		store := open(t)
		entryA := pendingEntry(1, "Alice", "10.64.0.2/32")
		entryB := pendingEntry(2, "Bob", "10.64.0.3/32")
		if err := store.CreatePendingPeer(entryA); err != nil {
			t.Fatal(err)
		}
		if err := store.CreatePendingPeer(entryB); err != nil {
			t.Fatal(err)
		}

		list, err := store.ListPendingPeers()
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 2 || list[0].Comment != "Alice" || list[1].Comment != "Bob" {
			t.Fatalf("unexpected pending list: %+v", list)
		}

		got, ok, err := store.GetPendingPeer(entryA.TokenHash)
		if err != nil || !ok {
			t.Fatalf("GetPendingPeer failed: ok=%v err=%v", ok, err)
		}
		if !reflect.DeepEqual(got, entryA) {
			t.Fatalf("round-trip mismatch: %+v != %+v", got, entryA)
		}
		if _, ok, err := store.GetPendingPeer(wireguard.Key{42}); err != nil || ok {
			t.Fatalf("expected miss: ok=%v err=%v", ok, err)
		}
	})

	t.Run("RejectsDuplicateAndEmptyPending", func(t *testing.T) {
		store := open(t)
		entry := pendingEntry(6, "Alice", "10.64.0.2/32")
		if err := store.CreatePendingPeer(entry); err != nil {
			t.Fatal(err)
		}
		dup := entry
		dup.Comment = "Bob"
		if err := store.CreatePendingPeer(dup); err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("expected duplicate error, got %v", err)
		}
		dup.TokenHash[4] = 0x77
		dup.AllowedIps = nil
		if err := store.CreatePendingPeer(dup); err == nil || !strings.Contains(err.Error(), "AllowedIPs cannot be empty") {
			t.Fatalf("expected AllowedIPs error, got %v", err)
		}
	})

	t.Run("UpdatePendingPeer", func(t *testing.T) {
		store := open(t)
		entry := pendingEntry(8, "Alice", "10.64.0.2/32")
		if err := store.CreatePendingPeer(entry); err != nil {
			t.Fatal(err)
		}
		newIPs := []netip.Prefix{netip.MustParsePrefix("10.64.0.9/32"), netip.MustParsePrefix("fd00::9/128")}
		if err := store.UpdatePendingPeer(entry.TokenHash, "Renamed", newIPs); err != nil {
			t.Fatal(err)
		}
		got, ok, _ := store.GetPendingPeer(entry.TokenHash)
		if !ok || got.Comment != "Renamed" || len(got.AllowedIps) != 2 || got.AllowedIps[0].String() != "10.64.0.9/32" {
			t.Fatalf("pending update failed: %+v ok=%v", got, ok)
		}
		if err := store.UpdatePendingPeer(entry.TokenHash, "x", nil); err == nil || !strings.Contains(err.Error(), "AllowedIPs cannot be empty") {
			t.Fatalf("expected AllowedIPs error, got %v", err)
		}
		if err := store.UpdatePendingPeer(wireguard.Key{99}, "x", newIPs); err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("expected missing-pending error, got %v", err)
		}
	})

	t.Run("DeletePendingPeer", func(t *testing.T) {
		store := open(t)
		entry := pendingEntry(10, "Alice", "10.64.0.2/32")
		if err := store.CreatePendingPeer(entry); err != nil {
			t.Fatal(err)
		}
		if err := store.DeletePendingPeer(entry.TokenHash); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := store.GetPendingPeer(entry.TokenHash); ok {
			t.Fatal("pending entry still present after deletion")
		}
		if err := store.DeletePendingPeer(entry.TokenHash); err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("expected missing-pending error, got %v", err)
		}
	})

	t.Run("PromotePendingPeer", func(t *testing.T) {
		store := open(t)
		psk := wireguard.Key{17}
		entry := pendingEntry(11, "Alice", "10.64.0.2/32")
		newPubkey := wireguard.Key{12}
		if err := store.CreatePendingPeer(entry); err != nil {
			t.Fatal(err)
		}

		var applied []wireguard.WgPeer
		if err := store.PromotePendingPeer(entry.TokenHash, newPubkey, &psk, func(list []wireguard.WgPeer) error {
			applied = list
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		if _, ok, _ := store.GetPendingPeer(entry.TokenHash); ok {
			t.Fatal("pending entry still present after promotion")
		}
		got, ok, err := store.GetPeer(newPubkey)
		if err != nil || !ok {
			t.Fatalf("promoted peer missing: ok=%v err=%v", ok, err)
		}
		if got.Comment != "Alice" ||
			len(got.AllowedIps) != 1 || got.AllowedIps[0].String() != "10.64.0.2/32" ||
			got.PresharedKey == nil || *got.PresharedKey != psk {
			t.Fatalf("promoted peer fields wrong: %+v", got)
		}
		if len(applied) != 1 || applied[0].Pubkey != newPubkey {
			t.Fatalf("apply callback got wrong list: %+v", applied)
		}
	})

	t.Run("PromotePendingPeerMissing", func(t *testing.T) {
		store := open(t)
		if err := store.PromotePendingPeer(wireguard.Key{31}, wireguard.Key{32}, nil, nil); err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("expected missing-pending error, got %v", err)
		}
	})

	t.Run("PromotePendingPeerRejectsKeyCollision", func(t *testing.T) {
		store := open(t)
		conflict := peers(1)[0]
		if err := store.CreatePeer(conflict); err != nil {
			t.Fatal(err)
		}
		entry := pendingEntry(13, "Alice", "10.64.0.2/32")
		if err := store.CreatePendingPeer(entry); err != nil {
			t.Fatal(err)
		}
		if err := store.PromotePendingPeer(entry.TokenHash, conflict.Pubkey, nil, nil); err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("expected duplicate error, got %v", err)
		}
		if _, ok, _ := store.GetPendingPeer(entry.TokenHash); !ok {
			t.Fatal("pending entry was consumed by a failed promotion")
		}
	})

	t.Run("PromotePendingPeerRollsBackOnApplyFailure", func(t *testing.T) {
		store := open(t)
		entry := pendingEntry(14, "Alice", "10.64.0.2/32")
		newPubkey := wireguard.Key{15}
		if err := store.CreatePendingPeer(entry); err != nil {
			t.Fatal(err)
		}
		sentinel := errors.New("device apply failed")
		if err := store.PromotePendingPeer(entry.TokenHash, newPubkey, nil, func([]wireguard.WgPeer) error { return sentinel }); err == nil {
			t.Fatal("expected device apply error to propagate")
		}
		if _, ok, _ := store.GetPeer(newPubkey); ok {
			t.Fatal("peer was committed although the device apply failed")
		}
		if _, ok, _ := store.GetPendingPeer(entry.TokenHash); !ok {
			t.Fatal("pending entry was consumed although the device apply failed")
		}
	})

	t.Run("SessionLifecycle", func(t *testing.T) {
		store := open(t)

		// Unknown tokens never authenticate.
		if ok, err := store.TouchSession("unknown", time.Now().Add(time.Hour)); err != nil || ok {
			t.Fatalf("touching an unknown token must fail: ok=%v err=%v", ok, err)
		}

		// A created session authenticates and survives touches; its expiry
		// is readable and slid to the requested value.
		if err := store.CreateSession("tok-a", time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		slide := time.Now().Add(2 * time.Hour)
		if ok, err := store.TouchSession("tok-a", slide); err != nil || !ok {
			t.Fatalf("valid session touch failed: ok=%v err=%v", ok, err)
		}
		got, ok, err := store.SessionExpiry("tok-a")
		if err != nil || !ok {
			t.Fatalf("session expiry unreadable: ok=%v err=%v", ok, err)
		}
		if !got.Equal(slide.Truncate(time.Second)) {
			t.Fatalf("touch must slide the stored expiry to %v, got %v", slide.Truncate(time.Second), got)
		}

		// Logout removes the session; deleting unknown tokens is a no-op.
		if err := store.DeleteSession("tok-a"); err != nil {
			t.Fatal(err)
		}
		if err := store.DeleteSession("tok-never-existed"); err != nil {
			t.Fatalf("deleting an unknown session must not fail, got %v", err)
		}

		// Expired sessions are not authenticatable and are swept by the
		// prune call.
		if err := store.CreateSession("tok-old", time.Now().Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
		if ok, err := store.TouchSession("tok-old", time.Now().Add(time.Hour)); err != nil || ok {
			t.Fatalf("expired session must not authenticate: ok=%v err=%v", ok, err)
		}
		removed, err := store.DeleteExpiredSessions(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if removed != 1 {
			t.Fatalf("expected to remove exactly 1 expired session, got %d", removed)
		}
		removed, err = store.DeleteExpiredSessions(time.Now())
		if err != nil || removed != 0 {
			t.Fatalf("second prune must be a no-op: removed=%d err=%v", removed, err)
		}
	})
}
