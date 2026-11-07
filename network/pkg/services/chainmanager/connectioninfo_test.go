package chainmanager

import (
	"context"
	"errors"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store/yamlstore"
)

// A publisher's connection info is held to the keys and value form this side
// uses; Subscribe refuses anything else as the publisher's fault, undoes the
// remote registration, and stores and imports nothing.
func TestSubscribe_RefusesConnectionInfoOutsideTheAllowedForm(t *testing.T) {
	for name, info := range map[string]map[string]string{
		"unknown key":     {"subject": pubPipeline, "extra": "x"},
		"tab in a value":  {"subject": pubPipeline, "url": "nats://h\t:4222"},
		"trailing spaces": {"subject": pubPipeline, "url": "nats://h:4222    \n"},
		"leading dot":     {"subject": pubPipeline, "account": ".nan"},
		"angle brackets":  {"subject": pubPipeline, "url": "x<<"},
		"non-ASCII":       {"subject": pubPipeline, "url": "nats://é"},
		"too long":        {"subject": pubPipeline, "url": "n" + strings.Repeat("x", 1000)},
	} {
		inf := &fakeInfra{}
		peer := defaultPeer()
		peer.connInfo = info
		svc, subs := subSvc(inf, peer, publicGuard())
		_, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "inline")
		if !errors.Is(err, ErrRemotePeer) {
			t.Errorf("%s: err = %v, want ErrRemotePeer", name, err)
		}
		if len(peer.disconnected) != 1 || len(inf.imported) != 0 {
			t.Errorf("%s: disconnected %v, imported %v; want one compensation, no import", name, peer.disconnected, inf.imported)
		}
		if all, _ := subs.List(); len(all) != 0 {
			t.Errorf("%s: subscription stored", name)
		}
	}
}

// What the NATS transport writes passes.
func TestCheckConnectionInfo_AcceptsWhatTheTransportWrites(t *testing.T) {
	info := map[string]string{
		"subject":     ByReferenceSubjectPrefix + "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1",
		"account":     "ABJHLOVMPA4CI6R5KLNGOB4GSLNIY7IOUPAJC4YFNDLQVIOBYQGUWVLA",
		"url":         "nats://user:p%40ss@[::1]:4222",
		"publishType": "nats",
	}
	if err := checkConnectionInfo(info); err != nil {
		t.Fatal(err)
	}
}

// Every connection info the check admits is stored and read back as it was:
// the store's own fidelity check, a backstop, is not reached by any of it.
func TestCheckConnectionInfo_WhatItAdmitsReadsBackFromTheStore(t *testing.T) {
	const first = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	const rest = first + "._~:/?@!$&'()*+,;=%[]-"
	keys := []string{"subject", "account", "url", "publishType"}
	r := rand.New(rand.NewPCG(5, 6))
	value := func() string {
		if r.IntN(10) == 0 {
			return ""
		}
		b := []byte{first[r.IntN(len(first))]}
		for range r.IntN(60) {
			b = append(b, rest[r.IntN(len(rest))])
		}
		return string(b)
	}
	subs := yamlstore.NewSubscriptionStore(t.TempDir())
	for i := range 3000 {
		info := map[string]string{}
		for _, k := range keys {
			if r.IntN(2) == 0 {
				info[k] = value()
			}
		}
		if err := checkConnectionInfo(info); err != nil {
			t.Fatalf("generated %q: %v", info, err)
		}
		sub := &store.Subscription{ID: "s" + strings.Repeat("x", i%3) + string(rune('a'+i%26)), ConnectionInfo: info, Created: time.Unix(0, 0).UTC()}
		if err := subs.Save(sub); err != nil {
			t.Fatalf("store refused %q: %v", info, err)
		}
		got, err := subs.Get(sub.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(info) == 0 && len(got.ConnectionInfo) == 0 {
			continue
		}
		if !reflect.DeepEqual(got.ConnectionInfo, info) {
			t.Fatalf("read back %q, stored %q", got.ConnectionInfo, info)
		}
	}
}
