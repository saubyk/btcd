// Copyright (c) 2024 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// TestAddrSpillRoundTrip ensures records survive a spill to the staging shards
// and back, are routed to the shard for their address hash160, and that none are
// lost.
func TestAddrSpillRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		numRecords int
		firstShard int
		numShards  int
	}{
		{
			name:       "single shard",
			numRecords: 50,
			firstShard: 42,
			numShards:  1,
		},
		{
			name:       "all shards",
			numRecords: 500,
			firstShard: 0,
			numShards:  numAddrSpillShards,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			spiller, err := newAddrSpiller(dir)
			if err != nil {
				t.Fatalf("newAddrSpiller: %v", err)
			}
			t.Cleanup(spiller.cleanup)

			want := make([]addrRecord, 0, test.numRecords)
			for i := 0; i < test.numRecords; i++ {
				var key [addrKeySize]byte
				key[0] = byte(i % 5)
				key[1] = byte(test.firstShard + i%test.numShards)
				key[addrKeySize-1] = byte(i)
				rec := addrRecord{
					addrKey: key,
					blockID: uint32(i),
					txStart: uint32(i * 7),
					txLen:   uint32(i + 1),
				}
				want = append(want, rec)

				err := spiller.add(&key, rec.blockID, wire.TxLoc{
					TxStart: int(rec.txStart),
					TxLen:   int(rec.txLen),
				})
				if err != nil {
					t.Fatalf("spiller.add: %v", err)
				}
			}

			for i := range spiller.shards {
				if err := spiller.shards[i].buf.Flush(); err != nil {
					t.Fatalf("flush shard %d: %v", i, err)
				}
			}

			// Read every record back and confirm the routing put each in the
			// shard for its hash160 byte.
			var got []addrRecord
			for i := range spiller.shards {
				recs, err := readAddrSpillShard(spiller.shards[i].f)
				if err != nil {
					t.Fatalf("readAddrSpillShard %d: %v", i, err)
				}
				for _, rec := range recs {
					if int(rec.addrKey[1]) != i {
						t.Fatalf("record with hash160 byte %d found in shard %d",
							rec.addrKey[1], i)
					}
				}
				got = append(got, recs...)
			}
			if len(got) != len(want) {
				t.Fatalf("record count mismatch: got %d, want %d", len(got),
					len(want))
			}

			less := func(recs []addrRecord) func(a, b int) bool {
				return func(a, b int) bool { return recs[a].less(&recs[b]) }
			}
			sort.Slice(want, less(want))
			sort.Slice(got, less(got))
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("record %d mismatch: got %+v, want %+v", i,
						got[i], want[i])
				}
			}
		})
	}
}

// TestAddrBuildManifestRoundTrip ensures the scan checkpoint manifest round
// trips all of its fields, and that a missing, truncated, or wrong-magic
// manifest is rejected.
func TestAddrBuildManifestRoundTrip(t *testing.T) {
	t.Parallel()

	manifest := addrBuildManifest{
		completed:    123456,
		baseHeight:   100000,
		targetHeight: 200000,
	}
	for i := range manifest.baseHash {
		manifest.baseHash[i] = byte(i)
		manifest.targetHash[i] = byte(255 - i)
	}

	fromScratch := manifest
	fromScratch.baseHeight = -1
	fromScratch.baseHash = chainhash.Hash{}

	tests := []struct {
		name          string
		manifest      addrBuildManifest
		writeManifest bool
		mutate        func([]byte) []byte
		wantValid     bool
	}{
		{
			name:          "existing base",
			manifest:      manifest,
			writeManifest: true,
			wantValid:     true,
		},
		{
			name:          "from scratch",
			manifest:      fromScratch,
			writeManifest: true,
			wantValid:     true,
		},
		{
			name:      "missing",
			wantValid: false,
		},
		{
			name:          "truncated",
			manifest:      manifest,
			writeManifest: true,
			mutate: func(data []byte) []byte {
				return data[:len(data)-1]
			},
			wantValid: false,
		},
		{
			name:          "wrong magic",
			manifest:      manifest,
			writeManifest: true,
			mutate: func(data []byte) []byte {
				data[0] ^= 0xff
				return data
			},
			wantValid: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if test.writeManifest {
				err := writeAddrBuildManifest(dir, &test.manifest)
				if err != nil {
					t.Fatalf("writeAddrBuildManifest: %v", err)
				}
			}

			if test.mutate != nil {
				path := filepath.Join(dir, addrBuildManifestName)
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read manifest: %v", err)
				}
				if err := os.WriteFile(path, test.mutate(data), 0600); err != nil {
					t.Fatalf("mutate manifest: %v", err)
				}
			}

			got, ok := readAddrBuildManifest(dir)
			if ok != test.wantValid {
				t.Fatalf("manifest validity: got %v, want %v", ok,
					test.wantValid)
			}
			if ok && got != test.manifest {
				t.Fatalf("manifest mismatch: got %+v, want %+v", got,
					test.manifest)
			}
		})
	}
}
