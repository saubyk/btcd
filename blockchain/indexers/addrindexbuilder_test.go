// Copyright (c) 2024 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// addrBuildTestSpec describes one address key and how many entries it has for
// the fast build parity test.
type addrBuildTestSpec struct {
	addrKey    [addrKeySize]byte
	numEntries int
}

// entryLoc returns the block id and transaction location of the i'th entry (in
// oldest-to-newest order) for an address in the parity test.  Several entries
// share a block id to exercise the within-block tiebreak, while the block id and
// transaction offset are both strictly increasing with i so the canonical order
// is unambiguous.
func entryLoc(i int) (uint32, wire.TxLoc) {
	return uint32(i / 3), wire.TxLoc{TxStart: i * 4, TxLen: i + 1}
}

// TestAddrIndexFastBuildParity ensures the fast build write path produces a
// level layout byte-identical to the incremental path.  The reference is built
// by inserting each address's entries in canonical order directly through
// dbPutAddrIndexEntry, while the fast path recovers that order by sorting a
// shuffled record slice, so the test also proves the record ordering is correct.
func TestAddrIndexFastBuildParity(t *testing.T) {
	t.Parallel()

	// mkKey builds an address key with the given type byte, shard byte, and a
	// distinguishing tail byte.
	mkKey := func(typ, shard, tail byte) [addrKeySize]byte {
		var key [addrKeySize]byte
		key[0] = typ
		key[1] = shard
		key[addrKeySize-1] = tail
		return key
	}

	// The specs span several shards (byte 1), multiple keys per shard, several
	// address types (byte 0), and entry counts that exercise level 0 through a
	// handful of higher levels.
	specs := []addrBuildTestSpec{
		{mkKey(0, 0, 1), 1},
		{mkKey(0, 0, 2), level0MaxEntries - 1},
		{mkKey(1, 0, 3), level0MaxEntries},
		{mkKey(2, 0, 4), level0MaxEntries + 1},
		{mkKey(0, 1, 1), level0MaxEntries*2 + 1},
		{mkKey(3, 1, 2), level0MaxEntries*5 + 1},
		{mkKey(4, 5, 1), level0MaxEntries*12 + 1},
		{mkKey(0, 5, 2), 250},
		{mkKey(1, 200, 1), 1000},
		{mkKey(2, 255, 1), 777},
	}

	// Build the reference bucket by inserting each address's entries in
	// canonical order, exactly as the incremental path does.
	reference := &addrIndexBucket{
		levels: make(map[[levelKeySize]byte][]byte),
	}
	for _, spec := range specs {
		for i := 0; i < spec.numEntries; i++ {
			blockID, txLoc := entryLoc(i)
			err := dbPutAddrIndexEntry(reference, spec.addrKey, blockID, txLoc)
			if err != nil {
				t.Fatalf("dbPutAddrIndexEntry: %v", err)
			}
		}
	}

	// Build the flat record slice the fast path consumes and shuffle it so the
	// sort inside emitAddrLevelEntries is what recovers the canonical order.
	var records []addrRecord
	for _, spec := range specs {
		for i := 0; i < spec.numEntries; i++ {
			blockID, txLoc := entryLoc(i)
			records = append(records, addrRecord{
				addrKey: spec.addrKey,
				blockID: blockID,
				txStart: uint32(txLoc.TxStart),
				txLen:   uint32(txLoc.TxLen),
			})
		}
	}
	rng := rand.New(rand.NewSource(1))
	rng.Shuffle(len(records), func(a, b int) {
		records[a], records[b] = records[b], records[a]
	})

	// Run the fast build write path and collect the level entries it emits.
	got := make(map[[levelKeySize]byte][]byte)
	memBucket := &memAddrBucket{levels: make(map[[levelKeySize]byte][]byte)}
	err := emitAddrLevelEntries(records, nil, 0, memBucket,
		func(key [levelKeySize]byte, value []byte) error {
			got[key] = append([]byte(nil), value...)
			return nil
		}, nil)
	if err != nil {
		t.Fatalf("emitAddrLevelEntries: %v", err)
	}

	// The emitted level entries must exactly match the reference.
	if len(got) != len(reference.levels) {
		t.Fatalf("level key count mismatch: got %d, want %d", len(got),
			len(reference.levels))
	}
	for key, want := range reference.levels {
		have, ok := got[key]
		if !ok {
			t.Fatalf("fast build missing level key %x", key)
		}
		if !bytes.Equal(have, want) {
			t.Fatalf("value mismatch for level key %x: got %x, want %x",
				key, have, want)
		}
	}
}

// TestAddrIndexFastBuildDedupsResumeOverlap ensures that duplicate records,
// which a resumed build produces when it re-scans heights whose records were
// spilled but not checkpointed, do not change the built index.  The output must
// match a reference built from the entries exactly once.
func TestAddrIndexFastBuildDedupsResumeOverlap(t *testing.T) {
	t.Parallel()

	var addrKey [addrKeySize]byte
	addrKey[0] = 2
	addrKey[1] = 42
	addrKey[addrKeySize-1] = 9
	const numEntries = level0MaxEntries*6 + 3

	// Reference: insert each entry exactly once in canonical order.
	reference := &addrIndexBucket{
		levels: make(map[[levelKeySize]byte][]byte),
	}
	var records []addrRecord
	for i := 0; i < numEntries; i++ {
		blockID, txLoc := entryLoc(i)
		if err := dbPutAddrIndexEntry(reference, addrKey, blockID, txLoc); err != nil {
			t.Fatalf("dbPutAddrIndexEntry: %v", err)
		}
		records = append(records, addrRecord{
			addrKey: addrKey,
			blockID: blockID,
			txStart: uint32(txLoc.TxStart),
			txLen:   uint32(txLoc.TxLen),
		})
	}

	// Duplicate the second half of the entries, as if those heights were
	// re-scanned on resume, then shuffle everything.
	records = append(records, records[numEntries/2:]...)
	rng := rand.New(rand.NewSource(3))
	rng.Shuffle(len(records), func(a, b int) {
		records[a], records[b] = records[b], records[a]
	})

	got := make(map[[levelKeySize]byte][]byte)
	memBucket := &memAddrBucket{levels: make(map[[levelKeySize]byte][]byte)}
	err := emitAddrLevelEntries(records, nil, 0, memBucket,
		func(key [levelKeySize]byte, value []byte) error {
			got[key] = append([]byte(nil), value...)
			return nil
		}, nil)
	if err != nil {
		t.Fatalf("emitAddrLevelEntries: %v", err)
	}

	if len(got) != len(reference.levels) {
		t.Fatalf("level key count mismatch: got %d, want %d", len(got),
			len(reference.levels))
	}
	for key, want := range reference.levels {
		if have, ok := got[key]; !ok || !bytes.Equal(have, want) {
			t.Fatalf("value mismatch for level key %x: got %x, want %x",
				key, have, want)
		}
	}
}

// insertAddrEntries inserts entries from (inclusive) to (exclusive) of the
// canonical entryLoc sequence for the address into the bucket through
// dbPutAddrIndexEntry, exactly as the incremental path would.
func insertAddrEntries(t *testing.T, bucket internalBucket,
	addrKey [addrKeySize]byte, from, to int) {

	t.Helper()
	for i := from; i < to; i++ {
		blockID, txLoc := entryLoc(i)
		if err := dbPutAddrIndexEntry(bucket, addrKey, blockID, txLoc); err != nil {
			t.Fatalf("dbPutAddrIndexEntry: %v", err)
		}
	}
}

// addrLevelValues returns copies of the address's level values from the bucket
// in ascending level order, or nil when the address has none.
func addrLevelValues(bucket *addrIndexBucket, addrKey [addrKeySize]byte) [][]byte {
	var levels [][]byte
	for level := uint8(0); ; level++ {
		value := bucket.levels[keyForLevel(addrKey, level)]
		if value == nil {
			return levels
		}
		levels = append(levels, append([]byte(nil), value...))
	}
}

// addrRecordsRange returns the records for entries from (inclusive) to
// (exclusive) of the canonical entryLoc sequence for the address.
func addrRecordsRange(addrKey [addrKeySize]byte, from, to int) []addrRecord {
	records := make([]addrRecord, 0, to-from)
	for i := from; i < to; i++ {
		blockID, txLoc := entryLoc(i)
		records = append(records, addrRecord{
			addrKey: addrKey,
			blockID: blockID,
			txStart: uint32(txLoc.TxStart),
			txLen:   uint32(txLoc.TxLen),
		})
	}
	return records
}

// applyAddrLevelEmissions returns an emit callback that applies puts and nil
// value deletes to the bucket, the same way the write phase applies them to
// the database.
func applyAddrLevelEmissions(bucket *addrIndexBucket) func([levelKeySize]byte, []byte) error {
	return func(key [levelKeySize]byte, value []byte) error {
		if value == nil {
			return bucket.Delete(key[:])
		}
		return bucket.Put(key[:], append([]byte(nil), value...))
	}
}

// assertLevelsEqual fails the test when the two level maps differ.
func assertLevelsEqual(t *testing.T, got, want map[[levelKeySize]byte][]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("level key count mismatch: got %d, want %d", len(got),
			len(want))
	}
	for key, wantValue := range want {
		if gotValue, ok := got[key]; !ok || !bytes.Equal(gotValue, wantValue) {
			t.Fatalf("value mismatch for level key %x: got %x, want %x",
				key, gotValue, wantValue)
		}
	}
}

// TestAddrIndexFastBuildMergeParity ensures the write path of a build that
// extends a partially built index produces exactly the level layout the
// incremental path would have.  Each address's entries through the base are
// inserted incrementally as the existing index state, the remainder is
// replayed through emitAddrLevelEntries as staged records, and the combined
// result must match a reference built by inserting the full sequence
// incrementally.
func TestAddrIndexFastBuildMergeParity(t *testing.T) {
	t.Parallel()

	// entryLoc assigns three entries per block id, so the first numCovered
	// entries have block ids at most baseBlockID and are covered by the base.
	const baseBlockID = 5
	const numCovered = (baseBlockID + 1) * 3

	mkKey := func(typ, shard, tail byte) [addrKeySize]byte {
		var key [addrKeySize]byte
		key[0] = typ
		key[1] = shard
		key[addrKeySize-1] = tail
		return key
	}

	// The entry counts cover addresses the base fully covers, which spill no
	// records at all, an address that barely extends past the base, and
	// addresses whose staged entries grow the levels well past the existing
	// ones.
	specs := []addrBuildTestSpec{
		{mkKey(0, 0, 1), 5},
		{mkKey(0, 0, 2), numCovered},
		{mkKey(1, 0, 3), numCovered + 1},
		{mkKey(2, 4, 1), numCovered + level0MaxEntries*3 + 1},
		{mkKey(0, 4, 2), numCovered + 400},
	}

	reference := &addrIndexBucket{levels: make(map[[levelKeySize]byte][]byte)}
	existingBucket := &addrIndexBucket{levels: make(map[[levelKeySize]byte][]byte)}
	existing := make(map[[addrKeySize]byte][][]byte)
	var records []addrRecord
	for _, spec := range specs {
		insertAddrEntries(t, reference, spec.addrKey, 0, spec.numEntries)

		covered := spec.numEntries
		if covered > numCovered {
			covered = numCovered
		}
		insertAddrEntries(t, existingBucket, spec.addrKey, 0, covered)
		if levels := addrLevelValues(existingBucket, spec.addrKey); levels != nil {
			existing[spec.addrKey] = levels
		}
		records = append(records,
			addrRecordsRange(spec.addrKey, covered, spec.numEntries)...)
	}

	rng := rand.New(rand.NewSource(4))
	rng.Shuffle(len(records), func(a, b int) {
		records[a], records[b] = records[b], records[a]
	})

	// Apply the emitted puts and deletes on top of the existing state, the
	// same way the write phase applies them to the database.
	got := existingBucket.Clone()
	memBucket := &memAddrBucket{levels: make(map[[levelKeySize]byte][]byte)}
	err := emitAddrLevelEntries(records, existing, baseBlockID, memBucket,
		applyAddrLevelEmissions(got), nil)
	if err != nil {
		t.Fatalf("emitAddrLevelEntries: %v", err)
	}

	assertLevelsEqual(t, got.levels, reference.levels)
}

// TestAddrIndexFastBuildMergeHealsInterruptedWrite ensures a merge whose
// staged entries were already partially written to the index, which is the
// state an interrupted write phase leaves behind, strips those entries from
// the seeded levels and replays them to the same result.  An address the
// interrupted write already finished must produce no emissions at all since
// every level value it has is already correct.
func TestAddrIndexFastBuildMergeHealsInterruptedWrite(t *testing.T) {
	t.Parallel()

	const baseBlockID = 4
	const numCovered = (baseBlockID + 1) * 3
	const numEntries = numCovered + level0MaxEntries*6 + 2

	// mergedPartway had about half of its staged entries written before the
	// interruption, mergedFully had all of them, and mergedNone had none.
	var mergedPartway, mergedFully, mergedNone [addrKeySize]byte
	mergedPartway[1], mergedPartway[2] = 10, 1
	mergedFully[1], mergedFully[2] = 10, 2
	mergedNone[1], mergedNone[2] = 90, 3

	mergedThrough := map[[addrKeySize]byte]int{
		mergedPartway: numCovered + (numEntries-numCovered)/2,
		mergedFully:   numEntries,
		mergedNone:    numCovered,
	}

	reference := &addrIndexBucket{levels: make(map[[levelKeySize]byte][]byte)}
	existingBucket := &addrIndexBucket{levels: make(map[[levelKeySize]byte][]byte)}
	existing := make(map[[addrKeySize]byte][][]byte)
	var records []addrRecord
	for addrKey, through := range mergedThrough {
		insertAddrEntries(t, reference, addrKey, 0, numEntries)
		insertAddrEntries(t, existingBucket, addrKey, 0, through)
		existing[addrKey] = addrLevelValues(existingBucket, addrKey)
		records = append(records,
			addrRecordsRange(addrKey, numCovered, numEntries)...)
	}
	rng := rand.New(rand.NewSource(5))
	rng.Shuffle(len(records), func(a, b int) {
		records[a], records[b] = records[b], records[a]
	})

	got := existingBucket.Clone()
	apply := applyAddrLevelEmissions(got)
	fullyMergedEmissions := 0
	memBucket := &memAddrBucket{levels: make(map[[levelKeySize]byte][]byte)}
	err := emitAddrLevelEntries(records, existing, baseBlockID, memBucket,
		func(key [levelKeySize]byte, value []byte) error {
			var addrKey [addrKeySize]byte
			copy(addrKey[:], key[:addrKeySize])
			if addrKey == mergedFully {
				fullyMergedEmissions++
			}
			return apply(key, value)
		}, nil)
	if err != nil {
		t.Fatalf("emitAddrLevelEntries: %v", err)
	}

	if fullyMergedEmissions != 0 {
		t.Fatalf("fully merged address produced %d emissions, want 0",
			fullyMergedEmissions)
	}
	assertLevelsEqual(t, got.levels, reference.levels)
}

// TestAddrIndexFastBuildMergeDeletesExtraLevels ensures a seeded level that no
// longer exists after the strip and replay is emitted with a nil value so the
// caller removes its key.  The seeded state holds far more entries beyond the
// base than the staged records put back, so the address ends up with fewer
// levels than it had.
func TestAddrIndexFastBuildMergeDeletesExtraLevels(t *testing.T) {
	t.Parallel()

	const baseBlockID = 0
	const numCovered = 3
	const numSeeded = numCovered + level0MaxEntries*5
	const numEntries = numCovered + 3

	var addrKey [addrKeySize]byte
	addrKey[1] = 77

	reference := &addrIndexBucket{levels: make(map[[levelKeySize]byte][]byte)}
	insertAddrEntries(t, reference, addrKey, 0, numEntries)

	existingBucket := &addrIndexBucket{levels: make(map[[levelKeySize]byte][]byte)}
	insertAddrEntries(t, existingBucket, addrKey, 0, numSeeded)
	existing := map[[addrKeySize]byte][][]byte{
		addrKey: addrLevelValues(existingBucket, addrKey),
	}
	if len(existing[addrKey]) <= len(addrLevelValues(reference, addrKey)) {
		t.Fatal("seeded state does not have more levels than the reference")
	}

	got := existingBucket.Clone()
	apply := applyAddrLevelEmissions(got)
	numDeletes := 0
	memBucket := &memAddrBucket{levels: make(map[[levelKeySize]byte][]byte)}
	err := emitAddrLevelEntries(
		addrRecordsRange(addrKey, numCovered, numEntries), existing,
		baseBlockID, memBucket,
		func(key [levelKeySize]byte, value []byte) error {
			if value == nil {
				numDeletes++
			}
			return apply(key, value)
		}, nil)
	if err != nil {
		t.Fatalf("emitAddrLevelEntries: %v", err)
	}

	if numDeletes == 0 {
		t.Fatal("no level keys were emitted for deletion")
	}
	assertLevelsEqual(t, got.levels, reference.levels)
}

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
