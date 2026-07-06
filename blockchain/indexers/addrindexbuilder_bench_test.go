// Copyright (c) 2024 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/wire/v2"
)

func benchmarkAddrRecords(numAddrs, entriesPerAddr int) []addrRecord {
	records := make([]addrRecord, 0, numAddrs*entriesPerAddr)
	for addrNum := 0; addrNum < numAddrs; addrNum++ {
		var addrKey [addrKeySize]byte
		addrKey[1] = byte(addrNum)
		byteOrder.PutUint32(addrKey[addrKeySize-4:], uint32(addrNum))
		for entryNum := 0; entryNum < entriesPerAddr; entryNum++ {
			records = append(records, addrRecord{
				addrKey: addrKey,
				blockID: uint32(entryNum),
				txStart: uint32(entryNum * 100),
				txLen:   100,
			})
		}
	}
	rng := rand.New(rand.NewSource(1))
	rng.Shuffle(len(records), func(i, j int) {
		records[i], records[j] = records[j], records[i]
	})
	return records
}

func benchmarkEmitAddrLevelEntries(b *testing.B, numAddrs, entriesPerAddr int) {
	b.Helper()

	records := benchmarkAddrRecords(numAddrs, entriesPerAddr)
	b.ReportAllocs()
	b.SetBytes(int64(len(records) * addrRecordSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		work := append([]addrRecord(nil), records...)
		memBucket := &memAddrBucket{
			levels: make(map[[levelKeySize]byte][]byte),
		}
		err := emitAddrLevelEntries(work, nil, 0, memBucket,
			func(_ [levelKeySize]byte, _ []byte) error {
				return nil
			}, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkWriteAddrIndexToDB(b *testing.B, numAddrs, entriesPerAddr int) {
	b.Helper()

	records := benchmarkAddrRecords(numAddrs, entriesPerAddr)

	root := b.TempDir()
	db, err := database.Create("ffldb", filepath.Join(root, "db"), wire.MainNet)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })

	idx := NewAddrIndex(db, nil, root)
	if err := db.Update(func(dbTx database.Tx) error {
		return idx.Create(dbTx)
	}); err != nil {
		b.Fatal(err)
	}

	stagingDir := filepath.Join(root, "staging")
	if err := os.Mkdir(stagingDir, 0700); err != nil {
		b.Fatal(err)
	}
	spiller, err := newAddrSpiller(stagingDir)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(spiller.cleanup)
	for i := range records {
		record := &records[i]
		err := spiller.add(&record.addrKey, record.blockID, wire.TxLoc{
			TxStart: int(record.txStart),
			TxLen:   int(record.txLen),
		})
		if err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(records) * addrRecordSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := idx.writeAddrIndexToDB(db, spiller, 0, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriteAddrIndexToDB(b *testing.B) {
	for _, test := range []struct {
		numAddrs       int
		entriesPerAddr int
	}{
		{numAddrs: 1, entriesPerAddr: 100000},
		{numAddrs: 10000, entriesPerAddr: 10},
	} {
		name := fmt.Sprintf("addresses=%d/entries=%d", test.numAddrs,
			test.entriesPerAddr)
		b.Run(name, func(b *testing.B) {
			benchmarkWriteAddrIndexToDB(b, test.numAddrs,
				test.entriesPerAddr)
		})
	}
}

func BenchmarkEmitAddrLevelEntries(b *testing.B) {
	for _, test := range []struct {
		numAddrs       int
		entriesPerAddr int
	}{
		{numAddrs: 1, entriesPerAddr: 100000},
		{numAddrs: 10000, entriesPerAddr: 10},
	} {
		name := fmt.Sprintf("addresses=%d/entries=%d", test.numAddrs,
			test.entriesPerAddr)
		b.Run(name, func(b *testing.B) {
			benchmarkEmitAddrLevelEntries(b, test.numAddrs,
				test.entriesPerAddr)
		})
	}
}
