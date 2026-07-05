// Copyright (c) 2024 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

const (
	// addrIndexBuildDirName is the subdirectory of the data dir that holds the
	// address index build staging files.
	addrIndexBuildDirName = "addrindexbuild"

	// addrRecordSize is the size of a spilled record: the address key followed
	// by the block id and transaction location it maps to.  It is exactly one
	// address index entry keyed by its address.
	addrRecordSize = addrKeySize + txEntrySize

	// addrBuildManifestVersion is the version of the scan checkpoint manifest.
	addrBuildManifestVersion = 1

	// numAddrSpillShards is the number of staging shards records are
	// partitioned into during a build, keyed by the first byte of the address
	// hash160.  That byte is uniformly distributed for the hashed address
	// types, so the records spread evenly across the shards and every entry for
	// a given address lands in the same shard, which is what lets each shard be
	// sorted and written independently.
	numAddrSpillShards = 256

	// addrBuildManifestName is the file in the staging directory that records
	// the highest checkpointed scan height and the block the scan is
	// targeting.
	addrBuildManifestName = "manifest"
)

// addrBuildManifestMagic identifies the serialized address index scan
// checkpoint.
var addrBuildManifestMagic = [4]byte{'a', 'd', 'r', 'b'}

// addrRecord is a single address index entry keyed by the address it maps to.
type addrRecord struct {
	addrKey [addrKeySize]byte
	blockID uint32
	txStart uint32
	txLen   uint32
}

// less orders records by address key, then by the order the incremental path
// would have inserted the entry: block id ascending, then transaction offset
// ascending within the block.  Grouping by address key and following that order
// is what lets the write phase reproduce the on-disk level layout exactly.
func (r *addrRecord) less(o *addrRecord) bool {
	if c := bytes.Compare(r.addrKey[:], o.addrKey[:]); c != 0 {
		return c < 0
	}
	if r.blockID != o.blockID {
		return r.blockID < o.blockID
	}
	return r.txStart < o.txStart
}

// addrSpillShard owns one shard's file and buffer.  Its mutex protects the
// shared scratch record and writer during unordered appends.  The write phase
// sorts the records before rebuilding the address index levels.
type addrSpillShard struct {
	mu  sync.Mutex
	f   *os.File
	buf *bufio.Writer
	rec [addrRecordSize]byte
}

// addrSpiller owns the hash-prefix shards for one address index fast build.
// Routing by the first hash160 byte keeps each address in one shard and permits
// concurrent appends.  The write phase decodes and sorts shards sequentially
// instead of loading all staged records at once.
type addrSpiller struct {
	dir    string
	shards [numAddrSpillShards]addrSpillShard
}

// newAddrSpiller creates a spiller with a staging file per shard in dir.
func newAddrSpiller(dir string) (*addrSpiller, error) {
	s := &addrSpiller{dir: dir}
	for i := range s.shards {
		path := filepath.Join(dir, fmt.Sprintf("shard-%03d.tmp", i))
		f, err := os.Create(path)
		if err != nil {
			s.closeShards()
			return nil, err
		}
		s.shards[i].f = f
		s.shards[i].buf = bufio.NewWriterSize(f, 64*1024)
	}
	return s, nil
}

// openAddrSpiller reopens the staging shards of an interrupted build for
// appending.  Each shard is truncated to a whole number of records so a torn
// trailing record from an interrupted write is dropped.
func openAddrSpiller(dir string) (*addrSpiller, error) {
	s := &addrSpiller{dir: dir}
	for i := range s.shards {
		path := filepath.Join(dir, fmt.Sprintf("shard-%03d.tmp", i))
		f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0666)
		if err != nil {
			s.closeShards()
			return nil, err
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			s.closeShards()
			return nil, err
		}
		if rem := info.Size() % addrRecordSize; rem != 0 {
			if err := f.Truncate(info.Size() - rem); err != nil {
				f.Close()
				s.closeShards()
				return nil, err
			}
		}
		s.shards[i].f = f
		s.shards[i].buf = bufio.NewWriterSize(f, 64*1024)
	}
	return s, nil
}

// sync flushes and fsyncs every shard so the records written so far are durable
// before a checkpoint manifest referring to them is written.
func (s *addrSpiller) sync() error {
	for i := range s.shards {
		if err := s.shards[i].buf.Flush(); err != nil {
			return err
		}
		if err := s.shards[i].f.Sync(); err != nil {
			return err
		}
	}
	return nil
}

// add appends an address index entry to the shard for its address key.
func (s *addrSpiller) add(addrKey *[addrKeySize]byte, blockID uint32, txLoc wire.TxLoc) error {
	sh := &s.shards[addrKey[1]]
	sh.mu.Lock()
	defer sh.mu.Unlock()

	copy(sh.rec[:addrKeySize], addrKey[:])
	byteOrder.PutUint32(sh.rec[addrKeySize:], blockID)
	byteOrder.PutUint32(sh.rec[addrKeySize+4:], uint32(txLoc.TxStart))
	byteOrder.PutUint32(sh.rec[addrKeySize+8:], uint32(txLoc.TxLen))
	_, err := sh.buf.Write(sh.rec[:])
	return err
}

// closeShards closes all open shard files.
func (s *addrSpiller) closeShards() {
	for i := range s.shards {
		if s.shards[i].f != nil {
			s.shards[i].f.Close()
		}
	}
}

// cleanup closes the shard files and removes the staging directory.
func (s *addrSpiller) cleanup() {
	s.closeShards()
	os.RemoveAll(s.dir)
}

// readAddrSpillShard reads all records from a staging shard file into memory.
func readAddrSpillShard(f *os.File) ([]addrRecord, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size()%addrRecordSize != 0 {
		return nil, fmt.Errorf("address index spill shard has a truncated record")
	}

	numRecords64 := info.Size() / addrRecordSize
	numRecords := int(numRecords64)
	if int64(numRecords) != numRecords64 {
		return nil, fmt.Errorf("address index spill shard is too large")
	}
	records := make([]addrRecord, numRecords)
	const maxRecordsPerRead = 1024 * 1024 / addrRecordSize
	readBuf := make([]byte, min(numRecords, maxRecordsPerRead)*addrRecordSize)
	for first := 0; first < numRecords; {
		n := min(numRecords-first, maxRecordsPerRead)
		data := readBuf[:n*addrRecordSize]
		if _, err := io.ReadFull(f, data); err != nil {
			return nil, err
		}
		for i := 0; i < n; i++ {
			off := i * addrRecordSize
			record := &records[first+i]
			copy(record.addrKey[:], data[off:off+addrKeySize])
			record.blockID = byteOrder.Uint32(data[off+addrKeySize:])
			record.txStart = byteOrder.Uint32(data[off+addrKeySize+4:])
			record.txLen = byteOrder.Uint32(data[off+addrKeySize+8:])
		}
		first += n
	}
	return records, nil
}

// addrBuildManifest is a scan checkpoint.  It records the index tip the build
// extends (height -1 and a zero hash for a build from scratch), the block the
// scan is targeting, and the height the scan has completed through.
type addrBuildManifest struct {
	completed    int32
	baseHeight   int32
	targetHeight int32
	baseHash     chainhash.Hash
	targetHash   chainhash.Hash
}

// addrBuildManifestSize is the serialized size of a scan checkpoint manifest.
const addrBuildManifestSize = 17 + 2*chainhash.HashSize

// writeAddrBuildManifest atomically records the provided scan checkpoint in
// the staging directory.
func writeAddrBuildManifest(stagingDir string, manifest *addrBuildManifest) error {
	var buf [addrBuildManifestSize]byte
	copy(buf[0:4], addrBuildManifestMagic[:])
	buf[4] = addrBuildManifestVersion
	byteOrder.PutUint32(buf[5:9], uint32(manifest.completed))
	byteOrder.PutUint32(buf[9:13], uint32(manifest.baseHeight))
	byteOrder.PutUint32(buf[13:17], uint32(manifest.targetHeight))
	copy(buf[17:17+chainhash.HashSize], manifest.baseHash[:])
	copy(buf[17+chainhash.HashSize:], manifest.targetHash[:])

	tmpPath := filepath.Join(stagingDir, addrBuildManifestName+".tmp")
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf[:]); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, filepath.Join(stagingDir, addrBuildManifestName))
}

// readAddrBuildManifest returns the scan checkpoint recorded in the staging
// directory and whether a valid manifest was present.
func readAddrBuildManifest(stagingDir string) (addrBuildManifest, bool) {
	var manifest addrBuildManifest
	data, err := os.ReadFile(filepath.Join(stagingDir, addrBuildManifestName))
	if err != nil || len(data) != addrBuildManifestSize {
		return manifest, false
	}
	if !bytes.Equal(data[0:4], addrBuildManifestMagic[:]) ||
		data[4] != addrBuildManifestVersion {
		return manifest, false
	}

	manifest.completed = int32(byteOrder.Uint32(data[5:9]))
	manifest.baseHeight = int32(byteOrder.Uint32(data[9:13]))
	manifest.targetHeight = int32(byteOrder.Uint32(data[13:17]))
	copy(manifest.baseHash[:], data[17:17+chainhash.HashSize])
	copy(manifest.targetHash[:], data[17+chainhash.HashSize:])
	return manifest, true
}
