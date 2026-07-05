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
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/database"
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

	// addrBuildScanChunkSize is the number of contiguous block heights scanned
	// between checkpoints.  After each chunk the spilled records are synced and
	// a manifest records the height reached so an interrupted build resumes from
	// there rather than restarting.
	addrBuildScanChunkSize = 50000

	// addrBuildManifestName is the file in the staging directory that records
	// the highest checkpointed scan height and the block the scan is
	// targeting.
	addrBuildManifestName = "manifest"

	// addrBuildWriteBatchBytes is the approximate number of value bytes buffered
	// before a database transaction is committed during the write phase.  It
	// bounds the memory a single transaction holds since address index values
	// vary widely in size.
	addrBuildWriteBatchBytes = 32 * 1024 * 1024

	// addrBuildProgressInterval is how often scan progress is logged.
	addrBuildProgressInterval = 15 * time.Second
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

// memAddrBucket is an in-memory internalBucket used to replay one address key's
// entries through dbPutAddrIndexEntry so the write phase produces the same level
// keys and values the incremental path would.
type memAddrBucket struct {
	levels map[[levelKeySize]byte][]byte
}

// Get returns the value associated with the key.
//
// This is part of the internalBucket interface.
func (b *memAddrBucket) Get(key []byte) []byte {
	var levelKey [levelKeySize]byte
	copy(levelKey[:], key)
	return b.levels[levelKey]
}

// Put stores a copy of the provided key/value pair.  The value is copied so the
// caller may reuse or mutate the passed slice, and so the emitted level values
// remain valid after the bucket is reset.
//
// This is part of the internalBucket interface.
func (b *memAddrBucket) Put(key []byte, value []byte) error {
	var levelKey [levelKeySize]byte
	copy(levelKey[:], key)
	stored := make([]byte, len(value))
	copy(stored, value)
	b.levels[levelKey] = stored
	return nil
}

// Delete removes the provided key.
//
// This is part of the internalBucket interface.
func (b *memAddrBucket) Delete(key []byte) error {
	var levelKey [levelKeySize]byte
	copy(levelKey[:], key)
	delete(b.levels, levelKey)
	return nil
}

// reset clears the bucket so it can be reused for the next address key.
func (b *memAddrBucket) reset() {
	clear(b.levels)
}

// scanAddrHeightRange scans the block heights in [start, end] with a pool of
// workers, spilling the derived address index records, and increments scanned
// for every block processed.  Reads are done through read-only views, which is
// safe to do concurrently.
func (idx *AddrIndex) scanAddrHeightRange(chain *blockchain.BlockChain,
	spiller *addrSpiller, start, end int32, numWorkers int,
	scanned *int64, interrupt <-chan struct{}) error {

	heights := make(chan int32, numWorkers*4)
	var (
		wg       sync.WaitGroup
		errOnce  sync.Once
		firstErr error
		stop     = make(chan struct{})
	)
	fail := func(e error) {
		errOnce.Do(func() {
			firstErr = e
			close(stop)
		})
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for height := range heights {
				block, err := chain.BlockByHeight(height)
				if err != nil {
					fail(err)
					return
				}

				// The address index maps the outputs created as well as the
				// outputs spent by a block, so the spend journal is needed to
				// recover the previous output scripts referenced by the inputs.
				stxos, err := chain.FetchSpendJournal(block)
				if err != nil {
					fail(err)
					return
				}

				txLocs, err := block.TxLoc()
				if err != nil {
					fail(err)
					return
				}

				// The block at height h always receives block id h+1 from the
				// transaction index, which assigns ids sequentially from the
				// genesis block, so the id is derived here rather than read back
				// from a transaction index that may not be built yet.
				blockID := uint32(height + 1)

				// Build the address to transaction mappings exactly as the
				// incremental path does, then spill one record per mapping.
				data := make(writeIndexData)
				idx.indexBlock(data, block, stxos)
				for addrKey, txIdxs := range data {
					for _, txIdx := range txIdxs {
						err := spiller.add(&addrKey, blockID, txLocs[txIdx])
						if err != nil {
							fail(err)
							return
						}
					}
				}
				atomic.AddInt64(scanned, 1)
			}
		}()
	}

feed:
	for height := start; height <= end; height++ {
		select {
		case <-stop:
			break feed
		case <-interrupt:
			fail(errInterruptRequested)
			break feed
		case heights <- height:
		}
	}
	close(heights)
	wg.Wait()
	return firstErr
}

// buildAddrIndexRecords scans every block after the base up to the current
// best height in parallel, deriving the address index entries for each block
// and spilling them into shards keyed by the address hash160.  The base is the
// index tip the build extends, height -1 and a zero hash for a build from
// scratch.  It returns the populated spiller, which the caller is responsible
// for cleaning up, along with the height and hash it scanned to.
//
// The scan proceeds in chunks and checkpoints its progress after each one, so an
// interrupted build resumes from the last checkpoint rather than restarting.  It
// is meant to run during index initialization, while the chain is quiescent and
// no blocks are being connected.  Any blocks that arrive after the target height
// is read are connected by the manager's per-block catchup afterwards.
func (idx *AddrIndex) buildAddrIndexRecords(chain *blockchain.BlockChain,
	dataDir string, baseHeight int32, baseHash chainhash.Hash, numWorkers int,
	interrupt <-chan struct{}) (*addrSpiller, chainhash.Hash, int32, error) {

	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	best := chain.BestSnapshot()
	targetHeight := best.Height
	targetHash := best.Hash

	stagingDir := filepath.Join(dataDir, addrIndexBuildDirName, "staging")
	_, statErr := os.Stat(stagingDir)
	stagingExisted := statErr == nil
	if err := os.MkdirAll(stagingDir, 0700); err != nil {
		return nil, chainhash.Hash{}, 0, err
	}

	// Resume from a prior checkpoint if the staging directory holds one for
	// the same base, otherwise start a fresh scan from the block after the
	// base.  Every spilled record, checkpointed or not, comes from an ancestor
	// of the scan target recorded in the manifest, so the staging is only
	// reused while that target is still on the main chain.  A staging
	// directory that cannot be reopened is discarded as well.
	var (
		spiller     *addrSpiller
		startHeight = baseHeight + 1
		err         error
	)
	manifest, ok := readAddrBuildManifest(stagingDir)
	if ok {
		mainChainHash, hashErr := chain.BlockHashByHeight(manifest.targetHeight)
		switch {
		case manifest.baseHeight != baseHeight ||
			!manifest.baseHash.IsEqual(&baseHash):

			log.Warnf("Discarding the interrupted address index scan since " +
				"it does not extend the current index tip")

		case hashErr != nil || !manifest.targetHash.IsEqual(mainChainHash):
			log.Warnf("Discarding the interrupted address index scan since " +
				"the chain it scanned is no longer the main chain")

		default:
			spiller, err = openAddrSpiller(stagingDir)
			if err != nil {
				log.Warnf("Cannot resume address index scan (%v), starting over",
					err)
				spiller = nil
			} else {
				startHeight = manifest.completed + 1
				log.Infof("Resuming address index scan from height %d of %d",
					startHeight, targetHeight)
			}
		}
	}
	if spiller == nil {
		if baseHeight == -1 {
			// Anything an earlier interrupted build already wrote into the
			// address index bucket cannot be trusted without resumable
			// staging, since it may belong to a chain that has since been
			// reorged.  Clear the bucket so the build starts empty.
			if err := idx.clearAddrIndexBucket(interrupt); err != nil {
				return nil, chainhash.Hash{}, 0, err
			}
		} else if stagingExisted &&
			(!ok || manifest.completed >= manifest.targetHeight) {

			// The write phase of the discarded build, which only runs once
			// its scan reaches the target, may have merged entries beyond the
			// base into the bucket.  Those entries cannot be trusted for the
			// same reason, so remove them while keeping everything the index
			// tip covers.
			err := idx.removeAddrIndexEntriesAboveBlockID(
				uint32(baseHeight+1), interrupt,
			)
			if err != nil {
				return nil, chainhash.Hash{}, 0, err
			}
		}

		os.RemoveAll(stagingDir)
		if err := os.MkdirAll(stagingDir, 0700); err != nil {
			return nil, chainhash.Hash{}, 0, err
		}
		spiller, err = newAddrSpiller(stagingDir)
		if err != nil {
			return nil, chainhash.Hash{}, 0, err
		}
	}

	// The scan already reached the tip on a previous run, so leave the write to
	// the caller.
	if startHeight > targetHeight {
		return spiller, targetHash, targetHeight, nil
	}

	log.Infof("Scanning blocks %d to %d for address index entries using %d workers",
		startHeight, targetHeight, numWorkers)

	// Log progress periodically off a shared counter the workers advance.
	scanned := int64(startHeight)
	progressDone := make(chan struct{})
	var progressWg sync.WaitGroup
	progressWg.Add(1)
	go func() {
		defer progressWg.Done()
		ticker := time.NewTicker(addrBuildProgressInterval)
		defer ticker.Stop()
		for {
			select {
			case <-progressDone:
				return
			case <-ticker.C:
				n := atomic.LoadInt64(&scanned)
				log.Infof("Address index scan: %d/%d blocks (%.1f%%)", n,
					targetHeight, float64(n)/float64(targetHeight)*100)
			}
		}
	}()

	// Scan in chunks, checkpointing after each so the build can resume.
	var scanErr error
	for chunkStart := startHeight; chunkStart <= targetHeight; chunkStart += addrBuildScanChunkSize {
		chunkEnd := chunkStart + addrBuildScanChunkSize - 1
		if chunkEnd > targetHeight {
			chunkEnd = targetHeight
		}

		scanErr = idx.scanAddrHeightRange(chain, spiller, chunkStart, chunkEnd,
			numWorkers, &scanned, interrupt)
		if scanErr != nil {
			break
		}
		if scanErr = spiller.sync(); scanErr != nil {
			break
		}
		scanErr = writeAddrBuildManifest(stagingDir, &addrBuildManifest{
			completed:    chunkEnd,
			baseHeight:   baseHeight,
			targetHeight: targetHeight,
			baseHash:     baseHash,
			targetHash:   targetHash,
		})
		if scanErr != nil {
			break
		}
		log.Debugf("Checkpointed address index scan at height %d", chunkEnd)
	}

	close(progressDone)
	progressWg.Wait()

	if scanErr != nil {
		// Keep the staging directory so the scan can resume, but release the
		// file handles.
		spiller.closeShards()
		return nil, chainhash.Hash{}, 0, scanErr
	}

	return spiller, targetHash, targetHeight, nil
}

// emitAddrLevelEntries sorts the records, groups them by address key, replays
// each group through dbPutAddrIndexEntry against memBucket, and invokes emit for
// every produced level key in ascending level order.  Replaying the sorted
// entries through the same routine the incremental path uses is what makes the
// emitted level keys and values byte-identical to a block-by-block build.
// memBucket is reused across groups and must be non-nil.
//
// A build that extends an existing index provides the level values every
// address already has in the database via existing, along with the block id of
// the base the build extends.  Each group's replay then starts from those
// levels after stripping any entries beyond the base, which an interrupted
// write of the same staging may have merged already.  Level values that end up
// unchanged are not emitted, and a seeded level that no longer exists is
// emitted with a nil value so the caller deletes it.
//
// addrDone, when non-nil, is invoked after each address's emissions.  It gives
// the caller a safe point to commit what has been emitted so far, since
// committing only part of an address would leave a mix of old and new level
// values for a resumed build to seed its replay from.
func emitAddrLevelEntries(records []addrRecord,
	existing map[[addrKeySize]byte][][]byte, baseBlockID uint32,
	memBucket *memAddrBucket,
	emit func(key [levelKeySize]byte, value []byte) error,
	addrDone func() error) error {

	sort.Slice(records, func(a, b int) bool {
		return records[a].less(&records[b])
	})

	for j := 0; j < len(records); {
		// Gather the contiguous run of records for one address key.
		addrKey := records[j].addrKey
		k := j
		for k < len(records) && records[k].addrKey == addrKey {
			k++
		}

		// Seed the replay with the level values the address already has,
		// counting the entries beyond the base so they can be stripped.
		memBucket.reset()
		existingLevels := existing[addrKey]
		numStale := 0
		for level, value := range existingLevels {
			levelKey := keyForLevel(addrKey, uint8(level))
			if err := memBucket.Put(levelKey[:], value); err != nil {
				return err
			}
			for off := 0; off+txEntrySize <= len(value); off += txEntrySize {
				if byteOrder.Uint32(value[off:]) > baseBlockID {
					numStale++
				}
			}
		}
		if numStale > 0 {
			err := dbRemoveAddrIndexEntries(memBucket, addrKey, numStale)
			if err != nil {
				return err
			}
		}

		// Reconstruct the on-disk level layout by replaying the entries in
		// order through the same routine the incremental path uses.
		var (
			havePrev    bool
			prevBlockID uint32
			prevTxStart uint32
		)
		for _, r := range records[j:k] {
			// Skip exact-duplicate entries.  A legitimate entry for an address
			// is unique per block and transaction, so identical (blockID,
			// txStart) records only arise when a resumed build re-scans heights
			// whose records were spilled but not yet checkpointed.
			if havePrev && r.blockID == prevBlockID && r.txStart == prevTxStart {
				continue
			}
			havePrev = true
			prevBlockID = r.blockID
			prevTxStart = r.txStart

			txLoc := wire.TxLoc{
				TxStart: int(r.txStart),
				TxLen:   int(r.txLen),
			}
			err := dbPutAddrIndexEntry(memBucket, addrKey, r.blockID, txLoc)
			if err != nil {
				return err
			}
		}

		// Emit the produced level keys in ascending level order.  There are no
		// gaps, so the first missing level ends the address.  Seeded levels
		// whose value did not change are already in the database and are
		// skipped.
		numLevels := 0
		for level := uint8(0); ; level++ {
			levelKey := keyForLevel(addrKey, level)
			value := memBucket.levels[levelKey]
			if value == nil {
				break
			}
			numLevels++
			if int(level) < len(existingLevels) &&
				bytes.Equal(value, existingLevels[level]) {
				continue
			}
			if err := emit(levelKey, value); err != nil {
				return err
			}
		}

		// Any seeded level beyond the ones produced no longer exists, so emit
		// a nil value for it to have the caller delete it.
		for level := numLevels; level < len(existingLevels); level++ {
			levelKey := keyForLevel(addrKey, uint8(level))
			if err := emit(levelKey, nil); err != nil {
				return err
			}
		}

		if addrDone != nil {
			if err := addrDone(); err != nil {
				return err
			}
		}
		j = k
	}
	return nil
}

// fetchExistingAddrLevels returns the level values every address appearing in
// the records already has in the address index bucket, in ascending level
// order.  Addresses with no levels are absent from the returned map.
func fetchExistingAddrLevels(db database.DB,
	records []addrRecord) (map[[addrKeySize]byte][][]byte, error) {

	addrKeys := make(map[[addrKeySize]byte]struct{})
	for i := range records {
		addrKeys[records[i].addrKey] = struct{}{}
	}

	existing := make(map[[addrKeySize]byte][][]byte)
	err := db.View(func(dbTx database.Tx) error {
		bucket := dbTx.Metadata().Bucket(addrIndexKey)
		for addrKey := range addrKeys {
			// Levels have no gaps, so the first missing level ends the
			// address.  The values are copied since they are only valid for
			// the duration of the transaction.
			var levels [][]byte
			for level := uint8(0); ; level++ {
				levelKey := keyForLevel(addrKey, level)
				value := bucket.Get(levelKey[:])
				if value == nil {
					break
				}
				levels = append(levels, append([]byte(nil), value...))
			}
			if levels != nil {
				existing[addrKey] = levels
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return existing, nil
}

// writeAddrIndexToDB sorts each shard, groups its records by address key, and
// writes each address's level entries into the address index bucket in batched
// transactions.  Shards are processed in order and each shard is sorted, so the
// database receives keys in mostly ascending order.  baseBlockID is the block
// id of the index tip the build extends, or zero for a build from scratch, and
// a nonzero value has each address's staged entries merged into the level
// values it already has.
func (idx *AddrIndex) writeAddrIndexToDB(db database.DB, spiller *addrSpiller,
	baseBlockID uint32, interrupt <-chan struct{}) error {

	for i := range spiller.shards {
		if err := spiller.shards[i].buf.Flush(); err != nil {
			return err
		}
	}

	type levelEntry struct {
		key   [levelKeySize]byte
		value []byte
	}
	batch := make([]levelEntry, 0, 4096)
	deletes := make([][levelKeySize]byte, 0)
	var batchBytes int
	flush := func() error {
		if len(batch) == 0 && len(deletes) == 0 {
			return nil
		}
		err := db.Update(func(dbTx database.Tx) error {
			bucket := dbTx.Metadata().Bucket(addrIndexKey)
			for j := range batch {
				err := bucket.Put(batch[j].key[:], batch[j].value)
				if err != nil {
					return err
				}
			}
			// Merging into existing levels can leave an address with fewer
			// levels than it had, so remove the level keys that no longer
			// exist.
			for j := range deletes {
				if err := bucket.Delete(deletes[j][:]); err != nil {
					return err
				}
			}
			return nil
		})
		batch = batch[:0]
		deletes = deletes[:0]
		batchBytes = 0
		return err
	}

	memBucket := &memAddrBucket{levels: make(map[[levelKeySize]byte][]byte)}
	for i := range spiller.shards {
		if interruptRequested(interrupt) {
			return errInterruptRequested
		}

		records, err := readAddrSpillShard(spiller.shards[i].f)
		if err != nil {
			return err
		}

		// When the build extends an existing index, load the level values the
		// shard's addresses already have so the staged entries merge into
		// them.  Addresses never span shards, so the levels a prior shard's
		// flush may still have pending are not read here.
		var existing map[[addrKeySize]byte][][]byte
		if baseBlockID > 0 {
			existing, err = fetchExistingAddrLevels(db, records)
			if err != nil {
				return err
			}
		}

		err = emitAddrLevelEntries(records, existing, baseBlockID, memBucket,
			func(key [levelKeySize]byte, value []byte) error {
				if value == nil {
					deletes = append(deletes, key)
					return nil
				}
				batch = append(batch, levelEntry{key: key, value: value})
				batchBytes += len(value) + levelKeySize
				return nil
			},
			func() error {
				if batchBytes >= addrBuildWriteBatchBytes {
					return flush()
				}
				return nil
			})
		if err != nil {
			return err
		}
	}
	return flush()
}

// clearAddrIndexBucket deletes every entry in the address index bucket.  Since
// the bucket can be massive, the entries are deleted in multiple database
// transactions to keep memory usage to reasonable levels.  It is a no-op
// beyond a single empty transaction when the bucket holds nothing.
func (idx *AddrIndex) clearAddrIndexBucket(interrupt <-chan struct{}) error {
	const maxDeletions = 2000000
	var totalDeleted uint64
	for numDeleted := maxDeletions; numDeleted == maxDeletions; {
		if interruptRequested(interrupt) {
			return errInterruptRequested
		}

		numDeleted = 0
		err := idx.db.Update(func(dbTx database.Tx) error {
			bucket := dbTx.Metadata().Bucket(addrIndexKey)
			if bucket == nil {
				return nil
			}
			cursor := bucket.Cursor()
			for ok := cursor.First(); ok; ok = cursor.Next() &&
				numDeleted < maxDeletions {

				if err := cursor.Delete(); err != nil {
					return err
				}
				numDeleted++
			}
			return nil
		})
		if err != nil {
			return err
		}

		if numDeleted > 0 {
			totalDeleted += uint64(numDeleted)
			log.Infof("Deleted %d stale address index entries (%d total)",
				numDeleted, totalDeleted)
		}
	}
	return nil
}

// removeAddrIndexEntriesAboveBlockID removes every entry in the address index
// bucket that references a block id greater than the one provided.  Entries
// are appended in block order, so an address's entries beyond the given block
// id are always its most recent ones and are removed the same way the
// incremental path removes entries for a disconnected block.  This restores
// the bucket to exactly what the index tip covers after the write phase of a
// discarded build merged entries beyond it.
func (idx *AddrIndex) removeAddrIndexEntriesAboveBlockID(maxBlockID uint32,
	interrupt <-chan struct{}) error {

	// Collect how many entries beyond the block id every address has.
	staleCounts := make(map[[addrKeySize]byte]int)
	err := idx.db.View(func(dbTx database.Tx) error {
		bucket := dbTx.Metadata().Bucket(addrIndexKey)
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(k, v []byte) error {
			if len(k) != levelKeySize {
				return nil
			}
			numStale := 0
			for off := 0; off+txEntrySize <= len(v); off += txEntrySize {
				if byteOrder.Uint32(v[off:]) > maxBlockID {
					numStale++
				}
			}
			if numStale > 0 {
				var addrKey [addrKeySize]byte
				copy(addrKey[:], k)
				staleCounts[addrKey] += numStale
			}
			return nil
		})
	})
	if err != nil {
		return err
	}
	if len(staleCounts) == 0 {
		return nil
	}

	log.Infof("Removing stale address index entries beyond the index tip "+
		"for %d addresses", len(staleCounts))

	addrKeys := make([][addrKeySize]byte, 0, len(staleCounts))
	for addrKey := range staleCounts {
		addrKeys = append(addrKeys, addrKey)
	}

	// Remove the entries in multiple transactions to keep the memory a single
	// transaction holds to reasonable levels.
	const addrsPerTx = 4096
	for start := 0; start < len(addrKeys); start += addrsPerTx {
		if interruptRequested(interrupt) {
			return errInterruptRequested
		}

		end := start + addrsPerTx
		if end > len(addrKeys) {
			end = len(addrKeys)
		}
		err := idx.db.Update(func(dbTx database.Tx) error {
			bucket := dbTx.Metadata().Bucket(addrIndexKey)
			for _, addrKey := range addrKeys[start:end] {
				err := dbRemoveAddrIndexEntries(bucket, addrKey,
					staleCounts[addrKey])
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// buildAddrIndexFromChain builds the address index into the address index bucket
// of the main database, on top of whatever the index holds through the given
// base.  The base is the current index tip, height -1 and a zero hash for a
// build from scratch.  It returns the height and hash it was built to.
func (idx *AddrIndex) buildAddrIndexFromChain(chain *blockchain.BlockChain,
	dataDir string, baseHeight int32, baseHash chainhash.Hash, numWorkers int,
	interrupt <-chan struct{}) (chainhash.Hash, int32, error) {

	spiller, targetHash, targetHeight, err := idx.buildAddrIndexRecords(chain,
		dataDir, baseHeight, baseHash, numWorkers, interrupt)
	if err != nil {
		return chainhash.Hash{}, 0, err
	}

	log.Infof("Writing address index into the database")
	err = idx.writeAddrIndexToDB(idx.db, spiller, uint32(baseHeight+1),
		interrupt)
	if err != nil {
		// Keep the completed scan staged so a retry skips straight to the write
		// rather than rescanning.
		spiller.closeShards()
		return chainhash.Hash{}, 0, err
	}
	spiller.closeShards()

	log.Infof("Built address index into the database at height %d (%s)",
		targetHeight, targetHash)
	return targetHash, targetHeight, nil
}

// AddrIndexFastBuildStaging returns the directory an address index fast build
// stages its work in under the given data directory, and whether it currently
// exists on disk.  An interrupted build keeps its staging so a later run can
// resume, and only running the build to completion or DropAddrIndex removes
// it.
func AddrIndexFastBuildStaging(dataDir string) (string, bool) {
	dir := filepath.Join(dataDir, addrIndexBuildDirName)
	_, err := os.Stat(dir)
	return dir, err == nil
}
