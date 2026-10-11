package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// intruderResultStore keeps every finding of an attack on disk instead of in
// memory.
//
// A wordlist run is unbounded by design: a hundred thousand payloads produce a
// hundred thousand results, each carrying the full request and response. Holding
// them as decoded maps cost about a gigabyte of resident memory, which is what
// made a long run stall the whole application. Writing each result as one JSON
// line keeps every byte of the evidence and reduces the resident cost of a run
// to a small index: sixteen bytes per result instead of a decoded map with its
// buffers.
//
// The index records where each result starts, so the incremental `since`
// polling the browser already performs reads exactly the lines it needs and
// nothing else. Nothing is dropped, sampled or truncated.
type intruderResultStore struct {
	mutex sync.Mutex
	file  *os.File
	path  string
	index []resultRef
}

// resultRef points at one stored result.
type resultRef struct {
	offset int64
	length int32
}

// intruderResultDir is where running attacks keep their evidence. The engine
// owns this directory: the browser never sends or receives a server path.
var intruderResultDir = func() string {
	dir, err := os.MkdirTemp("", "rr-intruder-*")
	if err != nil {
		return os.TempDir()
	}
	return dir
}()

// newIntruderResultStore creates the spill file of one attack. A failure is not
// fatal: the caller keeps its results in memory so no evidence is ever lost.
func newIntruderResultStore(attackID uint64) (*intruderResultStore, error) {
	path := filepath.Join(intruderResultDir, fmt.Sprintf("intruder-%d.jsonl", attackID))
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &intruderResultStore{file: file, path: path}, nil
}

// Append writes one result and records where it landed.
func (s *intruderResultStore) Append(result map[string]interface{}) error {
	if s == nil || s.file == nil {
		return fmt.Errorf("result store is not available")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	s.mutex.Lock()
	defer s.mutex.Unlock()
	offset, err := s.file.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if _, err := s.file.Write(encoded); err != nil {
		return err
	}
	s.index = append(s.index, resultRef{offset: offset, length: int32(len(encoded))})
	return nil
}

// Len is the number of results stored so far.
func (s *intruderResultStore) Len() int {
	if s == nil {
		return 0
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return len(s.index)
}

// Read returns the results from the given offset onwards, which is exactly the
// incremental read the browser performs while an attack runs.
func (s *intruderResultStore) Read(since int) ([]map[string]interface{}, error) {
	if s == nil {
		return nil, fmt.Errorf("result store is not available")
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// A closed store is reopened rather than declared lost. The spill path closes
	// the handle the moment an append fails, and the findings already written are
	// exactly the ones a full disk or a quota error puts at risk: refusing to read
	// them would discard the evidence the run had already produced, which is the
	// one outcome "no evidence is ever lost" is meant to rule out.
	//
	// The reopened handle stays local: storing it in s.file would leave the field
	// pointing at a handle this function closes on return, and the next Append
	// would write to a closed file.
	reader := s.file
	if reader == nil {
		if s.path == "" {
			return nil, fmt.Errorf("result store is not available")
		}
		file, err := os.Open(s.path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("result store was released: %s", filepath.Base(s.path))
			}
			return nil, fmt.Errorf("result store could not be reopened: %w", err)
		}
		defer file.Close()
		reader = file
	}
	if since < 0 {
		since = 0
	}
	if since > len(s.index) {
		since = len(s.index)
	}
	results := make([]map[string]interface{}, 0, len(s.index)-since)
	var buffer []byte
	for _, ref := range s.index[since:] {
		if cap(buffer) < int(ref.length) {
			buffer = make([]byte, ref.length)
		}
		chunk := buffer[:ref.length]
		if _, err := reader.ReadAt(chunk, ref.offset); err != nil {
			return results, err
		}
		var result map[string]interface{}
		if err := json.Unmarshal(trimRecordSeparator(chunk), &result); err != nil {
			return results, err
		}
		results = append(results, result)
	}
	return results, nil
}

// Close releases the file descriptor. The evidence stays on disk until the
// process exits, so a late poll can still read it.
func (s *intruderResultStore) Close() {
	if s == nil {
		return
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.file != nil {
		_ = s.file.Close()
		s.file = nil
	}
}

// Remove closes the spill file and deletes it.
//
// It is separate from Close because the two mean different things. Close releases
// the handle and the run keeps its evidence readable; Remove gives the disk space
// back, and the caller may no longer read the run. A run that is being released
// for good wants both, and mixing them would mean either a handle kept open or
// evidence deleted on a path that only meant to stop writing.
func (s *intruderResultStore) Remove() {
	if s == nil {
		return
	}
	s.Close()
	s.mutex.Lock()
	path := s.path
	s.path = ""
	s.mutex.Unlock()
	if path == "" {
		return
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		// A file that cannot be removed is a leftover the process will not get a
		// second chance at, so it is named rather than dropped silently.
		log.Printf("[INTRUDER] spill_file_leftover path=%s error=%v", filepath.Base(path), err)
	}
}

// trimRecordSeparator removes the newline a JSON line ends with.
func trimRecordSeparator(raw []byte) []byte {
	for len(raw) > 0 && (raw[len(raw)-1] == '\n' || raw[len(raw)-1] == '\r') {
		raw = raw[:len(raw)-1]
	}
	return raw
}
