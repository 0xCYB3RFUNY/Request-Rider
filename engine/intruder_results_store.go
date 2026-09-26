package main

import (
	"encoding/json"
	"fmt"
	"io"
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
	if s == nil || s.file == nil {
		return nil, fmt.Errorf("result store is not available")
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
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
		if _, err := s.file.ReadAt(chunk, ref.offset); err != nil {
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

// trimRecordSeparator removes the newline a JSON line ends with.
func trimRecordSeparator(raw []byte) []byte {
	for len(raw) > 0 && (raw[len(raw)-1] == '\n' || raw[len(raw)-1] == '\r') {
		raw = raw[:len(raw)-1]
	}
	return raw
}
