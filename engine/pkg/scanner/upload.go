package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// uploadTTL is how long a staged template directory survives without a run.
// It is a cleanup interval for abandoned uploads, not a limit on how much an
// operator may upload: staging itself has no file or byte ceiling.
const uploadTTL = 2 * time.Hour

// uploadSession is one staged template set waiting for its run. Chunks of the
// same folder accumulate here, so a staged upload spans as many requests as the
// browser needed to send it.
type uploadSession struct {
	ID        string
	Dir       string
	Staged    []StagedFile
	UsedPaths map[string]int
	CreatedAt time.Time
}

// uploadStore keeps staged template directories alive between the chunked
// upload requests and the run request that consumes them.
type uploadStore struct {
	mutex    sync.Mutex
	sessions map[string]*uploadSession
}

var uploads = &uploadStore{sessions: map[string]*uploadSession{}}

func newUploadID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

// Append stages one chunk into an existing session and returns the session
// together with the per-file results of that chunk.
func (s *uploadStore) Append(id string, files []UploadFile) (*uploadSession, []StagedFile, error) {
	s.mutex.Lock()
	session, ok := s.sessions[id]
	s.mutex.Unlock()
	if !ok {
		return nil, nil, fmt.Errorf("upload %q is unknown or already consumed", id)
	}
	staged, err := stageInto(session.Dir, files, session.UsedPaths)
	if err != nil {
		return nil, nil, err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// The session may have been consumed by a run while the chunk was staging.
	if current, ok := s.sessions[id]; ok {
		current.Staged = append(current.Staged, staged...)
		session = current
	} else {
		return nil, nil, fmt.Errorf("upload %q is unknown or already consumed", id)
	}
	// A per-file limit alone still allows an unbounded session one chunk at a
	// time, so the session total is bounded too. The just-added files are removed
	// again rather than left staged: a half-accepted chunk is the state the next
	// run would silently inherit.
	if total := stagedBytesOnDisk(session.Staged); total > int64(maxUploadSessionBytes()) {
		for _, file := range staged {
			if file.StagedPath != "" {
				os.Remove(file.StagedPath)
			}
		}
		session.Staged = session.Staged[:len(session.Staged)-len(staged)]
		return nil, nil, fmt.Errorf(
			"upload session exceeds the %d-byte limit (TEMPLATE_TOO_LARGE)",
			maxUploadSessionBytes(),
		)
	}
	return session, staged, nil
}

// stagedBytesOnDisk totals the files actually written for a session. Files that
// were refused (oversized, empty, not YAML) carry no StagedPath and contribute
// nothing — the bound is on what the engine holds, not on what was attempted.
func stagedBytesOnDisk(staged []StagedFile) int64 {
	var total int64
	for _, file := range staged {
		if file.StagedPath == "" {
			continue
		}
		if info, err := os.Stat(file.StagedPath); err == nil {
			total += info.Size()
		}
	}
	return total
}

// Add records a freshly staged directory and returns its session id.
func (s *uploadStore) Add(dir string, staged []StagedFile) (string, error) {
	id, err := newUploadID()
	if err != nil {
		return "", err
	}
	usedPaths := make(map[string]int, len(staged))
	for _, file := range staged {
		if file.StagedPath != "" {
			usedPaths[file.StagedPath]++
		}
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.sessions[id] = &uploadSession{
		ID: id, Dir: dir, Staged: staged, UsedPaths: usedPaths, CreatedAt: time.Now(),
	}
	return id, nil
}

// Take removes and returns a session. The caller owns the returned directory
// and must remove it when the run finishes.
func (s *uploadStore) Take(id string) (*uploadSession, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	session, ok := s.sessions[id]
	if ok {
		delete(s.sessions, id)
	}
	return session, ok
}

// Sweep drops sessions that were staged but never run, so an abandoned upload
// cannot leave a template directory behind forever.
func (s *uploadStore) Sweep(now time.Time) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for id, session := range s.sessions {
		if now.Sub(session.CreatedAt) < uploadTTL {
			continue
		}
		os.RemoveAll(session.Dir)
		delete(s.sessions, id)
	}
}

// StageNucleiUpload validates and stages one chunk of uploaded templates. When
// uploadID is empty a new staging session is created and its id is returned;
// when it names an open session the chunk is appended to it, so a whole
// templates folder can arrive over many requests.
func StageNucleiUpload(uploadID string, files []UploadFile) (string, []StagedFile, int, error) {
	if len(files) == 0 {
		return "", nil, 0, fmt.Errorf("files must be a non-empty list")
	}
	uploads.Sweep(time.Now())
	if id := strings.TrimSpace(uploadID); id != "" {
		session, staged, err := uploads.Append(id, files)
		if err != nil {
			return "", nil, 0, err
		}
		return session.ID, staged, len(session.Staged), nil
	}
	dir, staged, err := StageUploads(files)
	if err != nil {
		return "", nil, 0, err
	}
	id, err := uploads.Add(dir, staged)
	if err != nil {
		os.RemoveAll(dir)
		return "", nil, 0, err
	}
	return id, staged, len(staged), nil
}

// RunNucleiUpload runs the templates staged under uploadID and always removes
// the staging directory afterwards, so a consumed upload cannot be replayed.
func RunNucleiUpload(ctx context.Context, uploadID string, request NucleiRequest) (NucleiRun, error) {
	session, ok := uploads.Take(strings.TrimSpace(uploadID))
	if !ok {
		return NucleiRun{}, fmt.Errorf("upload %q is unknown or already consumed", uploadID)
	}
	defer os.RemoveAll(session.Dir)
	return RunNucleiDir(ctx, session.Dir, session.Staged, request)
}

// TakeStagedTemplates removes a staged upload and returns each file together
// with its bytes, so a caller that runs templates itself needs nothing else from
// the staging directory.
//
// The upload is consumed here for the same reason the binary path consumes it: a
// staging directory that can be read twice is a directory whose contents no
// longer say which run they belonged to. The returned contents are in the same
// order as the returned files, and the pairing is by index because both come
// from one slice walk, not from a map.
func TakeStagedTemplates(id string) ([]StagedFile, []string, error) {
	session, ok := uploads.Take(id)
	if !ok {
		return nil, nil, fmt.Errorf("upload %q is unknown or already consumed", id)
	}
	if session.Dir != "" {
		defer os.RemoveAll(session.Dir)
	}
	contents := make([]string, 0, len(session.Staged))
	for _, file := range session.Staged {
		payload, err := os.ReadFile(file.StagedPath)
		if err != nil {
			// A file that cannot be read is reported as an empty body rather
			// than aborting the batch: the caller turns it into a `skipped` row
			// with the path, and the rest of the upload still runs.
			contents = append(contents, "")
			continue
		}
		contents = append(contents, string(payload))
	}
	return session.Staged, contents, nil
}

// SplitFlowTemplates divides a staged set into the files the binary will not
// execute and the files it will.
//
// The split happens before anything runs, so the caller can send each half to
// the engine that can actually execute it and merge the two reports. The
// decision is made from what the document declares, not from what a run returned:
// a file that declares `flow:` is one nuclei 3.11.1 refuses to execute from a
// template run, and discovering that by handing it over and reading the refusal
// would mean every scan pays for the same lesson.
func SplitFlowTemplates(staged []StagedFile) (flow, ordinary []StagedFile) {
	for _, file := range staged {
		if file.Meta != nil && file.Meta.IsFlow() {
			flow = append(flow, file)
			continue
		}
		ordinary = append(ordinary, file)
	}
	return flow, ordinary
}

// UploadInput is one template handed to the engine inline rather than staged
// into a directory. The split a scan makes between the binary path and the local
// runner is a split of one upload, and an inline half is what lets both halves
// belong to the same run.
type UploadInput struct {
	Name    string `json:"name"`
	Path    string `json:"path,omitempty"`
	Content string `json:"content"`
}

// StagedFromUploads turns inline template bodies into staged files, parsing each
// one so the report carries the same identity the staging path would have given
// it. A document that does not parse is kept with its reason rather than dropped:
// the caller reports it as `invalid` next to the rest, and a file that vanished
// here would be a file the operator cannot account for.
func StagedFromUploads(inputs []UploadInput) ([]StagedFile, []string) {
	staged := make([]StagedFile, 0, len(inputs))
	contents := make([]string, 0, len(inputs))
	for _, input := range inputs {
		meta, reason := parseTemplateDocumentWithPath(input.Content, input.Path)
		staged = append(staged, StagedFile{
			UploadName:   input.Name,
			RelativePath: input.Path,
			Meta:         meta,
			Reason:       reason,
		})
		contents = append(contents, input.Content)
	}
	return staged, contents
}
