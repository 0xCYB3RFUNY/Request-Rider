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
	return session, staged, nil
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
