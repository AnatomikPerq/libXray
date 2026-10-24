package netreport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// A report takes a minute or more. Mobile platforms serialize every libXray
// call behind one lock, so the App starts a run and polls its snapshot
// instead of blocking in one call.

const keepFinished = 10 * time.Minute

type session struct {
	run    *run
	cancel context.CancelFunc
	ended  time.Time
}

var (
	sessionsMu sync.Mutex
	sessions   = map[string]*session{}
)

// Start begins a run in the background and returns its id. One run at a
// time: two would measure each other's traffic.
func Start(request Request) (string, error) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	for id, existing := range sessions {
		if existing.ended.IsZero() {
			return "", errors.New("a network report is already running")
		}
		if time.Since(existing.ended) > keepFinished {
			delete(sessions, id)
		}
	}
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	id := hex.EncodeToString(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	current := &session{run: &run{}, cancel: cancel}
	sessions[id] = current
	go func() {
		err := current.run.execute(ctx, request)
		cancel()
		current.run.mu.Lock()
		current.run.finished = true
		if err != nil {
			current.run.err = err.Error()
		}
		current.run.mu.Unlock()
		sessionsMu.Lock()
		current.ended = time.Now()
		sessionsMu.Unlock()
	}()
	return id, nil
}

func State(id string) (Snapshot, error) {
	sessionsMu.Lock()
	current, ok := sessions[id]
	sessionsMu.Unlock()
	if !ok {
		return Snapshot{}, errors.New("no such network report")
	}
	return current.run.snapshot()
}

// Cancel stops a run; its snapshot keeps what finished.
func Cancel(id string) error {
	sessionsMu.Lock()
	current, ok := sessions[id]
	sessionsMu.Unlock()
	if !ok {
		return errors.New("no such network report")
	}
	current.cancel()
	return nil
}
