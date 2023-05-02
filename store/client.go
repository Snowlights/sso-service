package store

import (
	"context"
	"errors"
	"github.com/Snowlights/sso-service/common"
	"sync"
)

// NewClientStore create client store
func NewClientStore() *ClientStore {
	return &ClientStore{
		data: make(map[string]common.ClientInfo),
	}
}

// ClientStore client information store
type ClientStore struct {
	sync.RWMutex
	data map[string]common.ClientInfo
}

// GetByID according to the ID for the client information
func (cs *ClientStore) GetByID(ctx context.Context, id string) (common.ClientInfo, error) {
	cs.RLock()
	defer cs.RUnlock()

	if c, ok := cs.data[id]; ok {
		return c, nil
	}
	return nil, errors.New("not found")
}

// Set set client information
func (cs *ClientStore) Set(id string, cli common.ClientInfo) (err error) {
	cs.Lock()
	defer cs.Unlock()

	cs.data[id] = cli
	return
}
