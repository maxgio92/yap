package symcache

import (
	"github.com/pkg/errors"
	"sync"
)

type addr uint64
type name string

type SymCache struct {
	syms map[addr]name
	lock sync.RWMutex
}

func NewSymCache() *SymCache {
	cache := new(SymCache)
	cache.syms = make(map[addr]name)

	return cache
}

func (s *SymCache) Set(sym string, ip uint64) {
	s.lock.Lock()
	s.syms[addr(ip)] = name(sym)
	s.lock.Unlock()
}

func (s *SymCache) Get(ip uint64) (string, error) {
	s.lock.RLock()
	sym, ok := s.syms[addr(ip)]
	if !ok {
		return "", errors.New("key does not exist")
	}
	s.lock.RUnlock()

	return string(sym), nil
}
