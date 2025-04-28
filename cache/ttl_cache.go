// Copyright (C) 2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cache

import (
	"sync"
	"time"
)

type TTLCacheItem[V any] struct {
	value     V
	timestamp time.Time
}

// Cache with per-key TTL tracking
type TTLCache[K comparable, V any] struct {
	data map[K]TTLCacheItem[V]
	ttl  time.Duration
	lock sync.Mutex
}

func NewTTLCache[K comparable, V any](ttl time.Duration) *TTLCache[K, V] {
	return &TTLCache[K, V]{
		data: make(map[K]TTLCacheItem[V]),
		ttl:  ttl,
	}
}

// GetValue checks if the cached value is fresh for a given key, otherwise fetches
// the value from the fetchFunc and caches it.
// If skipCache is true, the value will be fetched from the fetchFunc regardless of
// whether it is fresh or not and stored in the cache.
func (c *TTLCache[K, V]) Get(key K, fetchFunc func(K) (V, error), skipCache bool) (V, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if !skipCache {
		item, exists := c.data[key]
		if exists && time.Since(item.timestamp) < c.ttl {
			return item.value, nil
		}
	}

	newValue, err := fetchFunc(key)
	if err != nil {
		// Return a zero value of the type V in case of error
		return *new(V), err
	}

	c.data[key] = TTLCacheItem[V]{
		value:     newValue,
		timestamp: time.Now(),
	}

	return newValue, nil
}
