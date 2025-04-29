// Copyright (C) 2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cache

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

type TTLCacheItem[V any] struct {
	value     V
	timestamp time.Time
}

// Cache with per-key TTL tracking and single-flight fetch
type TTLCache[K comparable, V any] struct {
	data    map[K]TTLCacheItem[V]
	ttl     time.Duration
	lock    sync.Mutex
	sfGroup singleflight.Group
}

func NewTTLCache[K comparable, V any](ttl time.Duration) *TTLCache[K, V] {
	return &TTLCache[K, V]{
		data: make(map[K]TTLCacheItem[V]),
		ttl:  ttl,
	}
}

// Get checks if the cached value is fresh for a given key, otherwise fetches
// the value using fetchFunc. Concurrent fetches for the same key are deduplicated.
// If skipCache is true, the value will be fetched regardless of cache state,
// but concurrent fetches for the same key during skipCache are still deduplicated.
func (c *TTLCache[K, V]) Get(key K, fetchFunc func(K) (V, error), skipCache bool) (V, error) {
	if !skipCache {
		c.lock.Lock()
		item, exists := c.data[key]
		if exists && time.Since(item.timestamp) < c.ttl {
			c.lock.Unlock()
			return item.value, nil
		}
		c.lock.Unlock()
	}

	keyStr := keyToString(key)

	v, err, _ := c.sfGroup.Do(keyStr, func() (interface{}, error) {
		newValue, fetchErr := fetchFunc(key)
		if fetchErr != nil {
			return *new(V), fetchErr
		}

		c.lock.Lock()
		c.data[key] = TTLCacheItem[V]{
			value:     newValue,
			timestamp: time.Now(),
		}
		c.lock.Unlock()

		return newValue, nil
	})

	if err != nil {
		return *new(V), err
	}

	return v.(V), nil
}

// keyToString is defined to allow for both fmt.Stringer and primitive string types.
func keyToString[K comparable](key K) string {
	if s, ok := any(key).(fmt.Stringer); ok {
		return s.String()
	}
	return fmt.Sprintf("%v", key)
}
