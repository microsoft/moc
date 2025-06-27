package poptoken

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	testNonceCacheSize      = 3
	testNonceValidInterval  = time.Minute * 1
	testNonceNowDateTimeStr = "2025-12-01T15:00:00Z"
)

func Test_NonceCacheIdExists(t *testing.T) {
	noncecache, err := NewNonceCache(testNonceCacheSize, testNonceValidInterval)
	assert.Nil(t, err)

	nonceId := "nonceId_1"
	now, _ := time.Parse(time.RFC3339, testNonceNowDateTimeStr)

	// first time seeing this nodeId, returning false
	isexist := noncecache.IsNonceExists(nonceId, now)
	assert.False(t, isexist)

	// the second time the nonceId should be cached.
	isexist = noncecache.IsNonceExists(nonceId, now)
	assert.True(t, isexist)

	// Validate a new entry will return false
	isexist = noncecache.IsNonceExists("nonceId_2", now)
	assert.False(t, isexist)
}

// expired entries are lazily evicted, so an invalid entry can remain in the cache
// validate that even the expired entry exists, we will still return false.
func Test_NonceCacheIdExistsButExpired(t *testing.T) {
	noncecache, err := NewNonceCache(testNonceCacheSize, testNonceValidInterval)
	assert.Nil(t, err)

	nonceId := "nonceId_1"
	now, _ := time.Parse(time.RFC3339, testNonceNowDateTimeStr)

	// first time seeing this nodeId, returning false
	isexist := noncecache.IsNonceExists(nonceId, now)
	assert.False(t, isexist)

	// the second time the nonceId should be cached.
	isexist = noncecache.IsNonceExists(nonceId, now)
	assert.True(t, isexist)
}

// Validate that expired Ids will be evicted upon the addition of a new entry.
func Test_NonceCacheEvictExpiredIds(t *testing.T) {
	noncecache, err := NewNonceCache(testNonceCacheSize, testNonceValidInterval)
	assert.Nil(t, err)

	now, _ := time.Parse(time.RFC3339, testNonceNowDateTimeStr)
	for i := 0; i < testNonceCacheSize-1; i++ {
		id := fmt.Sprintf("%d", i)
		now = now.Add(time.Second)
		noncecache.IsNonceExists(id, now)

		//need to call twice to confirm the nonceId were added, since the first time
		// it is added, it will not exist
		isexist := noncecache.IsNonceExists(id, now)
		assert.True(t, isexist)
	}

	// simulate querying a new nonce Id after time where the previously added ids expired.
	// adding the new entry will trigger an eviction of the expired entries
	newId := "new"
	now = now.Add(testNonceValidInterval * 2)
	noncecache.IsNonceExists(newId, now)

	// validate older entry has been evicted; size of cache should be 1
	// we check the size before checking if the older ids have been evicted as they will get
	// readded again.
	assert.Equal(t, 1, noncecache.GetCacheSize())

	// validate the ids no longer exists in cache
	for i := 0; i < testNonceCacheSize-1; i++ {
		id := fmt.Sprintf("%d", i)
		isexist := noncecache.IsNonceExists(id, now)
		assert.False(t, isexist)
	}

}

// Validate that the oldest Ids will be evicted upon the addition of a new entry that exceeds the cache size.
func Test_NonceCacheEvictOverflowIds(t *testing.T) {
	noncecache, err := NewNonceCache(testNonceCacheSize, testNonceValidInterval)
	assert.Nil(t, err)

	idsToAddCount := testNonceCacheSize + 2
	now, _ := time.Parse(time.RFC3339, testNonceNowDateTimeStr)
	for i := 0; i < idsToAddCount; i++ {
		id := fmt.Sprintf("%d", i)
		now = now.Add(time.Second)
		noncecache.IsNonceExists(id, now)

		//need to call twice to confirm the nonceId were added, since the first time
		// it is added, it will not exist
		isexist := noncecache.IsNonceExists(id, now)
		assert.True(t, isexist)

		// validate size of cache does not exceed the max even if more ids were added.
		assert.True(t, noncecache.GetCacheSize() <= testNonceCacheSize)
	}

	// when we add more ids than supported, the oldest ids get evicted.
	// verify the earlier ids should no longer exist. We need to check in reverse order
	// to avoid evicting the newer entries
	for i := idsToAddCount - 1; i >= 0; i-- {
		id := fmt.Sprintf("%d", i)
		now = now.Add(time.Second)

		isexist := noncecache.IsNonceExists(id, now)
		if i >= testNonceCacheSize {
			assert.True(t, isexist)
		} else {
			assert.False(t, isexist)
		}
	}

}
