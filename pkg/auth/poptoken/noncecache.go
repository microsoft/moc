package poptoken

import (
	"sync"
	"time"
)

const (
	DefaultNonceCacheSize     = 20
	DefaultNonceValidInterval = time.Minute * 5
)

type NonceCacheInterface interface {
	IsNonceExists(nonceId string, now time.Time) bool
}

type Nonce struct {
	Id              string
	CreatedDateTime time.Time
}

// Implement a simple LRU cache that evicts older nonce entries.
type nonceCache struct {
	cache              map[string]*Nonce
	queue              []*Nonce
	nonceValidInterval time.Duration
	size               int
	maxSize            int
	mutex              sync.Mutex
}

func (n *nonceCache) append(nonce *Nonce) {
	n.cache[nonce.Id] = nonce
	n.queue = append(n.queue, nonce)
	n.size++
	return

}

// keep trimming the cache until all expired entries are purged or we are within the cache size
func (n *nonceCache) trim(now time.Time) {
	isDelete := true

	for isDelete {
		if len(n.queue) == 0 {
			break
		}

		nonce := n.queue[0]
		isDelete = nonce.CreatedDateTime.Add(n.nonceValidInterval).Before(now)

		if !isDelete {
			isDelete = n.size >= n.maxSize
		}
		if isDelete {
			delete(n.cache, nonce.Id)
			n.queue = n.queue[1:]
			n.size--
		}
	}
}

func (n *nonceCache) IsNonceExists(nonceId string, now time.Time) bool {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	existNonce, ok := n.cache[nonceId]
	// entries are evicted lazily, so if entry has expired, return false even though the entry
	// is still in the cache.
	if ok {
		return existNonce.CreatedDateTime.Add(n.nonceValidInterval).After(now)
	}

	nonce := &Nonce{
		Id:              nonceId,
		CreatedDateTime: now,
	}
	n.append(nonce)
	n.trim(now)

	return false

}

func (n *nonceCache) GetCacheSize() int {
	return n.size
}

func NewNonceCache(maxSize int, nonceValidPeriod time.Duration) (*nonceCache, error) {
	return &nonceCache{
		cache:              make(map[string]*Nonce),
		nonceValidInterval: nonceValidPeriod,
		size:               0,
		maxSize:            maxSize,
	}, nil
}
