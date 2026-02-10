package cache

import (
	"context"
	"errors"
	"time"

	vulners "github.com/kidoz/go-vulners"
)

// ErrOfflineDataMissing is returned when offline data is not cached.
var ErrOfflineDataMissing = errors.New("offline data not synced; run 'vulners offline sync' first")

// CollectionMeta holds metadata about a synced collection.
type CollectionMeta struct {
	Collection string    `json:"collection"`
	Count      int       `json:"count"`
	SyncedAt   time.Time `json:"syncedAt"`
}

// Store is the interface for the local cache.
type Store interface {
	GetBulletin(ctx context.Context, id string) (*vulners.Bulletin, error)
	PutBulletins(ctx context.Context, collection string, bulletins []vulners.Bulletin) error
	SearchBulletins(ctx context.Context, query string, limit, offset int) ([]vulners.Bulletin, int, error)
	GetCollectionMeta(ctx context.Context) ([]CollectionMeta, error)
	GetLastSyncTime(ctx context.Context, collection string) (time.Time, error)
	Purge(ctx context.Context) error
	Close() error
}

// ErrCacheUnavailable is returned by NopStore for write operations.
var ErrCacheUnavailable = errors.New("cache unavailable")

// NopStore is a no-op Store returned when the cache database cannot be opened.
// Read operations return ErrOfflineDataMissing; write operations return ErrCacheUnavailable.
type NopStore struct{}

// NewNopStore returns a NopStore.
func NewNopStore() *NopStore { return &NopStore{} }

func (*NopStore) GetBulletin(context.Context, string) (*vulners.Bulletin, error) {
	return nil, ErrOfflineDataMissing
}

func (*NopStore) PutBulletins(context.Context, string, []vulners.Bulletin) error {
	return ErrCacheUnavailable
}

func (*NopStore) SearchBulletins(context.Context, string, int, int) ([]vulners.Bulletin, int, error) {
	return nil, 0, ErrOfflineDataMissing
}

func (*NopStore) GetCollectionMeta(context.Context) ([]CollectionMeta, error) {
	return nil, ErrOfflineDataMissing
}

func (*NopStore) GetLastSyncTime(context.Context, string) (time.Time, error) {
	return time.Time{}, ErrOfflineDataMissing
}

func (*NopStore) Purge(context.Context) error { return ErrCacheUnavailable }

func (*NopStore) Close() error { return nil }
