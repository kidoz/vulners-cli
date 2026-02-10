package cmd

import (
	"context"
	"time"

	vulners "github.com/kidoz/go-vulners"
	"github.com/kidoz/vulners-cli/internal/cache"
)

// mockStore implements cache.Store with configurable function fields.
type mockStore struct {
	getBulletinFn       func(ctx context.Context, id string) (*vulners.Bulletin, error)
	putBulletinsFn      func(ctx context.Context, collection string, bulletins []vulners.Bulletin) error
	searchBulletinsFn   func(ctx context.Context, query string, limit, offset int) ([]vulners.Bulletin, int, error)
	getCollectionMetaFn func(ctx context.Context) ([]cache.CollectionMeta, error)
	getLastSyncTimeFn   func(ctx context.Context, collection string) (time.Time, error)
	purgeFn             func(ctx context.Context) error
}

func (m *mockStore) GetBulletin(ctx context.Context, id string) (*vulners.Bulletin, error) {
	if m.getBulletinFn != nil {
		return m.getBulletinFn(ctx, id)
	}
	return nil, cache.ErrOfflineDataMissing
}

func (m *mockStore) PutBulletins(ctx context.Context, collection string, bulletins []vulners.Bulletin) error {
	if m.putBulletinsFn != nil {
		return m.putBulletinsFn(ctx, collection, bulletins)
	}
	return nil
}

func (m *mockStore) SearchBulletins(ctx context.Context, query string, limit, offset int) ([]vulners.Bulletin, int, error) {
	if m.searchBulletinsFn != nil {
		return m.searchBulletinsFn(ctx, query, limit, offset)
	}
	return nil, 0, cache.ErrOfflineDataMissing
}

func (m *mockStore) GetCollectionMeta(ctx context.Context) ([]cache.CollectionMeta, error) {
	if m.getCollectionMetaFn != nil {
		return m.getCollectionMetaFn(ctx)
	}
	return nil, cache.ErrOfflineDataMissing
}

func (m *mockStore) GetLastSyncTime(ctx context.Context, collection string) (time.Time, error) {
	if m.getLastSyncTimeFn != nil {
		return m.getLastSyncTimeFn(ctx, collection)
	}
	return time.Time{}, cache.ErrOfflineDataMissing
}

func (m *mockStore) Purge(ctx context.Context) error {
	if m.purgeFn != nil {
		return m.purgeFn(ctx)
	}
	return nil
}

func (m *mockStore) Close() error { return nil }
