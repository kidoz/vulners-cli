package cache

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	vulners "github.com/kidoz/go-vulners"
	_ "modernc.org/sqlite"
)

// SQLiteStore implements Store using a SQLite database.
type SQLiteStore struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewSQLiteStore opens or creates a SQLite cache at the given path.
func NewSQLiteStore(dbPath string, logger *slog.Logger) (*SQLiteStore, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("creating cache directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("opening cache database: %w", err)
	}

	db.SetMaxOpenConns(1)

	s := &SQLiteStore{db: db, logger: logger}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrating cache database: %w", err)
	}

	if err := os.Chmod(dbPath, 0o600); err != nil {
		logger.Warn("could not set cache file permissions", "path", dbPath, "error", err)
	}

	return s, nil
}

func (s *SQLiteStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS bulletins (
			id         TEXT PRIMARY KEY,
			collection TEXT NOT NULL,
			data       TEXT NOT NULL,
			title      TEXT NOT NULL DEFAULT '',
			synced_at  TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_bulletins_collection ON bulletins(collection);
		CREATE INDEX IF NOT EXISTS idx_bulletins_title ON bulletins(title);

		CREATE TABLE IF NOT EXISTS collection_meta (
			collection TEXT PRIMARY KEY,
			count      INTEGER NOT NULL DEFAULT 0,
			synced_at  TEXT NOT NULL
		);
	`)
	return err
}

func (s *SQLiteStore) GetBulletin(ctx context.Context, id string) (*vulners.Bulletin, error) {
	var data string
	err := s.db.QueryRowContext(ctx, "SELECT data FROM bulletins WHERE id = ?", id).Scan(&data)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrOfflineDataMissing
		}
		return nil, fmt.Errorf("querying bulletin %s: %w", id, err)
	}

	var b vulners.Bulletin
	if err := json.Unmarshal([]byte(data), &b); err != nil {
		return nil, fmt.Errorf("unmarshaling bulletin %s: %w", id, err)
	}

	return &b, nil
}

func (s *SQLiteStore) PutBulletins(ctx context.Context, collection string, bulletins []vulners.Bulletin) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.PrepareContext(ctx,
		"INSERT OR REPLACE INTO bulletins (id, collection, data, title, synced_at) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		return fmt.Errorf("preparing insert: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	now := time.Now().UTC().Format(time.RFC3339)
	for _, b := range bulletins {
		data, err := json.Marshal(b)
		if err != nil {
			s.logger.Warn("skipping bulletin, marshal error", "id", b.ID, "error", err)
			continue
		}
		if _, err := stmt.ExecContext(ctx, b.ID, collection, string(data), b.Title, now); err != nil {
			return fmt.Errorf("inserting bulletin %s: %w", b.ID, err)
		}
	}

	// Update collection metadata with the actual row count for this collection.
	var actualCount int
	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM bulletins WHERE collection = ?", collection).Scan(&actualCount); err != nil {
		return fmt.Errorf("counting bulletins: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO collection_meta (collection, count, synced_at) VALUES (?, ?, ?)
		ON CONFLICT(collection) DO UPDATE SET
			count = excluded.count,
			synced_at = excluded.synced_at`,
		collection, actualCount, now); err != nil {
		return fmt.Errorf("updating collection meta: %w", err)
	}

	return tx.Commit()
}

func (s *SQLiteStore) SearchBulletins(ctx context.Context, query string, limit, offset int) ([]vulners.Bulletin, int, error) {
	// Escape LIKE meta-characters so user input is treated literally.
	escaped := query
	escaped = strings.ReplaceAll(escaped, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `%`, `\%`)
	escaped = strings.ReplaceAll(escaped, `_`, `\_`)
	pattern := "%" + escaped + "%"

	var total int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM bulletins WHERE id LIKE ? ESCAPE '\' OR title LIKE ? ESCAPE '\'`,
		pattern, pattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("counting search results: %w", err)
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT data FROM bulletins WHERE id LIKE ? ESCAPE '\' OR title LIKE ? ESCAPE '\' ORDER BY id LIMIT ? OFFSET ?`,
		pattern, pattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("searching bulletins: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var results []vulners.Bulletin
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, 0, fmt.Errorf("scanning result: %w", err)
		}
		var b vulners.Bulletin
		if err := json.Unmarshal([]byte(data), &b); err != nil {
			s.logger.Warn("skipping corrupted bulletin", "error", err)
			continue
		}
		results = append(results, b)
	}

	return results, total, rows.Err()
}

func (s *SQLiteStore) GetCollectionMeta(ctx context.Context) ([]CollectionMeta, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT collection, count, synced_at FROM collection_meta ORDER BY collection")
	if err != nil {
		return nil, fmt.Errorf("querying collection meta: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var metas []CollectionMeta
	for rows.Next() {
		var m CollectionMeta
		var syncedAt string
		if err := rows.Scan(&m.Collection, &m.Count, &syncedAt); err != nil {
			return nil, fmt.Errorf("scanning collection meta: %w", err)
		}
		var parseErr error
		m.SyncedAt, parseErr = time.Parse(time.RFC3339, syncedAt)
		if parseErr != nil {
			s.logger.Warn("corrupt synced_at timestamp", "collection", m.Collection, "raw", syncedAt)
		}
		metas = append(metas, m)
	}

	return metas, rows.Err()
}

func (s *SQLiteStore) GetLastSyncTime(ctx context.Context, collection string) (time.Time, error) {
	var syncedAt string
	err := s.db.QueryRowContext(ctx,
		"SELECT synced_at FROM collection_meta WHERE collection = ?", collection).Scan(&syncedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, nil
		}
		return time.Time{}, fmt.Errorf("querying last sync time for %s: %w", collection, err)
	}
	t, parseErr := time.Parse(time.RFC3339, syncedAt)
	if parseErr != nil {
		s.logger.Warn("corrupt synced_at timestamp", "collection", collection, "raw", syncedAt)
	}
	return t, nil
}

func (s *SQLiteStore) Purge(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning purge transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(ctx, "DELETE FROM bulletins"); err != nil {
		return fmt.Errorf("purging bulletins: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM collection_meta"); err != nil {
		return fmt.Errorf("purging collection meta: %w", err)
	}
	return tx.Commit()
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
