package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/plexusone/omnivault/vault"
)

func TestProviderCRUD(t *testing.T) {
	db := openTestDB(t)
	provider, err := New(Config{
		DB:            db,
		EncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		AutoMigrate:   true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	secret := &vault.Secret{
		Value: "root:@tcp(127.0.0.1:13307)/omniroadmap",
		Fields: map[string]string{
			"username": "root",
			"database": "omniroadmap",
		},
	}
	if err := provider.Set(ctx, "analytics-sources/omniroadmap-local", secret); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := provider.Get(ctx, "analytics-sources/omniroadmap-local")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Value != secret.Value {
		t.Fatalf("Value = %q, want %q", got.Value, secret.Value)
	}
	if got.Fields["database"] != "omniroadmap" {
		t.Fatalf("database field = %q, want omniroadmap", got.Fields["database"])
	}
	exists, err := provider.Exists(ctx, "analytics-sources/omniroadmap-local")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !exists {
		t.Fatalf("Exists = false, want true")
	}
	paths, err := provider.List(ctx, "analytics-sources/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(paths) != 1 || paths[0] != "analytics-sources/omniroadmap-local" {
		t.Fatalf("List = %#v, want one analytics source path", paths)
	}
	if err := provider.Delete(ctx, "analytics-sources/omniroadmap-local"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	exists, err = provider.Exists(ctx, "analytics-sources/omniroadmap-local")
	if err != nil {
		t.Fatalf("Exists after delete: %v", err)
	}
	if exists {
		t.Fatalf("Exists after delete = true, want false")
	}
}

func TestProviderEncryptsStoredPayload(t *testing.T) {
	db := openTestDB(t)
	mem := db.Driver().(*testDriver).store
	provider, err := New(Config{
		DB:            db,
		EncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := provider.Set(context.Background(), "secret/path", &vault.Secret{Value: "plain-text-secret"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	mem.mu.Lock()
	row := mem.rows["secret/path"]
	mem.mu.Unlock()
	if strings.Contains(string(row.ciphertext), "plain-text-secret") {
		t.Fatalf("ciphertext contains plaintext secret")
	}
}

func TestProviderReadOnly(t *testing.T) {
	provider, err := New(Config{
		DB:            openTestDB(t),
		EncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
		ReadOnly:      true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := provider.Set(context.Background(), "path", &vault.Secret{Value: "value"}); !errors.Is(err, vault.ErrReadOnly) {
		t.Fatalf("Set error = %v, want ErrReadOnly", err)
	}
}

func TestProviderValidation(t *testing.T) {
	if _, err := New(Config{DB: openTestDB(t), Table: "bad-name", EncryptionKey: []byte("0123456789abcdef")}); err == nil {
		t.Fatalf("New accepted invalid table name")
	}
	if _, err := New(Config{DB: openTestDB(t), EncryptionKey: []byte("short")}); err == nil {
		t.Fatalf("New accepted invalid encryption key")
	}
}

type rowData struct {
	nonce      []byte
	ciphertext []byte
	keyID      string
}

type testStore struct {
	mu   sync.Mutex
	rows map[string]rowData
}

type testDriver struct {
	store *testStore
}

type testConn struct {
	store *testStore
}

type testResult int64

type testRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	store := &testStore{rows: map[string]rowData{}}
	name := "omnivault-sqlstore-test-" + strings.ReplaceAll(t.Name(), "/", "-") + "-" + testDriverSeq()
	sql.Register(name, &testDriver{store: store})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

var testDriverCounter atomic.Uint64

func testDriverSeq() string {
	return fmt.Sprintf("%d", testDriverCounter.Add(1))
}

func (d *testDriver) Open(string) (driver.Conn, error) {
	return &testConn{store: d.store}, nil
}

func (d *testDriver) Store() *testStore {
	return d.store
}

func (c *testConn) Prepare(query string) (driver.Stmt, error) {
	return nil, errors.New("prepare not implemented")
}

func (c *testConn) Close() error {
	return nil
}

func (c *testConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions not implemented")
}

func (c *testConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	lower := strings.ToLower(query)
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	switch {
	case strings.HasPrefix(lower, "create table"):
		return testResult(0), nil
	case strings.HasPrefix(lower, "insert into"):
		path := args[0].Value.(string)
		c.store.rows[path] = rowData{
			nonce:      append([]byte(nil), args[1].Value.([]byte)...),
			ciphertext: append([]byte(nil), args[2].Value.([]byte)...),
			keyID:      args[3].Value.(string),
		}
		return testResult(1), nil
	case strings.HasPrefix(lower, "delete from"):
		delete(c.store.rows, args[0].Value.(string))
		return testResult(1), nil
	default:
		return nil, errors.New("unsupported exec: " + query)
	}
}

func (c *testConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	lower := strings.ToLower(query)
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	switch {
	case strings.HasPrefix(lower, "select nonce"):
		path := args[0].Value.(string)
		row, ok := c.store.rows[path]
		if !ok {
			return &testRows{columns: []string{"nonce", "ciphertext", "key_id"}}, nil
		}
		return &testRows{
			columns: []string{"nonce", "ciphertext", "key_id"},
			values: [][]driver.Value{{
				append([]byte(nil), row.nonce...),
				append([]byte(nil), row.ciphertext...),
				row.keyID,
			}},
		}, nil
	case strings.HasPrefix(lower, "select count"):
		path := args[0].Value.(string)
		count := int64(0)
		if _, ok := c.store.rows[path]; ok {
			count = 1
		}
		return &testRows{columns: []string{"count"}, values: [][]driver.Value{{count}}}, nil
	case strings.HasPrefix(lower, "select path"):
		prefix := strings.TrimSuffix(args[0].Value.(string), "%")
		var values [][]driver.Value
		for path := range c.store.rows {
			if strings.HasPrefix(path, prefix) {
				values = append(values, []driver.Value{path})
			}
		}
		return &testRows{columns: []string{"path"}, values: values}, nil
	default:
		return nil, errors.New("unsupported query: " + query)
	}
}

func (r testResult) LastInsertId() (int64, error) {
	return 0, nil
}

func (r testResult) RowsAffected() (int64, error) {
	return int64(r), nil
}

func (r *testRows) Columns() []string {
	return r.columns
}

func (r *testRows) Close() error {
	return nil
}

func (r *testRows) Next(dest []driver.Value) error {
	if r.index >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.index])
	r.index++
	return nil
}

var (
	_ driver.Driver         = (*testDriver)(nil)
	_ driver.Conn           = (*testConn)(nil)
	_ driver.ExecerContext  = (*testConn)(nil)
	_ driver.QueryerContext = (*testConn)(nil)
)
