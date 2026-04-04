package postgres

import (
	"reflect"
	"testing"
	"testing/fstest"
)

func TestMigrationFilesSortsAndFiltersSQLFiles(t *testing.T) {
	t.Parallel()

	files, err := migrationFiles(fstest.MapFS{
		"0002_create_nodes.sql":  {Data: []byte("SELECT 1")},
		"0001_create_sites.sql":  {Data: []byte("SELECT 1")},
		"README.md":              {Data: []byte("ignore")},
		"nested/0003_create.sql": {Data: []byte("ignore nested")},
	})
	if err != nil {
		t.Fatalf("migrationFiles returned error: %v", err)
	}

	want := []string{"0001_create_sites.sql", "0002_create_nodes.sql"}
	if !reflect.DeepEqual(files, want) {
		t.Fatalf("files = %#v, want %#v", files, want)
	}
}
