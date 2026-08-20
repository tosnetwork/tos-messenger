package securefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadBoundedRegular(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "input")
	if err := os.WriteFile(path, []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := ReadBoundedRegular(path, 5)
	if err != nil || string(raw) != "value" {
		t.Fatalf("raw=%q err=%v", raw, err)
	}
	for name, candidate := range map[string]string{
		"missing":   filepath.Join(root, "missing"),
		"directory": root,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadBoundedRegular(candidate, 5); err == nil {
				t.Fatal("accepted non-regular input")
			}
		})
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBoundedRegular(link, 5); err == nil {
		t.Fatal("followed symlink")
	}
	if _, err := ReadBoundedRegular(path, 4); err == nil {
		t.Fatal("accepted oversized input")
	}
}
