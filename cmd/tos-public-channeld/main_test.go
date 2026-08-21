package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSitesPublisherConfigurationIsAllOrNothing(t *testing.T) {
	if publisher, err := sitesPublisher(options{}); err != nil || publisher != nil {
		t.Fatalf("empty Sites publisher=%#v err=%v", publisher, err)
	}
	if _, err := sitesPublisher(options{sitesState: filepath.Join(t.TempDir(), "sites")}); err == nil {
		t.Fatal("accepted partial Sites publisher configuration")
	}
	root := t.TempDir()
	command := filepath.Join(root, "storage-cli")
	private := filepath.Join(root, "client.key")
	public := filepath.Join(root, "server.pub")
	if err := os.WriteFile(command, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(private, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(public, []byte("public"), 0o600); err != nil {
		t.Fatal(err)
	}
	configured := options{sitesState: filepath.Join(root, "sites"), storageCLI: command,
		storageAddr: "127.0.0.1:5555", storageKey: private, storagePub: public}
	publisher, err := sitesPublisher(configured)
	if err != nil || publisher == nil || publisher.Command != command {
		t.Fatalf("configured Sites publisher=%#v err=%v", publisher, err)
	}
	if err := os.Chmod(private, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := sitesPublisher(configured); err == nil {
		t.Fatal("accepted group-readable storage client key")
	}
}

func TestSitesDownloaderConfigurationIsIndependentAndAllOrNothing(t *testing.T) {
	if downloader, err := sitesDownloader(options{}); err != nil || downloader != nil {
		t.Fatalf("empty Sites downloader=%#v err=%v", downloader, err)
	}
	if _, err := sitesPublisher(options{storageAddr: "127.0.0.1:5555"}); err == nil {
		t.Fatal("accepted unused partial storage credentials")
	}
	if _, err := sitesDownloader(options{sitesCatchUp: filepath.Join(t.TempDir(), "catchup")}); err == nil {
		t.Fatal("accepted partial Sites downloader configuration")
	}
	root := t.TempDir()
	command := filepath.Join(root, "storage-cli")
	private := filepath.Join(root, "client.key")
	public := filepath.Join(root, "server.pub")
	for path, mode := range map[string]os.FileMode{command: 0o700, private: 0o600, public: 0o600} {
		if err := os.WriteFile(path, []byte("fixture"), mode); err != nil {
			t.Fatal(err)
		}
	}
	configured := options{sitesCatchUp: filepath.Join(root, "catchup"), storageCLI: command,
		storageAddr: "127.0.0.1:5555", storageKey: private, storagePub: public}
	downloader, err := sitesDownloader(configured)
	if err != nil || downloader == nil || downloader.Command != command {
		t.Fatalf("configured Sites downloader=%#v err=%v", downloader, err)
	}
	if publisher, err := sitesPublisher(configured); err != nil || publisher != nil {
		t.Fatalf("download-only configuration unexpectedly enabled publication=%#v err=%v", publisher, err)
	}
	configured.sitesState = filepath.Join(root, "publish")
	if publisher, err := sitesPublisher(configured); err != nil || publisher == nil {
		t.Fatalf("combined configuration publication=%#v err=%v", publisher, err)
	}
}
