// Package evidence creates and verifies self-contained M0 review bundles.
// A bundle preserves artifacts and their hashes; it does not turn a local run
// into independent review or multi-operator evidence.
package evidence

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

const (
	Schema                 = "tos.messaging.m0-evidence-bundle.v1"
	MaxArtifacts           = 512
	MaxArtifactBytes int64 = 512 << 20
	MaxBundleBytes   int64 = 1 << 30
)

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Manifest struct {
	Schema    string     `json:"schema"`
	Commit    string     `json:"commit"`
	Toolchain string     `json:"toolchain"`
	Artifacts []Artifact `json:"artifacts"`
}

// Pack writes a deterministic ZIP whose manifest commits every input byte.
func Pack(root, output, commit, toolchain string) (Manifest, error) {
	if !filepath.IsAbs(root) || !filepath.IsAbs(output) || filepath.Clean(root) != root || filepath.Clean(output) != output {
		return Manifest{}, errors.New("evidence paths must be clean and absolute")
	}
	if !commitPattern.MatchString(commit) || toolchain == "" || len(toolchain) > 256 || strings.TrimSpace(toolchain) != toolchain {
		return Manifest{}, errors.New("invalid evidence build identity")
	}
	if relative, err := filepath.Rel(root, output); err != nil || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		return Manifest{}, errors.New("evidence output must be outside its input tree")
	}
	if _, err := os.Lstat(output); err == nil {
		return Manifest{}, errors.New("evidence output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, err
	}
	files, manifest, err := collect(root, commit, toolchain)
	if err != nil {
		return Manifest{}, err
	}
	if err := validateRequired(manifest); err != nil {
		return Manifest{}, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(output), ".m0-evidence-")
	if err != nil {
		return Manifest{}, err
	}
	name := temporary.Name()
	defer os.Remove(name)
	archive := zip.NewWriter(temporary)
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		_ = archive.Close()
		_ = temporary.Close()
		return Manifest{}, err
	}
	manifestRaw = append(manifestRaw, '\n')
	if err := addZip(archive, "manifest.json", manifestRaw); err != nil {
		_ = archive.Close()
		_ = temporary.Close()
		return Manifest{}, err
	}
	for index, artifact := range manifest.Artifacts {
		raw, err := os.ReadFile(files[index])
		if err != nil {
			_ = archive.Close()
			_ = temporary.Close()
			return Manifest{}, err
		}
		if err := addZip(archive, artifact.Path, raw); err != nil {
			_ = archive.Close()
			_ = temporary.Close()
			return Manifest{}, err
		}
	}
	if err := archive.Close(); err != nil {
		_ = temporary.Close()
		return Manifest{}, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return Manifest{}, err
	}
	if err := temporary.Close(); err != nil {
		return Manifest{}, err
	}
	if err := os.Rename(name, output); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// Verify reads every artifact, checks the manifest, and returns it only after
// the archive proves complete and byte-exact.
func Verify(path string) (Manifest, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Manifest{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > MaxBundleBytes {
		return Manifest{}, errors.New("invalid evidence bundle file")
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		return Manifest{}, err
	}
	defer reader.Close()
	if len(reader.File) < 2 || len(reader.File) > MaxArtifacts+1 {
		return Manifest{}, errors.New("invalid evidence bundle entry count")
	}
	entries := make(map[string]*zip.File, len(reader.File))
	for _, file := range reader.File {
		if !validPath(file.Name) || file.FileInfo().IsDir() {
			return Manifest{}, errors.New("invalid evidence bundle path")
		}
		if _, duplicate := entries[file.Name]; duplicate {
			return Manifest{}, errors.New("duplicate evidence bundle path")
		}
		entries[file.Name] = file
	}
	manifestFile, found := entries["manifest.json"]
	if !found {
		return Manifest{}, errors.New("evidence bundle has no manifest")
	}
	manifestRaw, err := readZip(manifestFile, 1<<20)
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(manifestRaw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("evidence manifest has trailing JSON")
	}
	if err := validateRequired(manifest); err != nil {
		return Manifest{}, err
	}
	if len(entries) != len(manifest.Artifacts)+1 {
		return Manifest{}, errors.New("evidence bundle contains uncommitted files")
	}
	artifactByPath := make(map[string]Artifact, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		artifactByPath[artifact.Path] = artifact
	}
	for _, artifact := range manifest.Artifacts {
		file, found := entries[artifact.Path]
		if !found {
			return Manifest{}, errors.New("evidence artifact is missing")
		}
		raw, err := readZip(file, MaxArtifactBytes)
		if err != nil {
			return Manifest{}, err
		}
		sum := sha256.Sum256(raw)
		if artifact.Size != int64(len(raw)) || artifact.SHA256 != hex.EncodeToString(sum[:]) {
			return Manifest{}, errors.New("evidence artifact digest mismatch")
		}
		if strings.HasPrefix(artifact.Path, "collectors/") && strings.HasSuffix(artifact.Path, ".json") {
			collector, err := reachability.DecodeManifestJSON(raw)
			if err != nil {
				return Manifest{}, errors.New("invalid collector manifest in evidence bundle")
			}
			binary, found := artifactByPath[strings.TrimSuffix(artifact.Path, ".json")+".binary"]
			if !found || binary.SHA256 != collector.BinarySHA256 {
				return Manifest{}, errors.New("collector manifest does not match its bundled binary")
			}
		}
	}
	return manifest, nil
}

func collect(root, commit, toolchain string) ([]string, Manifest, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("evidence input contains a non-regular file")
		}
		if !validPath(relative) || info.Size() > MaxArtifactBytes {
			return errors.New("invalid evidence artifact")
		}
		paths = append(paths, path)
		if len(paths) > MaxArtifacts {
			return errors.New("too many evidence artifacts")
		}
		return nil
	})
	if err != nil {
		return nil, Manifest{}, err
	}
	sort.Slice(paths, func(i, j int) bool {
		first, _ := filepath.Rel(root, paths[i])
		second, _ := filepath.Rel(root, paths[j])
		return filepath.ToSlash(first) < filepath.ToSlash(second)
	})
	manifest := Manifest{Schema: Schema, Commit: commit, Toolchain: toolchain}
	collectorClaims := make(map[string]string)
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, Manifest{}, err
		}
		relative, _ := filepath.Rel(root, path)
		relativeSlash := filepath.ToSlash(relative)
		if strings.HasPrefix(relativeSlash, "collectors/") && strings.HasSuffix(relativeSlash, ".json") {
			collector, err := reachability.DecodeManifestJSON(raw)
			if err != nil {
				return nil, Manifest{}, errors.New("invalid collector manifest in evidence input")
			}
			collectorClaims[strings.TrimSuffix(relativeSlash, ".json")+".binary"] = collector.BinarySHA256
		}
		sum := sha256.Sum256(raw)
		manifest.Artifacts = append(manifest.Artifacts, Artifact{Path: filepath.ToSlash(relative), SHA256: hex.EncodeToString(sum[:]), Size: int64(len(raw))})
	}
	artifactByPath := make(map[string]Artifact, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		artifactByPath[artifact.Path] = artifact
	}
	for binaryPath, claimed := range collectorClaims {
		binary, found := artifactByPath[binaryPath]
		if !found || binary.SHA256 != claimed {
			return nil, Manifest{}, errors.New("collector manifest does not match its input binary")
		}
	}
	return paths, manifest, nil
}

func validateRequired(manifest Manifest) error {
	if manifest.Schema != Schema || !commitPattern.MatchString(manifest.Commit) || manifest.Toolchain == "" || len(manifest.Artifacts) == 0 || len(manifest.Artifacts) > MaxArtifacts {
		return errors.New("invalid evidence manifest")
	}
	seen := map[string]bool{}
	var totalSize int64
	required := map[string]bool{"verify.log": false, "build/linux-amd64.log": false, "build/linux-arm64.log": false, "vectors/objects.json": false, "vectors/adversarial.json": false, "vectors/e2ee.json": false}
	binaryTargets := map[string]bool{"bin/linux-amd64/": false, "bin/linux-arm64/": false}
	collectors := 0
	for index, artifact := range manifest.Artifacts {
		if !validPath(artifact.Path) || artifact.Size < 0 || len(artifact.SHA256) != 64 {
			return errors.New("invalid evidence artifact manifest")
		}
		if _, err := hex.DecodeString(artifact.SHA256); err != nil {
			return errors.New("invalid evidence artifact digest")
		}
		if artifact.Size > MaxBundleBytes-totalSize {
			return errors.New("evidence artifact total exceeds bound")
		}
		totalSize += artifact.Size
		if index > 0 && manifest.Artifacts[index-1].Path >= artifact.Path {
			return errors.New("evidence artifacts are not strictly sorted")
		}
		if seen[artifact.Path] {
			return errors.New("duplicate evidence artifact")
		}
		seen[artifact.Path] = true
		if _, ok := required[artifact.Path]; ok {
			required[artifact.Path] = true
		}
		for prefix := range binaryTargets {
			if strings.HasPrefix(artifact.Path, prefix) {
				binaryTargets[prefix] = true
			}
		}
		if strings.HasPrefix(artifact.Path, "collectors/") && strings.HasSuffix(artifact.Path, ".json") {
			collectors++
		}
	}
	for name, present := range required {
		if !present {
			return errors.New("evidence bundle is missing " + name)
		}
	}
	for target, present := range binaryTargets {
		if !present {
			return errors.New("evidence bundle is missing " + target)
		}
	}
	if collectors == 0 {
		return errors.New("evidence bundle has no collector manifest")
	}
	for path := range seen {
		if strings.HasPrefix(path, "collectors/") && strings.HasSuffix(path, ".json") && !seen[strings.TrimSuffix(path, ".json")+".binary"] {
			return errors.New("collector manifest has no bundled binary")
		}
	}
	return nil
}

func validPath(path string) bool {
	return path != "" && path == filepath.ToSlash(filepath.Clean(path)) && path != "." && !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "../") && !strings.Contains(path, "\\")
}
func addZip(writer *zip.Writer, name string, raw []byte) error {
	header := &zip.FileHeader{Name: name, Method: zip.Store}
	header.SetMode(0o600)
	file, err := writer.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = file.Write(raw)
	return err
}
func readZip(file *zip.File, maximum int64) ([]byte, error) {
	if int64(file.UncompressedSize64) > maximum {
		return nil, errors.New("evidence artifact exceeds bound")
	}
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maximum {
		return nil, errors.New("evidence artifact exceeds bound")
	}
	return raw, nil
}
