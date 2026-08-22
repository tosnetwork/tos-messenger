// Package attachmentadmission owns the recipient-side boundary from an
// authenticated encrypted-attachment Event to content an Agent may consume.
// Fetch capability keys and unaudited plaintext never cross the local runtime
// API: this package fetches, authenticates, decrypts and scans first.
package attachmentadmission

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tosnetwork/tos-messenger/pkg/attachmentapi"
	"github.com/tosnetwork/tos-messenger/pkg/attachments"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
)

// CallerFactory resolves only the already validated HTTPS locator. Tests may
// substitute an in-process authenticated store without weakening production.
type CallerFactory func(locator, manifestDigest string) (attachmentapi.Caller, func(), error)

type Config struct {
	OpenPolicy    attachments.Policy
	ContentPolicy attachments.AgentContentPolicy
	HTTPS         attachmentapi.HTTPSConfig
	CallerFactory CallerFactory
	Now           func() time.Time
	RNG           io.Reader
}

type Admitter struct {
	config Config
}

type Result struct {
	Body     string
	Metadata attachments.Metadata
	Report   attachments.AdmissionReport
}

func New(config Config) (*Admitter, error) {
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.RNG == nil {
		config.RNG = rand.Reader
	}
	if config.CallerFactory == nil {
		httpsConfig := config.HTTPS
		config.CallerFactory = func(locator, manifestDigest string) (attachmentapi.Caller, func(), error) {
			client, err := attachmentapi.NewHTTPSClient(locator, manifestDigest, httpsConfig)
			if err != nil {
				return nil, nil, err
			}
			return client, client.CloseIdleConnections, nil
		}
	}
	if config.OpenPolicy.MaxPlaintextBytes == 0 || config.ContentPolicy.MaxPlaintextBytes == 0 ||
		config.OpenPolicy.MaxPlaintextBytes != config.ContentPolicy.MaxPlaintextBytes ||
		config.OpenPolicy.MaxPlaintextBytes > envelope.MaxContentBytes {
		return nil, errors.New("attachment admission needs one explicit matching plaintext bound")
	}
	if _, allowed := config.OpenPolicy.AllowedMediaTypes["text/plain"]; !allowed {
		return nil, errors.New("OpenFox attachment admission requires text/plain in the open policy")
	}
	if _, allowed := config.ContentPolicy.AllowedMediaTypes["text/plain"]; !allowed {
		return nil, errors.New("OpenFox attachment admission requires text/plain in the content policy")
	}
	if err := attachments.ValidateAgentContentPolicy(config.ContentPolicy); err != nil {
		return nil, err
	}
	for path, expected := range map[string]string{
		"/usr/bin/bwrap":   config.ContentPolicy.BubblewrapDigest,
		"/usr/bin/prlimit": config.ContentPolicy.PrlimitDigest,
	} {
		actual, err := attachments.ExecutableDigest(path)
		if err != nil || actual != expected {
			return nil, errors.New("attachment admission launcher does not match its configured digest")
		}
	}
	if config.ContentPolicy.Cgroup != nil {
		actual, err := attachments.ExecutableDigest("/usr/bin/systemd-run")
		if err != nil || actual != config.ContentPolicy.Cgroup.SystemdRunDigest {
			return nil, errors.New("attachment admission cgroup launcher does not match its configured digest")
		}
	}
	for _, scanner := range config.ContentPolicy.Scanners {
		actual, err := attachments.ExecutableDigest(scanner.Executable)
		if err != nil || actual != scanner.ExecutableDigest {
			return nil, errors.New("attachment admission scanner does not match its configured digest")
		}
		for _, resource := range scanner.Resources {
			actual, err := attachments.ScannerResourceDigest(resource.Path, resource.Executable)
			if err != nil || actual != resource.Digest {
				return nil, errors.New("attachment admission scanner resource does not match its configured digest")
			}
		}
	}
	config.OpenPolicy.AllowedMediaTypes = cloneMediaTypes(config.OpenPolicy.AllowedMediaTypes)
	config.ContentPolicy.AllowedMediaTypes = cloneMediaTypes(config.ContentPolicy.AllowedMediaTypes)
	config.ContentPolicy.Scanners = append([]attachments.ScannerSpec(nil), config.ContentPolicy.Scanners...)
	if config.ContentPolicy.Cgroup != nil {
		cgroup := *config.ContentPolicy.Cgroup
		config.ContentPolicy.Cgroup = &cgroup
	}
	for index := range config.ContentPolicy.Scanners {
		config.ContentPolicy.Scanners[index].Args = append([]string(nil), config.ContentPolicy.Scanners[index].Args...)
		config.ContentPolicy.Scanners[index].Resources = append([]attachments.ScannerResource(nil),
			config.ContentPolicy.Scanners[index].Resources...)
	}
	return &Admitter{config: config}, nil
}

func cloneMediaTypes(source map[string]struct{}) map[string]struct{} {
	cloned := make(map[string]struct{}, len(source))
	for mediaType := range source {
		cloned[mediaType] = struct{}{}
	}
	return cloned
}

// Admit consumes only the current v3 profile. Historical v1/v2 Events remain
// readable history, but cannot be fetched because they carry no recipient
// capability; treating a locator as authority would be a security downgrade.
func (a *Admitter) Admit(ctx context.Context, event envelope.Event) (result Result, err error) {
	if a == nil || ctx == nil {
		return Result{}, errors.New("invalid attachment admission request")
	}
	if err := envelope.ValidateEvent(event); err != nil || event.Kind != "artifact.encrypted" ||
		event.PayloadSchema != (payload.EncryptedAttachment{}).Schema() {
		return Result{}, errors.New("attachment admission requires one canonical current encrypted Event")
	}
	decoded, err := payload.DecodeSchema(event.Kind, event.PayloadSchema, event.Content)
	if err != nil {
		return Result{}, err
	}
	attachment, ok := decoded.(payload.EncryptedAttachment)
	if !ok {
		return Result{}, errors.New("encrypted attachment payload has another type")
	}
	reference, err := attachments.DecodeReferenceJSON(attachment.ReferenceJSON)
	if err != nil {
		return Result{}, err
	}
	grant, capabilityKey, err := attachment.FetchAccess()
	if err != nil {
		return Result{}, err
	}
	defer clear(capabilityKey)
	caller, closeCaller, err := a.config.CallerFactory(attachment.Locator, attachment.ManifestDigest)
	if err != nil {
		return Result{}, err
	}
	if closeCaller != nil {
		defer closeCaller()
	}
	client, err := attachmentapi.NewGrantClient(caller, grant, capabilityKey, a.config.Now, a.config.RNG)
	if err != nil {
		return Result{}, err
	}
	chunks, err := client.Fetch(ctx, reference.Manifest.ChunkDigests)
	if err != nil {
		return Result{}, err
	}
	admitted, err := attachments.OpenForAgent(ctx, reference, chunks, a.config.OpenPolicy,
		a.config.ContentPolicy, a.config.Now())
	if err != nil {
		return Result{}, err
	}
	defer clear(admitted.Plaintext)
	if admitted.Metadata.MediaType != "text/plain" || !utf8.Valid(admitted.Plaintext) || len(admitted.Plaintext) == 0 ||
		strings.ContainsRune(string(admitted.Plaintext), '\x00') {
		return Result{}, errors.New("admitted attachment is not bounded UTF-8 text/plain")
	}
	return Result{Body: string(admitted.Plaintext), Metadata: admitted.Metadata, Report: admitted.Report}, nil
}
