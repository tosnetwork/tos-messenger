package daemon

import (
	"context"
	"crypto"
	"errors"
	"net"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/prekeyapi"
)

// prekeyRuntime owns only public generation state and the device contribution
// socket. Its optional publisher has a narrow signing capability, never
// private-key bytes or a device private-key store; the planner has neither.
type prekeyRuntime struct {
	server    *prekeyapi.Server
	listener  net.Listener
	planner   *prekeyPlanner
	publisher *directory.GenerationPublisher
	devices   *eventlog.DevicePrekeyLedger
	suite     e2ee.Suite
	signer    crypto.Signer
	deviceID  string
}

// configureLocalDevice enables this daemon's configured Device to contribute
// through the externally custodied Endpoint signer. Private X25519 material is
// written only to the daemon's private device ledger; the publication path
// receives the signed public bundle and nothing else.
func (r *prekeyRuntime) configureLocalDevice(deviceID string, signer crypto.Signer) error {
	if r == nil || r.planner == nil || r.devices == nil || signer == nil {
		return errors.New("local device prekeys are not configured")
	}
	r.deviceID = deviceID
	r.signer = signer
	if err := r.ensureLocalDevice(); err != nil {
		r.deviceID = ""
		r.signer = nil
		return err
	}
	return nil
}

func (r *prekeyRuntime) ensureLocalDevice() error {
	if r == nil || r.planner == nil || r.devices == nil || r.suite == nil || r.signer == nil || r.deviceID == "" {
		return errors.New("local device prekeys are not configured")
	}
	now := r.planner.now().Truncate(time.Second)
	collection, found, err := r.planner.contributions.CurrentPrekeyCollection(r.planner.delegation, now)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("no current prekey generation")
	}
	planned := false
	for _, deviceID := range collection.Plan.DeviceIDs {
		if deviceID == r.deviceID {
			planned = true
			break
		}
	}
	if !planned {
		return errors.New("configured device is absent from the prekey generation")
	}
	prekey, _, err := r.devices.EnsureDevicePrekey(
		r.planner.delegation, r.signer, r.suite, r.deviceID,
		eventlog.DevicePrekeyPlan{
			IssuedAt:        time.Unix(int64(collection.Plan.IssuedAtUnix), 0),
			ExpiresAt:       time.Unix(int64(collection.Plan.ExpiresAtUnix), 0),
			ReplenishBefore: r.planner.config.ReplenishBefore(),
		}, now,
	)
	if err != nil {
		return err
	}
	collection, _, err = r.planner.contributions.AddPrekeyContribution(r.planner.delegation, prekey.Bundle, now)
	if err != nil || !collection.Complete {
		return err
	}
	_, _, err = r.planner.contributions.FinalizePrekeyCollection(r.planner.delegation, r.planner.publications, now)
	return err
}

func (r *prekeyRuntime) maintainLocalDevice() error {
	if err := r.planner.Ensure(); err != nil {
		return err
	}
	if r.signer == nil {
		return nil
	}
	return r.ensureLocalDevice()
}

// localBootstrapMaterial returns the configured Device's exact current public
// bundle and a private copy for one suite transition. The caller must clear
// the returned private bytes. No API above daemon may expose this method.
func (r *prekeyRuntime) localBootstrapMaterial(now time.Time) (e2ee.Bundle, []byte, error) {
	if r == nil || r.planner == nil || r.devices == nil || r.signer == nil || r.deviceID == "" {
		return e2ee.Bundle{}, nil, errors.New("local device prekeys are not configured")
	}
	if now.IsZero() || now.Unix() < 0 {
		return e2ee.Bundle{}, nil, errors.New("invalid local prekey selection time")
	}
	collection, found, err := r.planner.contributions.CurrentPrekeyCollection(r.planner.delegation, now)
	if err != nil || !found {
		return e2ee.Bundle{}, nil, err
	}
	for _, bundle := range collection.Contributions {
		if bundle.DeviceID != r.deviceID {
			continue
		}
		digest, err := e2ee.BundleDigest(bundle)
		if err != nil {
			return e2ee.Bundle{}, nil, err
		}
		private, err := r.devices.DevicePrekeyPrivate(bundle.EndpointID, bundle.DeviceID, digest, now)
		if err != nil {
			return e2ee.Bundle{}, nil, err
		}
		return bundle, private, nil
	}
	return e2ee.Bundle{}, nil, errors.New("configured device has no current prekey contribution")
}

func (r *prekeyRuntime) runPlanner(ctx context.Context, failed func(error)) {
	ticker := time.NewTicker(r.planner.config.CheckInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.maintainLocalDevice(); err != nil && failed != nil {
				failed(err)
			}
		}
	}
}

func (r *prekeyRuntime) publishCurrent(ctx context.Context) error {
	if r == nil || r.publisher == nil {
		return nil
	}
	now := r.planner.now().Truncate(time.Second)
	publication, found, err := r.planner.publications.CurrentPrekeyPublication(r.planner.delegation.EndpointID)
	if err != nil || !found {
		return err
	}
	if now.Unix() < 0 || publication.ExpiresAt <= uint64(now.Unix()) {
		return nil
	}
	_, _, err = r.publisher.Publish(ctx, directory.PublicGeneration{
		SetDigest: publication.SetDigest, JSON: append([]byte(nil), publication.BundleSetJSON...),
		IssuedAt: publication.IssuedAt, ExpiresAt: publication.ExpiresAt,
	}, now)
	return err
}

func (r *prekeyRuntime) runPublisher(ctx context.Context, failed func(error)) {
	if err := r.publishCurrent(ctx); err != nil && failed != nil {
		failed(err)
	}
	ticker := time.NewTicker(r.publisher.PublishInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.publishCurrent(ctx); err != nil && failed != nil {
				failed(err)
			}
		}
	}
}

type prekeyPlanner struct {
	config        PublicationConfig
	delegation    identity.Delegation
	contributions *eventlog.PrekeyContributionLedger
	publications  *eventlog.PrekeyPublicationLedger
	now           func() time.Time
}

func newPrekeyRuntime(config Config, delegation identity.Delegation, journal *eventlog.Journal,
	now func() time.Time) (*prekeyRuntime, error) {
	if config.Publication.Mode == PublicationNone {
		return nil, nil
	}
	if now == nil {
		now = time.Now
	}
	contributions, err := journal.OpenPrekeyContributions()
	if err != nil {
		return nil, err
	}
	publications, err := journal.OpenPrekeyPublications()
	if err != nil {
		return nil, err
	}
	devices, err := journal.OpenDevicePrekeys()
	if err != nil {
		return nil, err
	}
	planner := &prekeyPlanner{
		config: config.Publication, delegation: delegation, contributions: contributions,
		publications: publications, now: now,
	}
	server, err := prekeyapi.NewServer(prekeyapi.Config{Delegation: delegation, Journal: journal, Now: now})
	if err != nil {
		return nil, err
	}
	if err := planner.Ensure(); err != nil {
		return nil, errors.New("plan public prekey generation: " + err.Error())
	}
	return &prekeyRuntime{
		server: server, planner: planner, devices: devices,
		suite: e2ee.NewDefaultSuite(), deviceID: config.DeviceID,
	}, nil
}

// Ensure repairs a complete-but-unfinalized generation and rotates only when
// no live contribution can be discarded. The public structural read is used
// solely to recognize expired state; live state is always reauthenticated.
func (p *prekeyPlanner) Ensure() error {
	if p == nil || p.contributions == nil || p.publications == nil || p.now == nil {
		return errors.New("no prekey generation planner")
	}
	now := p.now().Truncate(time.Second)
	if now.Unix() < 0 {
		return errors.New("invalid prekey planner time")
	}
	stored, found, err := p.contributions.StoredPrekeyCollection(p.delegation.EndpointID)
	if err != nil {
		return err
	}
	if !found || stored.Plan.ExpiresAtUnix <= uint64(now.Unix()) {
		return p.begin(now)
	}
	current, found, err := p.contributions.CurrentPrekeyCollection(p.delegation, now)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("prekey generation disappeared during planning")
	}
	if current.Complete && current.FinalizedSetDigest == "" {
		if _, _, err := p.contributions.FinalizePrekeyCollection(p.delegation, p.publications, now); err != nil {
			return err
		}
		current, _, err = p.contributions.CurrentPrekeyCollection(p.delegation, now)
		if err != nil {
			return err
		}
	}
	horizon := uint64(now.Add(p.config.ReplenishBefore()).Unix())
	if current.FinalizedSetDigest != "" && current.Plan.ExpiresAtUnix <= horizon {
		return p.begin(now)
	}
	return nil
}

func (p *prekeyPlanner) begin(now time.Time) error {
	issued := uint64(now.Unix())
	expires := uint64(now.Add(p.config.GenerationLifetime()).Unix())
	if expires > p.delegation.ExpiresAtUnix {
		expires = p.delegation.ExpiresAtUnix
	}
	if expires <= uint64(now.Add(p.config.ReplenishBefore()).Unix()) {
		return errors.New("delegation does not cover a useful prekey generation")
	}
	_, _, err := p.contributions.BeginPrekeyCollection(p.delegation, eventlog.PrekeyCollectionPlan{
		DeviceIDs: append([]string(nil), p.config.DeviceIDs...), AlgorithmID: p.config.AlgorithmID,
		IssuedAtUnix: issued, ExpiresAtUnix: expires,
	}, now)
	return err
}

func (p *prekeyPlanner) Run(ctx context.Context, failed func(error)) {
	ticker := time.NewTicker(p.config.CheckInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.Ensure(); err != nil && failed != nil {
				failed(err)
			}
		}
	}
}
