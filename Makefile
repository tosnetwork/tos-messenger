.PHONY: verify fmt-check vet test-race test-openmls test-storage-live test-attachment-corpus-live calibrate-public-channel calibrate-public-channel-concurrent build

verify: fmt-check vet test-race test-adnl test-openmls build

fmt-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

vet:
	GOWORK=off go vet ./...

test-race:
	GOWORK=off go test -race -count=1 ./...

# The ADNL gateway cannot run under the race detector (tosutils-go's TL
# serializer trips checkptr), so its ADNL and RLDP end-to-end tests skip there
# and run here.
test-adnl:
	GOWORK=off go test -count=1 -run 'ADNL|RLDP' ./pkg/probe ./pkg/publicchannel ./cmd/tos-reachability

test-openmls:
	cargo fmt --manifest-path rust/openmls-driver/Cargo.toml -- --check
	cargo test --locked --manifest-path rust/openmls-driver/Cargo.toml
	cargo build --locked --manifest-path rust/openmls-driver/Cargo.toml
	TOS_OPENMLS_DRIVER="$$(pwd)/rust/openmls-driver/target/debug/tos-openmls-driver" GOWORK=off go test -count=1 -run OpenMLS ./pkg/group ./pkg/eventlog ./pkg/mlslab

# Explicit operator acceptance: starts two real storage-daemon processes and a
# locally signed DHT bootstrap. It is intentionally outside verify because the
# four inputs are independently built/provisioned operator resources.
test-storage-live:
	@test -n "$$TOS_STORAGE_LIVE_DAEMON" -a -n "$$TOS_STORAGE_LIVE_CLI" -a -n "$$TOS_STORAGE_LIVE_KEY_TOOL" -a -n "$$TOS_STORAGE_LIVE_GLOBAL_CONFIG" || { echo "set TOS_STORAGE_LIVE_DAEMON, TOS_STORAGE_LIVE_CLI, TOS_STORAGE_LIVE_KEY_TOOL, and TOS_STORAGE_LIVE_GLOBAL_CONFIG"; exit 1; }
	GOWORK=off go test -count=1 -run TestStorageCLILiveTwoDaemonCatchUp -v ./pkg/publicchannel

# Explicit private-corpus acceptance. The approver and runner keys identify
# accountable parties but do not themselves prove organizational independence
# or corpus representativeness; those remain review facts outside this target.
test-attachment-corpus-live:
	@test -n "$$TOS_ATTACHMENT_CORPUS_RUNNER" -a -n "$$TOS_ATTACHMENT_CORPUS_MANIFEST" -a -n "$$TOS_ATTACHMENT_CORPUS_SAMPLES" -a -n "$$TOS_ATTACHMENT_CORPUS_POLICY" -a -n "$$TOS_ATTACHMENT_CORPUS_APPROVER_KEY" -a -n "$$TOS_ATTACHMENT_CORPUS_RUNNER_KEY" -a -n "$$TOS_ATTACHMENT_CORPUS_RUNNER_PUBLIC_KEY" -a -n "$$TOS_ATTACHMENT_CORPUS_REPORT" || { echo "set all TOS_ATTACHMENT_CORPUS_* acceptance inputs"; exit 1; }
	"$$TOS_ATTACHMENT_CORPUS_RUNNER" run -manifest "$$TOS_ATTACHMENT_CORPUS_MANIFEST" -samples "$$TOS_ATTACHMENT_CORPUS_SAMPLES" -admission-policy "$$TOS_ATTACHMENT_CORPUS_POLICY" -approver-public-key "$$TOS_ATTACHMENT_CORPUS_APPROVER_KEY" -runner-key "$$TOS_ATTACHMENT_CORPUS_RUNNER_KEY" -output "$$TOS_ATTACHMENT_CORPUS_REPORT"
	"$$TOS_ATTACHMENT_CORPUS_RUNNER" verify -manifest "$$TOS_ATTACHMENT_CORPUS_MANIFEST" -admission-policy "$$TOS_ATTACHMENT_CORPUS_POLICY" -report "$$TOS_ATTACHMENT_CORPUS_REPORT" -approver-public-key "$$TOS_ATTACHMENT_CORPUS_APPROVER_KEY" -runner-public-key "$$TOS_ATTACHMENT_CORPUS_RUNNER_PUBLIC_KEY"

# Opt-in, single-core resource evidence. The protocol-maximum Storage cases
# create and verify 65,536 immutable Event files and can take several minutes.
calibrate-public-channel:
	GOMAXPROCS=1 GOWORK=off go test -run '^$$' -bench 'BenchmarkPublicChannel' -benchmem -benchtime=1x -count=1 ./pkg/publicchannel

# Opt-in concurrent authenticated-peer calibration. Override the scheduler
# width only to record a particular target; the benchmark always exercises
# 1, 8, and the protocol maximum of 32 simultaneous peers.
calibrate-public-channel-concurrent:
	GOMAXPROCS="$${TOS_PUBLIC_CHANNEL_CALIBRATION_PROCS:-8}" GOWORK=off go test -run '^$$' -bench '^BenchmarkConcurrentPublicChannelPeerSync$$' -benchmem -benchtime=1x -count=1 ./pkg/publicchannel

build:
	GOWORK=off go build ./...
