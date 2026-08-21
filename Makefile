.PHONY: verify fmt-check vet test-race test-openmls test-storage-live build

verify: fmt-check vet test-race test-adnl test-openmls build

fmt-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

vet:
	GOWORK=off go vet ./...

test-race:
	GOWORK=off go test -race -count=1 ./...

# The ADNL gateway cannot run under the race detector (tonutils-go's TL
# serializer trips checkptr), so its end-to-end tests skip there and run here.
test-adnl:
	GOWORK=off go test -count=1 -run ADNL ./pkg/probe ./pkg/publicchannel ./cmd/tos-reachability

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

build:
	GOWORK=off go build ./...
