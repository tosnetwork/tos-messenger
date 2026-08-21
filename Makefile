.PHONY: verify fmt-check vet test-race test-openmls build

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

build:
	GOWORK=off go build ./...
