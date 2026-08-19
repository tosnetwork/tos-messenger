.PHONY: verify fmt-check vet test-race build

verify: fmt-check vet test-race test-adnl build

fmt-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

vet:
	GOWORK=off go vet ./...

test-race:
	GOWORK=off go test -race -count=1 ./...

# The ADNL gateway cannot run under the race detector (tonutils-go's TL
# serializer trips checkptr), so its end-to-end tests skip there and run here.
test-adnl:
	GOWORK=off go test -count=1 -run ADNL ./pkg/probe ./cmd/tos-reachability

build:
	GOWORK=off go build ./...
