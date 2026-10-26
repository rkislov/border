.PHONY: build test check audit clean
build:
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o bin/radiusd ./cmd/radiusd
test:
	go test -race -count=1 ./...
check:
	go vet ./...
	@test -z "$$(gofmt -l cmd internal)"
audit:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
clean:
	rm -rf bin
