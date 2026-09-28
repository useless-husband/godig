BIN     := godig
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test race vet fuzz release clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BIN) .

test:
	go test ./...

race:
	go test -race -count=1 ./...

vet:
	go vet ./...

# Fuzz the message decoder for 30 seconds (CI only runs the seed corpus).
fuzz:
	go test ./internal/dnsmsg -run '^$$' -fuzz FuzzUnpack -fuzztime 30s

release: clean
	mkdir -p dist
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/$(BIN)-darwin-arm64 .
	GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/$(BIN)-darwin-amd64 .
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/$(BIN)-linux-amd64 .
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/$(BIN)-windows-amd64.exe .

clean:
	rm -rf dist $(BIN)
