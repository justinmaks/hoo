BINARY := hoo
PKG := github.com/justinmaks/hoo
CMD := ./cmd/hoo

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X '$(PKG)/internal/cmd.version=$(VERSION)' \
	-X '$(PKG)/internal/cmd.commit=$(COMMIT)' \
	-X '$(PKG)/internal/cmd.date=$(DATE)'

.PHONY: build test lint run clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(CMD)

test:
	go test ./... -v -race

lint:
	golangci-lint run ./...

run: build
	sudo ./bin/$(BINARY)

clean:
	rm -rf bin/
