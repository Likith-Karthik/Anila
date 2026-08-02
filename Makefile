GO ?= go
BINARY := bin/sshscope
FUZZTIME ?= 10s

.PHONY: build test test-race fuzz integration-test lint clean

build:
	$(GO) build -trimpath -o $(BINARY) ./cmd/sshscope

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

fuzz:
	$(GO) test ./internal/probe/banner -run='^$$' -fuzz=FuzzParseIdentification -fuzztime=$(FUZZTIME)
	$(GO) test ./internal/probe/kex -run='^$$' -fuzz=FuzzReadPacket -fuzztime=$(FUZZTIME)
	$(GO) test ./internal/probe/kex -run='^$$' -fuzz=FuzzParseNameList -fuzztime=$(FUZZTIME)
	$(GO) test ./internal/probe/kex -run='^$$' -fuzz=FuzzParseKEXINIT -fuzztime=$(FUZZTIME)

integration-test:
	$(GO) test -count=1 ./integration

lint:
	$(GO) fmt ./...
	$(GO) vet ./...

clean:
	$(GO) clean -testcache
