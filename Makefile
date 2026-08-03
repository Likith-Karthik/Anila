GO ?= go
BINARY := bin/sshscope
FUZZTIME ?= 10s
VERSION ?= dev
BUILD_FLAGS := -trimpath -buildvcs=false
LDFLAGS := -s -w -X main.version=$(VERSION)
DIST := dist

.PHONY: build release release-licenses test test-race fuzz integration-test docker-integration-test lint clean

build:
	$(GO) build $(BUILD_FLAGS) -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/sshscope

release: release-licenses
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build $(BUILD_FLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/sshscope-$(VERSION)-darwin-amd64 ./cmd/sshscope
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build $(BUILD_FLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/sshscope-$(VERSION)-darwin-arm64 ./cmd/sshscope
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(BUILD_FLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/sshscope-$(VERSION)-linux-amd64 ./cmd/sshscope
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(BUILD_FLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/sshscope-$(VERSION)-linux-arm64 ./cmd/sshscope
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build $(BUILD_FLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/sshscope-$(VERSION)-windows-amd64.exe ./cmd/sshscope
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 $(GO) build $(BUILD_FLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/sshscope-$(VERSION)-windows-arm64.exe ./cmd/sshscope
	cd $(DIST) && if command -v sha256sum >/dev/null 2>&1; then sha256sum sshscope-$(VERSION)-* > SHA256SUMS; else shasum -a 256 sshscope-$(VERSION)-* > SHA256SUMS; fi

release-licenses:
	mkdir -p $(DIST)
	@set -eu; output='$(DIST)/THIRD_PARTY_LICENSES.txt'; : > "$$output"; \
	for module in github.com/spf13/cobra github.com/spf13/pflag github.com/inconshreveable/mousetrap golang.org/x/crypto golang.org/x/sys golang.org/x/time gopkg.in/yaml.v3; do \
		directory="$$($(GO) list -m -f '{{.Dir}}' "$$module")"; \
		license="$$(find "$$directory" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'COPYING*' \) | head -n 1)"; \
		test -n "$$license"; \
		printf '\n===== %s =====\n\n' "$$module" >> "$$output"; \
		cat "$$license" >> "$$output"; \
	done
	cp LICENSE README.md THIRD_PARTY_NOTICES.md $(DIST)/

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

fuzz:
	$(GO) test ./internal/probe/banner -run='^$$' -fuzz=FuzzParseIdentification -fuzztime=$(FUZZTIME)
	$(GO) test ./internal/probe/kex -run='^$$' -fuzz=FuzzReadPacket -fuzztime=$(FUZZTIME)
	$(GO) test ./internal/probe/kex -run='^$$' -fuzz=FuzzParseNameList -fuzztime=$(FUZZTIME)
	$(GO) test ./internal/probe/kex -run='^$$' -fuzz=FuzzParseKEXINIT -fuzztime=$(FUZZTIME)
	$(GO) test ./internal/policy -run='^$$' -fuzz=FuzzYAMLLoader -fuzztime=$(FUZZTIME)

integration-test:
	$(GO) test -count=1 ./integration

docker-integration-test: build
	sh integration/docker/run.sh

lint:
	$(GO) fmt ./...
	$(GO) vet ./...

clean:
	$(GO) clean -testcache
	$(RM) $(BINARY)
	$(RM) -r $(DIST)
