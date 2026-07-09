GO ?= go

default: build

.PHONY: build
build:
	mkdir -p ./bin/
	CGO_ENABLED=0 $(GO) build -o ./bin/openfga-sync ./cmd/openfga-sync

.PHONY: test
test:
	$(GO) test ./... -cover

.PHONY: static-analysis
static-analysis:
ifeq ($(shell command -v golangci-lint),)
	curl -sSfL https://golangci-lint.run/install.sh | sh -s -- -b $$($(GO) env GOPATH)/bin
endif
	golangci-lint run ./...

.PHONY: vulncheck
vulncheck:
ifeq ($(shell command -v govulncheck),)
	go install golang.org/x/vuln/cmd/govulncheck@latest
endif
	govulncheck ./...

.PHONY: update-gomod
update-gomod:
	$(GO) get -t -v -u ./...
	$(GO) mod tidy --go=1.25.12
	$(GO) get toolchain@none

.PHONY: clean
clean:
	rm -rf bin/
