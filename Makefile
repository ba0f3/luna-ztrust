.PHONY: test testdata e2e-up e2e-down e2e-wait e2e-unseal e2e-test fmt fmt-check lint build update ci

MODULES := agent proxy sdk
E2E_PROXY_URL ?= https://localhost:8443

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

PROXY_LDFLAGS := -s -w \
	-X github.com/ba0f3/luna-ztrust/proxy/internal/version.Version=$(VERSION) \
	-X github.com/ba0f3/luna-ztrust/proxy/internal/version.Commit=$(COMMIT) \
	-X github.com/ba0f3/luna-ztrust/proxy/internal/version.Date=$(DATE)
AGENT_LDFLAGS := -s -w \
	-X github.com/ba0f3/luna-ztrust/agent/internal/version.Version=$(VERSION) \
	-X github.com/ba0f3/luna-ztrust/agent/internal/version.Commit=$(COMMIT) \
	-X github.com/ba0f3/luna-ztrust/agent/internal/version.Date=$(DATE)

COMPOSE := docker compose -f deploy/docker-compose.e2e.yml

build:
	go work sync
	(cd proxy && CGO_ENABLED=0 go build -ldflags "$(PROXY_LDFLAGS)" -o ../bin/luna-proxy ./cmd/luna-proxy)
	(cd agent && CGO_ENABLED=0 go build -ldflags "$(AGENT_LDFLAGS)" -o ../bin/luna-agent ./cmd/luna-agent)

fmt:
	@for m in $(MODULES); do \
		echo "==> $$m"; \
		(cd $$m && go fmt ./...); \
	done

fmt-check:
	@for m in $(MODULES); do \
		echo "==> $$m"; \
		out=$$(cd $$m && go fmt ./...); \
		if [ -n "$$out" ]; then \
			echo "$$out"; \
			exit 1; \
		fi; \
	done

lint:
	@for m in $(MODULES); do \
		echo "==> $$m"; \
		(cd $$m && go vet ./...); \
	done

update:
	go work sync
	@for m in $(MODULES); do \
		echo "==> $$m"; \
		(cd $$m && go get -u ./... && go mod tidy); \
	done
	go work sync

ci: fmt-check lint test build

test:
	go work sync
	go test ./sdk/... ./proxy/... ./agent/...

testdata:
	./scripts/gen-test-ca.sh
	./scripts/gen-test-ssh-ca.sh

e2e-up: testdata
	$(COMPOSE) up -d --build

e2e-down:
	$(COMPOSE) down -v

e2e-wait:
	@for i in $$(seq 1 30); do \
		if curl -sfk "$(E2E_PROXY_URL)/healthz" >/dev/null 2>&1; then \
			echo "proxy ready"; \
			exit 0; \
		fi; \
		sleep 2; \
	done; \
	echo "e2e proxy not ready at $(E2E_PROXY_URL)"; \
	exit 1

e2e-unseal:
	@echo test-pass | $(COMPOSE) exec -T luna-proxy \
		luna-proxy --socket /run/luna/control.sock key load /etc/luna/ssh/encrypted_ca.key --passphrase-stdin

e2e-test: e2e-unseal
	LUNA_PROXY_URL=$(E2E_PROXY_URL) go test -tags=e2e ./sdk/sign/... -count=1 -v
