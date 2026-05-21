.PHONY: test testdata e2e-up e2e-down e2e-test

COMPOSE := docker compose -f deploy/docker-compose.e2e.yml

test:
	go work sync
	go test ./sdk/... ./proxy/... ./agent/...

testdata:
	./scripts/gen-test-ca.sh

e2e-up: testdata
	$(COMPOSE) up -d --build

e2e-down:
	$(COMPOSE) down -v

e2e-test:
	LUNA_PROXY_URL=https://localhost:8443 go test -tags=e2e ./sdk/sign/... -count=1 -v
