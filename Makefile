.PHONY: test testdata
test:
	go work sync
	go test ./sdk/... ./proxy/... ./agent/...

testdata:
	./scripts/gen-test-ca.sh
