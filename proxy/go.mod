module github.com/ba0f3/luna-ztrust/proxy

go 1.25.0

require (
	github.com/oklog/ulid/v2 v2.1.1
	golang.org/x/crypto v0.51.0
)

require golang.org/x/sys v0.44.0 // indirect

replace github.com/ba0f3/luna-ztrust/sdk => ../sdk
