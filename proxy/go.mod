module github.com/ba0f3/luna-ztrust/proxy

go 1.23.0

require (
	github.com/oklog/ulid/v2 v2.1.0
	golang.org/x/crypto v0.39.0
)

require golang.org/x/sys v0.33.0 // indirect

replace github.com/ba0f3/luna-ztrust/sdk => ../sdk
