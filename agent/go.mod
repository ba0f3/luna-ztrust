module github.com/ba0f3/luna-ztrust/agent

go 1.25.0

require (
	github.com/ba0f3/luna-ztrust/sdk v0.0.0
	golang.org/x/crypto v0.52.0
)

require golang.org/x/sys v0.45.0 // indirect

replace github.com/ba0f3/luna-ztrust/sdk => ../sdk
