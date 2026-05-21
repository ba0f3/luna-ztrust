module github.com/ba0f3/luna-ztrust/proxy

go 1.22

require (
    github.com/ba0f3/luna-ztrust/sdk v0.0.0
    github.com/oklog/ulid/v2 v2.1.0
    golang.org/x/crypto v0.39.0
)

replace github.com/ba0f3/luna-ztrust/sdk => ../sdk
