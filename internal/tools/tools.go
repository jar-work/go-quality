// Package tools pins the external tools goquality runs. They are invoked with `go run pkg@version`,
// so upgrading one here upgrades it in every repository on its next goquality release.
package tools

const (
	Gremlins    = "github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0"
	Gosec       = "github.com/securego/gosec/v2/cmd/gosec@v2.29.0"
	Govulncheck = "golang.org/x/vuln/cmd/govulncheck@v1.8.0"
	Gitleaks    = "github.com/zricethezav/gitleaks/v8@v8.30.1"
)
