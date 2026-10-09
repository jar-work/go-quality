package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionWarning(t *testing.T) {
	b := Binary{Name: "trivy", Version: "0.75.0"}
	if w := VersionWarning(b, "Version: 0.75.0\nVulnerability DB: ..."); w != "" {
		t.Errorf("same version warned: %s", w)
	}
	if w := VersionWarning(b, "Version: 0.76.1"); !strings.Contains(w, "trivy 0.76.1 is installed, goquality is pinned to 0.75.0") {
		t.Errorf("warning = %q", w)
	}
	if w := VersionWarning(b, " dev build "); !strings.Contains(w, "trivy dev build is installed") {
		t.Errorf("warning without a version = %q", w)
	}
}

func TestCheckMissingBinary(t *testing.T) {
	_, err := Binary{Name: "goquality-no-such-tool", Install: "brew install it"}.Check()
	if err == nil || !strings.Contains(err.Error(), "is not installed: brew install it") {
		t.Errorf("err = %v", err)
	}
}

func TestCheckInstalledBinary(t *testing.T) {
	dir := t.TempDir()
	script := func(name, body string) {
		os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o700)
	}
	script("fake-ok", `echo "Version: 1.2.3"`)
	script("fake-broken", `echo "boom" >&2; exit 3`)
	t.Setenv("PATH", dir)

	if w, err := (Binary{Name: "fake-ok", Version: "1.2.3"}).Check(); w != "" || err != nil {
		t.Errorf("pinned version: %q, %v", w, err)
	}
	if w, err := (Binary{Name: "fake-ok", Version: "1.2.4"}).Check(); err != nil || !strings.Contains(w, "fake-ok 1.2.3 is installed, goquality is pinned to 1.2.4") {
		t.Errorf("other version: %q, %v", w, err)
	}
	if _, err := (Binary{Name: "fake-broken", Version: "1.0.0"}).Check(); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("failing --version: %v", err)
	}
}
