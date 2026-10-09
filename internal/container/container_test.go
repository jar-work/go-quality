package container

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jar-work/go-quality/internal/findings"
)

// hadolintOutput is hadolint 2.15.1's output on a multi-stage Go API Dockerfile.
const hadolintOutput = `[{"code":"DL3018","column":1,"file":"Dockerfile","level":"warning","line":5,"message":"Pin versions in apk add."},` +
	`{"code":"DL3059","column":1,"file":"Dockerfile","level":"info","line":18,"message":"Multiple consecutive RUN instructions."},` +
	`{"code":"DL3066","column":1,"file":"Dockerfile","level":"info","line":31,"message":"Non-numeric user-id"},` +
	`{"code":"DL3002","column":1,"file":"cli/Dockerfile","level":"error","line":9,"message":"Last USER should not be root"},` +
	`{"code":"SC2086","column":1,"file":"cli/Dockerfile","level":"style","line":4,"message":"Double quote to prevent globbing"}]`

func TestParseHadolint(t *testing.T) {
	cases := map[string]string{
		"error":   "DL3002 cli/Dockerfile",
		"warning": "DL3018 Dockerfile,DL3002 cli/Dockerfile",
		"info":    "DL3018 Dockerfile,DL3059 Dockerfile,DL3066 Dockerfile,DL3002 cli/Dockerfile",
		"style":   "DL3018 Dockerfile,DL3059 Dockerfile,DL3066 Dockerfile,DL3002 cli/Dockerfile,SC2086 cli/Dockerfile",
	}
	for level, want := range cases {
		found, err := ParseHadolint(hadolintOutput, level)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range found {
			got = append(got, f.Key())
		}
		if strings.Join(got, ",") != want {
			t.Errorf("level %s: %v, want %s", level, got, want)
		}
	}
	found, _ := ParseHadolint(hadolintOutput, "error")
	if found[0].Text != "cli/Dockerfile:9: DL3002 (error) Last USER should not be root" {
		t.Errorf("Text = %q", found[0].Text)
	}
	if _, err := ParseHadolint("hadolint: openBinaryFile: does not exist", "warning"); err == nil {
		t.Error("parsed an error message")
	}
}

// trivyOutput is the shape of trivy 0.75's report: a Dockerfile, and a chart rendered with values.
const trivyOutput = `{"SchemaVersion":2,"Results":[
 {"Target":"Dockerfile","Class":"config","Type":"dockerfile","Misconfigurations":[
   {"ID":"DS-0002","Title":"Image user should not be 'root'","Severity":"HIGH","Status":"FAIL","Resolution":"Add 'USER <non root user name>' line to the Dockerfile","CauseMetadata":{"StartLine":0}},
   {"ID":"DS-0005","Title":"ADD instead of COPY","Severity":"LOW","Status":"PASS","CauseMetadata":{}}]},
 {"Target":"templates/deployment.yaml","Class":"config","Type":"helm","Misconfigurations":[
   {"ID":"KSV-0014","Title":"Root file system is not read-only","Severity":"HIGH","Status":"FAIL","Resolution":"Change 'containers[].securityContext.readOnlyRootFilesystem' to 'true'.","CauseMetadata":{"StartLine":24}}]},
 {"Target":"templates/service.yaml","Class":"config","Type":"kubernetes"}]}`

func TestParseTrivy(t *testing.T) {
	found, err := ParseTrivy(trivyOutput, "../../charts/api")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("found = %+v, want the two FAIL results", found)
	}
	if found[0].Key() != "DS-0002 ../../charts/api/Dockerfile" || found[1].Key() != "KSV-0014 ../../charts/api/templates/deployment.yaml" {
		t.Errorf("keys = %s, %s", found[0].Key(), found[1].Key())
	}
	if want := "../../charts/api/templates/deployment.yaml:24: KSV-0014 (HIGH) Root file system is not read-only. Change"; !strings.HasPrefix(found[1].Text, want) {
		t.Errorf("Text = %q", found[1].Text)
	}
	if found, _ := ParseTrivy(trivyOutput, "."); found[0].File != "Dockerfile" {
		t.Errorf("target . gave file %q", found[0].File)
	}
	if _, err := ParseTrivy("FATAL: something", "."); err == nil {
		t.Error("parsed an error message")
	}
}

func TestDockerfiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"Dockerfile", "cli/Dockerfile.prod", "tools/build.dockerfile", "node_modules/x/Dockerfile", ".git/Dockerfile", "vendor/Dockerfile", "README.md"} {
		write(t, filepath.Join(dir, name), "FROM alpine:3.24\n")
	}
	files, err := Dockerfiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(files, ","); got != "Dockerfile,cli/Dockerfile.prod,tools/build.dockerfile" {
		t.Errorf("files = %s", got)
	}
}

func TestValidLevel(t *testing.T) {
	if !ValidLevel("style") || ValidLevel("notice") {
		t.Error("ValidLevel")
	}
}

// The integration tests run the real binaries when they are installed.

const rootDockerfile = "FROM alpine\nRUN apk add curl\nCOPY . /app\n"

func TestHadolintIntegration(t *testing.T) {
	requireBinary(t, "hadolint")
	dir := t.TempDir()
	write(t, filepath.Join(dir, "Dockerfile"), rootDockerfile)
	found, err := Hadolint(dir, []string{"Dockerfile"}, "warning")
	if err != nil {
		t.Fatal(err)
	}
	keys := keysOf(found)
	if !strings.Contains(keys, "DL3006 Dockerfile") || !strings.Contains(keys, "DL3018 Dockerfile") {
		t.Errorf("found %s, want DL3006 (untagged image) and DL3018 (unpinned apk)", keys)
	}
	if none, err := Hadolint(dir, nil, "warning"); err != nil || none != nil {
		t.Errorf("no files: %v, %v", none, err)
	}
}

func TestTrivyIntegration(t *testing.T) {
	requireBinary(t, "trivy")
	dir := t.TempDir()
	write(t, filepath.Join(dir, "Dockerfile"), rootDockerfile)
	found, err := Trivy(dir, ".", nil, []string{"HIGH", "CRITICAL"})
	if err != nil {
		t.Fatal(err)
	}
	if keys := keysOf(found); !strings.Contains(keys, "DS-0002 Dockerfile") || strings.Contains(keys, "DS-0026") {
		t.Errorf("found %s, want DS-0002 (runs as root) and nothing LOW such as DS-0026", keys)
	}
	if _, err := Trivy(dir, "missing-dir", nil, []string{"HIGH"}); err == nil {
		t.Error("a missing target did not fail")
	}
}

func requireBinary(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s is not installed", name)
	}
}

func keysOf(found []findings.Finding) string {
	var keys []string
	for _, f := range found {
		keys = append(keys, f.Key())
	}
	return strings.Join(keys, ",")
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCopiesWholeContext(t *testing.T) {
	cases := map[string]bool{
		". .":                                  true,
		"./ /app":                              true,
		"--chown=app:app . /app":               true,
		"go.mod go.sum . ./":                   true,
		`[".", "/app"]`:                        true,
		"--from=build /app/main .":             false, // another stage, not the context
		"--from=golang:1.26 /usr/local/go /go": false,
		"go.mod go.sum ./":                     false,
		". ":                                   false, // a destination alone
		"src/ /app/src/":                       false,
		`["main.go", "/app"]`:                  false,
		`[".", "/app"`:                         false, // malformed JSON form
	}
	for args, want := range cases {
		if got := copiesWholeContext(args); got != want {
			t.Errorf("copiesWholeContext(%q) = %v, want %v", args, got, want)
		}
	}
}

func TestInstructions(t *testing.T) {
	got := instructions("# syntax=docker/dockerfile:1\nFROM golang:1.26 AS build\n\ncopy go.mod \\\n    # a comment inside\n    go.sum \\\n\n    ./\nRUN go build \\")
	if len(got) != 3 {
		t.Fatalf("instructions = %+v", got)
	}
	if got[1] != (instruction{line: 4, command: "COPY", args: "go.mod go.sum ./"}) {
		t.Errorf("COPY = %+v", got[1])
	}
	if got[2] != (instruction{line: 9, command: "RUN", args: "go build"}) {
		t.Errorf("unfinished RUN = %+v", got[2])
	}
}

func TestDockerignore(t *testing.T) {
	dir := t.TempDir()
	// Copies the whole context, nothing ignored: reported once per offending instruction.
	write(t, filepath.Join(dir, "Dockerfile"), "FROM golang:1.26 AS build\nCOPY go.mod ./\nCOPY . .\nFROM alpine:3.24\nCOPY --from=build /app/main .\nADD . /extra\n")
	// A .dockerignore next to it.
	write(t, filepath.Join(dir, "api", "Dockerfile"), "FROM alpine:3.24\nCOPY . /app\n")
	write(t, filepath.Join(dir, "api", ".dockerignore"), ".env\n")
	// Its own <Dockerfile>.dockerignore.
	write(t, filepath.Join(dir, "jobs", "build.Dockerfile"), "FROM alpine:3.24\nCOPY . /app\n")
	write(t, filepath.Join(dir, "jobs", "build.Dockerfile.dockerignore"), ".env\n")
	// Copies only named files.
	write(t, filepath.Join(dir, "cli", "Dockerfile"), "FROM alpine:3.24\nCOPY main /app/\n")

	found, err := Dockerignore(dir, []string{"Dockerfile", "api/Dockerfile", "jobs/build.Dockerfile", "cli/Dockerfile"})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 || found[0].Key() != "GQ001 Dockerfile" ||
		!strings.HasPrefix(found[0].Text, "Dockerfile:3: GQ001 COPY copies the whole build context") ||
		!strings.HasPrefix(found[1].Text, "Dockerfile:6: GQ001 ADD") {
		t.Errorf("found = %+v", found)
	}
	if _, err := Dockerignore(dir, []string{"missing/Dockerfile"}); err == nil {
		t.Error("a missing Dockerfile did not fail")
	}
}
