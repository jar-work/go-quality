package container

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jar-work/go-quality/internal/findings"
)

// RuleDockerignore is goquality's own rule, for a gap neither hadolint nor trivy covers: copying
// the whole build context with no .dockerignore puts .env files and keys into the image layers.
const RuleDockerignore = "GQ001"

// Dockerignore reports each COPY or ADD of the whole build context in files (relative to dir)
// that no .dockerignore applies to: neither one next to the Dockerfile nor <Dockerfile>.dockerignore.
// It assumes the build context is the Dockerfile's directory, as `docker build .` does.
func Dockerignore(dir string, files []string) ([]findings.Finding, error) {
	var out []findings.Finding
	for _, file := range files {
		path := filepath.Join(dir, filepath.FromSlash(file))
		if exists(filepath.Join(filepath.Dir(path), ".dockerignore")) || exists(path+".dockerignore") {
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		for _, in := range instructions(string(content)) {
			if (in.command == "COPY" || in.command == "ADD") && copiesWholeContext(in.args) {
				out = append(out, findings.Finding{
					Rule: RuleDockerignore,
					File: file,
					Text: fmt.Sprintf("%s:%d: %s %s copies the whole build context with no .dockerignore: .env files and keys end up in the image layers",
						file, in.line, RuleDockerignore, in.command),
				})
			}
		}
	}
	return out, nil
}

type instruction struct {
	line          int
	command, args string
}

// instructions splits a Dockerfile into instructions, joining backslash continuations and
// skipping comments and blank lines (also inside a continuation, as Docker does).
func instructions(content string) []instruction {
	var out []instruction
	var current *instruction
	for i, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		continued := strings.HasSuffix(line, `\`)
		line = strings.TrimSpace(strings.TrimSuffix(line, `\`))
		if current == nil {
			command, args, _ := strings.Cut(line, " ")
			current = &instruction{line: i + 1, command: strings.ToUpper(command), args: strings.TrimSpace(args)}
		} else {
			current.args = strings.TrimSpace(current.args + " " + line)
		}
		if !continued {
			out = append(out, *current)
			current = nil
		}
	}
	if current != nil {
		out = append(out, *current)
	}
	return out
}

// copiesWholeContext reports whether COPY/ADD arguments have "." among their sources. A copy
// --from another stage or image does not read the build context.
func copiesWholeContext(args string) bool {
	var paths []string
	for _, f := range strings.Fields(args) {
		if strings.HasPrefix(f, "--from") {
			return false
		}
		if !strings.HasPrefix(f, "--") {
			paths = append(paths, f)
		}
	}
	if joined := strings.Join(paths, " "); strings.HasPrefix(joined, "[") {
		paths = nil
		if err := json.Unmarshal([]byte(joined), &paths); err != nil {
			return false
		}
	}
	for _, src := range paths[:max(len(paths)-1, 0)] { // the last path is the destination
		if src == "." || src == "./" {
			return true
		}
	}
	return false
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
