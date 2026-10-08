// Package execx runs external commands, streaming their output while keeping a copy to parse.
package execx

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
)

// Run executes name with args in dir. Output goes to out (if not nil) as it is produced and is
// also returned. A non-zero exit is reported through exitCode, not err; err is for failing to
// start the command at all.
func Run(dir string, env []string, out io.Writer, name string, args ...string) (output string, exitCode int, err error) {
	var buf bytes.Buffer
	w := io.Writer(&buf)
	if out != nil {
		w = io.MultiWriter(&buf, out)
	}
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = w
	cmd.Stderr = w
	err = cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return buf.String(), exitErr.ExitCode(), nil
	}
	return buf.String(), 0, err
}
