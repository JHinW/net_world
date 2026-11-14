//go:build windows

package main

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"

	ssh "github.com/tailscale/gliderssh"
)

func newPlatformSessionCommand(u *user.User, rawCmd string) *exec.Cmd {
	shell := resolveWindowsShell()
	var args []string
	if rawCmd == "" {
		args = []string{shell, "-NoLogo"}
	} else {
		args = []string{shell, "-Command", rawCmd}
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = u.HomeDir
	cmd.Env = os.Environ()
	return cmd
}

func resolveWindowsShell() string {
	if p, err := exec.LookPath("pwsh.exe"); err == nil {
		return p
	}
	if p, err := exec.LookPath("powershell.exe"); err == nil {
		return p
	}
	return filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}

func runSessionWithPTY(sess ssh.Session, cmd *exec.Cmd, ptyReq ssh.Pty, _ <-chan ssh.Window) {
	if ptyReq.Term != "" {
		cmd.Env = append(cmd.Env, "TERM="+ptyReq.Term)
	}
	runSessionWithPipes(sess, cmd)
}
