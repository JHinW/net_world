//go:build !windows

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/creack/pty"
	ssh "github.com/tailscale/gliderssh"
)

func newPlatformSessionCommand(u *user.User, rawCmd string) *exec.Cmd {
	shell := resolveUnixLoginShell(u)
	var args []string
	if rawCmd == "" {
		args = []string{shell, "-l"}
	} else {
		args = []string{shell, "-c", rawCmd}
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = u.HomeDir
	cmd.Env = []string{
		"SHELL=" + shell,
		"USER=" + u.Username,
		"LOGNAME=" + u.Username,
		"HOME=" + u.HomeDir,
		"PATH=" + resolveUnixSessionPath(u),
	}
	return cmd
}

func resolveUnixLoginShell(u *user.User) string {
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("dscl", ".", "-read", filepath.Join("/Users", u.Username), "UserShell").Output()
		if err == nil {
			if s, ok := strings.CutPrefix(string(out), "UserShell: "); ok {
				if trimmed := strings.TrimSpace(s); trimmed != "" {
					return trimmed
				}
			}
		}
	}
	if e := strings.TrimSpace(os.Getenv("SHELL")); e != "" {
		return e
	}
	if _, err := os.Stat("/bin/bash"); err == nil {
		return "/bin/bash"
	}
	return "/bin/sh"
}

func resolveUnixSessionPath(u *user.User) string {
	fallback := "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
	if u.Uid == "0" {
		fallback = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	if runtime.GOOS == "darwin" {
		fallback = "/opt/homebrew/bin:/opt/homebrew/sbin:" + fallback
	}
	hostPath := strings.TrimSpace(os.Getenv("PATH"))
	if hostPath == "" {
		return fallback
	}
	return hostPath + ":" + fallback
}

func runSessionWithPTY(sess ssh.Session, cmd *exec.Cmd, ptyReq ssh.Pty, winCh <-chan ssh.Window) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		_, _ = fmt.Fprintf(sess.Stderr(), "pty open: %v\r\n", err)
		_ = sess.Exit(1)
		return
	}
	defer ptmx.Close()
	defer tty.Close()

	if ptyReq.Term != "" {
		cmd.Env = append(cmd.Env, "TERM="+ptyReq.Term)
	}
	_ = pty.Setsize(ptmx, &pty.Winsize{
		Rows: uint16(ptyReq.Window.Height),
		Cols: uint16(ptyReq.Window.Width),
		X:    uint16(ptyReq.Window.WidthPixels),
		Y:    uint16(ptyReq.Window.HeightPixels),
	})

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setctty: true,
		Setsid:  true,
	}
	cmd.Stdin = tty
	cmd.Stdout = tty
	cmd.Stderr = tty

	if err := cmd.Start(); err != nil {
		_, _ = fmt.Fprintf(sess.Stderr(), "start: %v\r\n", err)
		_ = sess.Exit(1)
		return
	}
	_ = tty.Close()

	go func() {
		for win := range winCh {
			_ = pty.Setsize(ptmx, &pty.Winsize{
				Rows: uint16(win.Height),
				Cols: uint16(win.Width),
				X:    uint16(win.WidthPixels),
				Y:    uint16(win.HeightPixels),
			})
		}
	}()

	go func() {
		_, _ = io.Copy(ptmx, sess)
	}()
	_, _ = io.Copy(sess, ptmx)

	if err := cmd.Wait(); err != nil {
		_ = sess.Exit(processExitCode(err))
		return
	}
	_ = sess.Exit(0)
}
