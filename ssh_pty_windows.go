//go:build windows

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"unsafe"

	ssh "github.com/tailscale/gliderssh"
	"golang.org/x/sys/windows"
)

var (
	kernel32                      = windows.NewLazySystemDLL("kernel32.dll")
	procCreatePseudoConsole       = kernel32.NewProc("CreatePseudoConsole")
	procUpdateProcThreadAttribute = kernel32.NewProc("UpdateProcThreadAttribute")
	procSetConsoleCtrlHandler     = kernel32.NewProc("SetConsoleCtrlHandler")
)

// clearInheritedCtrlCIgnore clears the "ignore Ctrl-C" console flag that the
// server may have inherited from its parent (e.g. Win32-OpenSSH sshd).
// Without clearing it, child shells inherit the flag and silently drop ^C.
var clearInheritedCtrlCIgnore = sync.OnceFunc(func() {
	_, _, _ = procSetConsoleCtrlHandler.Call(0, 0)
})

// conPTYAvailable reports whether CreatePseudoConsole is present (Windows 10 1809+).
var conPTYAvailable = sync.OnceValue(func() bool {
	return procCreatePseudoConsole.Find() == nil
})

func newPlatformSessionCommand(u *user.User, rawCmd string) *exec.Cmd {
	clearInheritedCtrlCIgnore()
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

func runSessionWithPTY(sess ssh.Session, cmd *exec.Cmd, ptyReq ssh.Pty, winCh <-chan ssh.Window) {
	if ptyReq.Term != "" {
		cmd.Env = append(cmd.Env, "TERM="+ptyReq.Term)
	}
	if !conPTYAvailable() {
		_, _ = fmt.Fprintf(sess.Stderr(), "ssh: ConPTY unavailable on this Windows version; falling back to pipes\r\n")
		runSessionWithPipes(sess, cmd)
		return
	}

	cp, err := startConPTY(cmd, ptyReq.Window.Width, ptyReq.Window.Height)
	if err != nil {
		_, _ = fmt.Fprintf(sess.Stderr(), "conpty: %v\r\n", err)
		_ = sess.Exit(1)
		return
	}
	defer cp.Close()

	go func() {
		_, _ = io.Copy(cp, sess)
	}()

	go func() {
		for win := range winCh {
			_ = cp.Resize(win.Width, win.Height)
		}
	}()

	// Drain output until EOF before CloseConsole completes so conhost cannot
	// block on a full output pipe even if sess closes early.
	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		_, _ = io.Copy(sess, cp)
		_, _ = io.Copy(io.Discard, cp)
	}()

	// Terminate the attached process if the SSH client disconnects abruptly.
	waitDone := make(chan struct{})
	cancelDone := make(chan struct{})
	go func() {
		defer close(cancelDone)
		select {
		case <-sess.Context().Done():
			cp.Terminate()
		case <-waitDone:
		}
	}()

	code, err := cp.WaitExitCode()
	close(waitDone)
	<-cancelDone

	// Closing the pseudoconsole releases conhost's write handle so outRead sees EOF.
	cp.CloseConsole()
	<-outDone

	if err != nil {
		_, _ = fmt.Fprintf(sess.Stderr(), "wait: %v\r\n", err)
		_ = sess.Exit(1)
		return
	}
	_ = sess.Exit(code)
}

// conPTY owns a Windows pseudoconsole and the single process attached to it.
type conPTY struct {
	inWrite *os.File
	outRead *os.File

	mu         sync.Mutex
	hpc        windows.Handle
	closed     bool
	proc       windows.Handle
	procClosed bool
}

// startConPTY creates a pseudoconsole and spawns cmd attached to it via CreateProcess.
func startConPTY(cmd *exec.Cmd, width, height int) (*conPTY, error) {
	hpc, inWrite, outRead, err := createPseudoConsole(width, height)
	if err != nil {
		return nil, err
	}

	proc, err := spawnAttachedProcess(cmd, hpc)
	if err != nil {
		windows.ClosePseudoConsole(hpc)
		_ = inWrite.Close()
		_ = outRead.Close()
		return nil, err
	}

	return &conPTY{
		inWrite: inWrite,
		outRead: outRead,
		hpc:     hpc,
		proc:    proc,
	}, nil
}

func createPseudoConsole(width, height int) (windows.Handle, *os.File, *os.File, error) {
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		return 0, nil, nil, err
	}
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		_ = inRead.Close()
		_ = inWrite.Close()
		return 0, nil, nil, err
	}

	var hpc windows.Handle
	size := windows.Coord{
		X: clampConPTYCoord(width, 80, maxConPTYWidth),
		Y: clampConPTYCoord(height, 24, maxConPTYHeight),
	}
	err = windows.CreatePseudoConsole(
		size,
		windows.Handle(inRead.Fd()),
		windows.Handle(outWrite.Fd()),
		0,
		&hpc,
	)
	// CreatePseudoConsole duplicates the pipe handles it needs.
	_ = inRead.Close()
	_ = outWrite.Close()
	if err != nil {
		_ = inWrite.Close()
		_ = outRead.Close()
		return 0, nil, nil, fmt.Errorf("CreatePseudoConsole: %w", err)
	}
	return hpc, inWrite, outRead, nil
}

func spawnAttachedProcess(cmd *exec.Cmd, hpc windows.Handle) (windows.Handle, error) {
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return 0, err
	}
	defer attrs.Delete()
	if err := updatePseudoConsoleAttr(attrs.List(), hpc); err != nil {
		return 0, err
	}

	cmdLine, err := windows.UTF16FromString(windows.ComposeCommandLine(cmd.Args))
	if err != nil {
		return 0, err
	}
	var dir *uint16
	if cmd.Dir != "" {
		dir, err = windows.UTF16PtrFromString(cmd.Dir)
		if err != nil {
			return 0, err
		}
	}
	envSlice := cmd.Env
	if envSlice == nil {
		envSlice = os.Environ()
	}
	env, err := windowsEnvBlock(envSlice)
	if err != nil {
		return 0, err
	}

	si := &windows.StartupInfoEx{
		// STARTF_USESTDHANDLES with nil std handles prevents the child from
		// inheriting the parent's console handles and bypassing ConPTY.
		StartupInfo: windows.StartupInfo{
			Cb:    uint32(unsafe.Sizeof(windows.StartupInfoEx{})),
			Flags: windows.STARTF_USESTDHANDLES,
		},
		ProcThreadAttributeList: attrs.List(),
	}
	var pi windows.ProcessInformation
	err = windows.CreateProcess(
		nil,
		&cmdLine[0],
		nil,
		nil,
		false,
		windows.CREATE_UNICODE_ENVIRONMENT|windows.EXTENDED_STARTUPINFO_PRESENT,
		env,
		dir,
		&si.StartupInfo,
		&pi,
	)
	if err != nil {
		return 0, fmt.Errorf("CreateProcess: %w", err)
	}
	_ = windows.CloseHandle(pi.Thread)
	return pi.Process, nil
}

// updatePseudoConsoleAttr passes the pseudoconsole handle directly because its
// value is the handle itself rather than a pointer (avoiding go vet unsafeptr warnings).
func updatePseudoConsoleAttr(list *windows.ProcThreadAttributeList, hpc windows.Handle) error {
	r1, _, e1 := procUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(list)),
		0,
		windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
		uintptr(hpc),
		unsafe.Sizeof(hpc),
		0,
		0,
	)
	if r1 == 0 {
		return e1
	}
	return nil
}

const (
	// Cap ConPTY dimensions to prevent oversized client window-change requests
	// from causing conhost.exe to allocate gigabytes of screen buffer memory.
	maxConPTYWidth  = 1024
	maxConPTYHeight = 512
)

func clampConPTYCoord(v, fallback, maxVal int) int16 {
	if v <= 0 {
		v = fallback
	}
	if v > maxVal {
		v = maxVal
	}
	return int16(v)
}

// Read reads terminal output produced by the attached process.
func (c *conPTY) Read(p []byte) (int, error) {
	return c.outRead.Read(p)
}

// Write sends terminal input to the attached process.
func (c *conPTY) Write(p []byte) (int, error) {
	return c.inWrite.Write(p)
}

// Resize updates the pseudoconsole dimensions. It is a no-op after CloseConsole.
func (c *conPTY) Resize(width, height int) error {
	if width <= 0 || height <= 0 {
		return nil
	}
	coord := windows.Coord{
		X: clampConPTYCoord(width, 1, maxConPTYWidth),
		Y: clampConPTYCoord(height, 1, maxConPTYHeight),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	return windows.ResizePseudoConsole(c.hpc, coord)
}

// WaitExitCode waits for the attached process to exit and returns its exit code.
func (c *conPTY) WaitExitCode() (int, error) {
	if _, err := windows.WaitForSingleObject(c.proc, windows.INFINITE); err != nil {
		return 0, err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(c.proc, &code); err != nil {
		return 0, err
	}
	return int(code), nil
}

// Terminate forcefully terminates the attached process and closes the pseudoconsole.
func (c *conPTY) Terminate() {
	c.mu.Lock()
	if !c.procClosed {
		_ = windows.TerminateProcess(c.proc, 1)
	}
	c.mu.Unlock()
	c.CloseConsole()
}

// CloseConsole closes the pseudoconsole handle without closing pipes or the process handle.
func (c *conPTY) CloseConsole() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		windows.ClosePseudoConsole(c.hpc)
		c.closed = true
	}
}

// Close releases the pseudoconsole, pipes, and process handle.
func (c *conPTY) Close() {
	c.CloseConsole()
	_ = c.inWrite.Close()
	_ = c.outRead.Close()

	c.mu.Lock()
	if !c.procClosed {
		c.procClosed = true
		_ = windows.CloseHandle(c.proc)
	}
	c.mu.Unlock()
}

// windowsEnvBlock builds a sorted, UTF-16, NUL-separated, double-NUL-terminated
// environment block for CreateProcess, deduplicating keys case-insensitively (last wins).
func windowsEnvBlock(env []string) (*uint16, error) {
	type envEntry struct {
		upperKey string
		kv       string
	}
	seen := make(map[string]int)
	var list []envEntry
	for _, kv := range env {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			continue
		}
		uk := strings.ToUpper(k)
		if i, dup := seen[uk]; dup {
			list[i].kv = kv
		} else {
			seen[uk] = len(list)
			list = append(list, envEntry{upperKey: uk, kv: kv})
		}
	}
	if len(list) == 0 {
		block := []uint16{0, 0}
		return &block[0], nil
	}
	// MSDN requires the CreateProcess environment block to be sorted case-insensitively by name.
	slices.SortFunc(list, func(a, b envEntry) int {
		return strings.Compare(a.upperKey, b.upperKey)
	})

	var block []uint16
	for _, entry := range list {
		u, err := windows.UTF16FromString(entry.kv)
		if err != nil {
			return nil, err
		}
		block = append(block, u...)
	}
	block = append(block, 0)
	return &block[0], nil
}
