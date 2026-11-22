//go:build windows

package main

import (
	"io"
	"os/exec"
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"
)

func decodeEnvBlock(ptr *uint16) []string {
	var out []string
	var cur []uint16
	p := ptr
	for {
		ch := *p
		if ch == 0 {
			if len(cur) == 0 {
				break
			}
			out = append(out, string(utf16.Decode(cur)))
			cur = cur[:0]
		} else {
			cur = append(cur, ch)
		}
		p = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + unsafe.Sizeof(uint16(0))))
	}
	return out
}

func TestWindowsEnvBlock(t *testing.T) {
	ptr, err := windowsEnvBlock([]string{
		"invalid-no-equals",
		"=emptykey",
		"Path=C:\\old",
		"TERM=xterm",
		"PATH=C:\\new",
		"term=xterm-256color",
	})
	if err != nil {
		t.Fatalf("windowsEnvBlock: %v", err)
	}
	got := decodeEnvBlock(ptr)
	want := []string{"PATH=C:\\new", "term=xterm-256color"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	emptyPtr, err := windowsEnvBlock(nil)
	if err != nil {
		t.Fatalf("windowsEnvBlock(nil): %v", err)
	}
	if gotEmpty := decodeEnvBlock(emptyPtr); len(gotEmpty) != 0 {
		t.Fatalf("expected empty block, got %v", gotEmpty)
	}
}

func TestStartConPTY(t *testing.T) {
	if !conPTYAvailable() {
		t.Skip("ConPTY not available on this Windows version")
	}

	cmd := exec.Command("cmd.exe", "/d", "/c", "echo hello-conpty")
	cp, err := startConPTY(cmd, 0, 0)
	if err != nil {
		t.Fatalf("startConPTY: %v", err)
	}
	defer cp.Close()

	if err := cp.Resize(100, 30); err != nil {
		t.Fatalf("Resize: %v", err)
	}

	outCh := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(cp.outRead)
		outCh <- string(b)
	}()

	code, err := cp.WaitExitCode()
	cp.CloseConsole()
	out := <-outCh

	if err != nil {
		t.Fatalf("WaitExitCode: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (output=%q)", code, out)
	}
	if !strings.Contains(out, "hello-conpty") {
		t.Fatalf("expected output to contain %q, got %q", "hello-conpty", out)
	}
}
