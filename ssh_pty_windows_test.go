//go:build windows

package main

import (
	"io"
	"math"
	"os/exec"
	"strings"
	"testing"
	"time"
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
		p = (*uint16)(unsafe.Add(unsafe.Pointer(p), unsafe.Sizeof(uint16(0))))
	}
	return out
}

func TestClampConPTYCoord(t *testing.T) {
	cases := []struct {
		v, fallback, maxVal int
		want                int16
	}{
		{0, 80, maxConPTYWidth, 80},
		{-5, 24, maxConPTYHeight, 24},
		{120, 80, maxConPTYWidth, 120},
		{maxConPTYWidth, 80, maxConPTYWidth, maxConPTYWidth},
		{maxConPTYWidth + 500, 80, maxConPTYWidth, maxConPTYWidth},
		{math.MaxInt32, 24, maxConPTYHeight, maxConPTYHeight},
	}
	for _, tc := range cases {
		if got := clampConPTYCoord(tc.v, tc.fallback, tc.maxVal); got != tc.want {
			t.Fatalf("clampConPTYCoord(%d, %d, %d) = %d, want %d", tc.v, tc.fallback, tc.maxVal, got, tc.want)
		}
	}
}

func TestWindowsEnvBlock(t *testing.T) {
	ptr, err := windowsEnvBlock([]string{
		"invalid-no-equals",
		"=emptykey",
		"ZEBRA=1",
		"Path=C:\\old",
		"TERM=xterm",
		"alpha=first",
		"PATH=C:\\new",
		"term=xterm-256color",
	})
	if err != nil {
		t.Fatalf("windowsEnvBlock: %v", err)
	}
	got := decodeEnvBlock(ptr)
	want := []string{"alpha=first", "PATH=C:\\new", "term=xterm-256color", "ZEBRA=1"}
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

	t.Run("output and resize", func(t *testing.T) {
		cmd := exec.Command("cmd.exe", "/d", "/c", "echo hello-conpty")
		cp, err := startConPTY(cmd, 0, 0)
		if err != nil {
			t.Fatalf("startConPTY: %v", err)
		}
		defer cp.Close()

		if err := cp.Resize(100, 30); err != nil {
			t.Fatalf("Resize: %v", err)
		}
		// Oversized values must be clamped rather than overflowing int16.
		if err := cp.Resize(math.MaxInt32, math.MaxInt32); err != nil {
			t.Fatalf("Resize oversized: %v", err)
		}

		outCh := make(chan string, 1)
		go func() {
			b, _ := io.ReadAll(cp)
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
	})

	t.Run("non-zero exit code", func(t *testing.T) {
		cmd := exec.Command("cmd.exe", "/d", "/c", "exit 7")
		cp, err := startConPTY(cmd, 80, 24)
		if err != nil {
			t.Fatalf("startConPTY: %v", err)
		}
		defer cp.Close()

		outDone := make(chan struct{})
		go func() {
			defer close(outDone)
			_, _ = io.Copy(io.Discard, cp)
		}()

		code, err := cp.WaitExitCode()
		cp.CloseConsole()
		<-outDone

		if err != nil {
			t.Fatalf("WaitExitCode: %v", err)
		}
		if code != 7 {
			t.Fatalf("exit code = %d, want 7", code)
		}
	})
}

func TestConPTYInteractiveIO(t *testing.T) {
	if !conPTYAvailable() {
		t.Skip("ConPTY not available on this Windows version")
	}

	cmd := exec.Command("cmd.exe", "/d")
	cp, err := startConPTY(cmd, 80, 24)
	if err != nil {
		t.Fatalf("startConPTY: %v", err)
	}
	defer cp.Close()

	outCh := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(cp)
		outCh <- string(b)
	}()

	if _, err := io.WriteString(cp, "echo interactive-ok\r\nexit 0\r\n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}

	code, err := cp.WaitExitCode()
	cp.CloseConsole()
	out := <-outCh

	if err != nil {
		t.Fatalf("WaitExitCode: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (output=%q)", code, out)
	}
	if !strings.Contains(out, "interactive-ok") {
		t.Fatalf("expected output to contain %q, got %q", "interactive-ok", out)
	}
}

func TestConPTYTerminate(t *testing.T) {
	if !conPTYAvailable() {
		t.Skip("ConPTY not available on this Windows version")
	}

	cmd := exec.Command("cmd.exe", "/d", "/c", "ping -n 30 127.0.0.1 >nul")
	cp, err := startConPTY(cmd, 80, 24)
	if err != nil {
		t.Fatalf("startConPTY: %v", err)
	}
	defer cp.Close()

	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		_, _ = io.Copy(io.Discard, cp)
	}()

	waitCh := make(chan error, 1)
	go func() {
		_, waitErr := cp.WaitExitCode()
		waitCh <- waitErr
	}()

	time.Sleep(100 * time.Millisecond)
	cp.Terminate()

	select {
	case err := <-waitCh:
		if err != nil {
			t.Fatalf("WaitExitCode after Terminate: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WaitExitCode did not return promptly after Terminate")
	}

	select {
	case <-outDone:
	case <-time.After(5 * time.Second):
		t.Fatal("output drain did not finish promptly after Terminate")
	}
}
