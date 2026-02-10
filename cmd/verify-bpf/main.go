//go:build linux && bpfembed

package main

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed bpf/*.bpf.o
var bpfObjects embed.FS

// program describes a BPF object file to verify.
type program struct {
	file string
	desc string
}

var programs = []program{
	{"bpf/dhcp_fastpath.bpf.o", "XDP DHCP fast path"},
	{"bpf/qos_ratelimit.bpf.o", "TC QoS rate limiting"},
	{"bpf/nat44.bpf.o", "NAT44/CGNAT"},
	{"bpf/antispoof.bpf.o", "TC anti-spoofing"},
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: failed to remove memlock rlimit: %v\n", err)
	}

	var failed []string

	for _, p := range programs {
		if err := verify(p); err != nil {
			fmt.Printf("FAIL: %s (%s)\n  %v\n", p.file, p.desc, err)
			failed = append(failed, p.file)
		} else {
			fmt.Printf("PASS: %s (%s)\n", p.file, p.desc)
		}
	}

	fmt.Println()
	fmt.Printf("%d/%d programs passed kernel verification\n", len(programs)-len(failed), len(programs))

	if len(failed) > 0 {
		fmt.Printf("FAILED: %s\n", strings.Join(failed, ", "))
		os.Exit(1)
	}
}

func verify(p program) error {
	data, err := bpfObjects.ReadFile(p.file)
	if err != nil {
		return fmt.Errorf("reading embedded object: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("loading collection spec: %w", err)
	}

	// Shrink all maps to minimum size. The verifier only needs valid map FDs,
	// not production-sized maps. This avoids ENOSPC from memory cgroup limits.
	for _, m := range spec.Maps {
		switch m.Type {
		case ebpf.RingBuf:
			// Ring buffers require page-aligned power-of-2 size.
			m.MaxEntries = 4096
		default:
			if m.MaxEntries > 1 {
				m.MaxEntries = 1
			}
		}
	}

	// Load with default log settings. The library automatically retries with
	// verifier log capture on failure, keeping memory usage low on success.
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		// Try to extract verifier log from the error.
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// Print the cause first (the actual rejection reason).
			fmt.Fprintf(os.Stderr, "  cause: %s\n", ve.Cause)

			// Filter log to non-trace lines for readability, fall back to tail.
			var meaningful []string
			for _, line := range ve.Log {
				if strings.HasPrefix(line, "mark_precise") ||
					strings.HasPrefix(line, "propagating") ||
					strings.HasPrefix(line, "parent ") {
					continue
				}
				meaningful = append(meaningful, line)
			}
			if len(meaningful) > 40 {
				meaningful = meaningful[len(meaningful)-40:]
			}
			return fmt.Errorf("verifier rejected program:\n%s", strings.Join(meaningful, "\n"))
		}
		return fmt.Errorf("loading collection: %w", err)
	}
	coll.Close()
	return nil
}
