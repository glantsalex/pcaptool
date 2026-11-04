package cmd

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Diagnostics are INFO JSON on stderr, independent of progress/banner settings.
// They never contain environment variables, input contents, or shell hook bodies.
func infoDiagnostic(w io.Writer, event string, fields map[string]any) {
	fields["severity"] = "INFO"
	fields["component"] = "pcaptool"
	fields["event"] = event
	_ = json.NewEncoder(w).Encode(fields)
}

func logReceivedArguments(w io.Writer, argv []string) {
	args := append([]string{}, argv...)
	for i := 1; i < len(args); i++ {
		if args[i] == "--post-hook" && i+1 < len(args) {
			i++
			args[i] = "<redacted shell command>"
		} else if strings.HasPrefix(args[i], "--post-hook=") {
			args[i] = "--post-hook=<redacted shell command>"
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "<unavailable>"
	}
	infoDiagnostic(w, "invocation", map[string]any{"argv": args, "cwd": cwd})
}

func inputPathFields(role, path, status string) map[string]any {
	resolved := ""
	if path != "" {
		var err error
		resolved, err = filepath.Abs(path)
		if err != nil {
			resolved = "<unavailable>"
		}
	}
	return map[string]any{"role": role, "path": path, "resolved_path": resolved, "status": status}
}

// An access check confirms only readability, not parsing or validity. It does not
// change failure policy: the existing loaders remain responsible for validation.
func logInputAccess(w io.Writer, role, path string, directory, optional bool) {
	status := "readable"
	if path == "" {
		status = "not_configured"
	} else {
		st, err := os.Stat(path)
		if err != nil {
			status = "unreadable"
			if optional && os.IsNotExist(err) {
				status = "optional_absent"
			}
		} else if st.IsDir() != directory || (!directory && !st.Mode().IsRegular()) {
			// Do not open special files (notably FIFOs) just for diagnostics.
			status = "wrong_type"
		} else {
			f, err := os.Open(path)
			if err != nil {
				status = "unreadable"
			} else {
				_ = f.Close()
			}
		}
	}
	infoDiagnostic(w, "input_access", inputPathFields(role, path, status))
}

func logInputLoad(w io.Writer, role, path string, err error) {
	status := "loaded"
	if err != nil {
		status = "load_failed"
	}
	infoDiagnostic(w, "input_load", inputPathFields(role, path, status))
}

func logDNSExtractInputs(w io.Writer, opts DNSExtractOptions) {
	safe := opts
	safe.PostHooks = append([]string(nil), opts.PostHooks...)
	for i := range safe.PostHooks {
		safe.PostHooks[i] = "<redacted shell command>"
	}
	infoDiagnostic(w, "effective_options", map[string]any{"options": safe})
	logInputAccess(w, "read-dir", opts.ReadDir, true, false)
	logInputAccess(w, "fleet", opts.Fleet, false, false)
	logInputAccess(w, "dns-ip-file", opts.DNSIPFile, false, false)
	logInputAccess(w, "dns-normalization-rules", opts.DNSNormalizationRules, false, false)
	if strings.TrimSpace(opts.DNSIPFile) != "" {
		logInputAccess(w, "dns-topology-overlay", filepath.Join(filepath.Dir(opts.DNSIPFile), "topology-"+opts.NetID+".csv"), false, true)
	}
	if opts.DirectionRegistry != "" && opts.Fleet == "" {
		infoDiagnostic(w, "input_access", inputPathFields("direction-registry", opts.DirectionRegistry, "unused_without_fleet"))
	} else {
		logInputAccess(w, "direction-registry", opts.DirectionRegistry, false, false)
	}
}
