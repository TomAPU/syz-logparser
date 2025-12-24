// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/tool"
	_ "github.com/google/syzkaller/sys" // register targets
	"github.com/google/syzkaller/sys/targets"
)

var (
	flagOS     = flag.String("os", targets.Linux, "target OS of the log")
	flagArch   = flag.String("arch", runtime.GOARCH, "target architecture of the log")
	flagConfig = flag.String("config", "", "optional manager config to reuse parsing settings")
	flagJSON   = flag.Bool("json", false, "emit parsed crashes as JSON")
	flagAll    = flag.Bool("all", false, "parse all crash reports (default: only the first)")
)

type serializedReport struct {
	Title           string               `json:"title"`
	AltTitles       []string             `json:"alt_titles,omitempty"`
	Type            string               `json:"type"`
	Frame           string               `json:"frame,omitempty"`
	StartPos        int                  `json:"start_pos"`
	EndPos          int                  `json:"end_pos"`
	SkipPos         int                  `json:"skip_pos"`
	Suppressed      bool                 `json:"suppressed"`
	Corrupted       bool                 `json:"corrupted"`
	CorruptedReason string               `json:"corrupted_reason,omitempty"`
	Executor        *report.ExecutorInfo `json:"executor,omitempty"`
	Report          string               `json:"report"`
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: syz-logparser [flags] kernel_log_file\n")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}
	cfg, err := loadReporterConfig()
	if err != nil {
		tool.Failf("failed to load config: %v", err)
	}
	reporter, err := report.NewReporter(cfg)
	if err != nil {
		tool.Failf("failed to create reporter: %v", err)
	}
	logData, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		tool.Failf("failed to read log file: %v", err)
	}
	reports := parseReports(reporter, logData)
	if len(reports) == 0 {
		if *flagJSON {
			fmt.Fprintln(os.Stdout, "[]")
			return
		}
		fmt.Println("no crash reports found in log")
		if report.IsSuppressed(reporter, logData) {
			fmt.Println("note: log matched suppression patterns for this target")
		}
		return
	}
	if *flagJSON {
		emitJSON(reports)
		return
	}
	printHuman(reports)
}

func parseReports(reporter *report.Reporter, logData []byte) []*report.Report {
	if *flagAll {
		return report.ParseAll(reporter, logData)
	}
	if rep := reporter.Parse(logData); rep != nil {
		return []*report.Report{rep}
	}
	return nil
}

func loadReporterConfig() (*mgrconfig.Config, error) {
	cfg := mgrconfig.DefaultValues()
	if *flagConfig != "" {
		if err := config.LoadFile(*flagConfig, cfg); err != nil {
			return nil, err
		}
	}
	targetOS, targetVMArch, targetArch := *flagOS, *flagArch, *flagArch
	if cfg.RawTarget != "" {
		if parts := strings.Split(cfg.RawTarget, "/"); len(parts) >= 2 {
			targetOS = parts[0]
			targetVMArch = parts[1]
			targetArch = parts[len(parts)-1]
		}
	}
	sysTarget := targets.Get(targetOS, targetVMArch)
	if sysTarget == nil {
		return nil, fmt.Errorf("unknown target: %s/%s (supported: %v)", targetOS, targetVMArch, targets.List)
	}
	cfg.RawTarget = fmt.Sprintf("%s/%s", targetOS, targetVMArch)
	cfg.Derived.TargetOS = targetOS
	cfg.Derived.TargetArch = targetArch
	cfg.Derived.TargetVMArch = targetVMArch
	cfg.Derived.SysTarget = sysTarget
	cfg.CompleteKernelDirs()
	return cfg, nil
}

func emitJSON(reports []*report.Report) {
	out := make([]serializedReport, len(reports))
	for i, rep := range reports {
		out[i] = serializedReport{
			Title:           rep.Title,
			AltTitles:       rep.AltTitles,
			Type:            rep.Type.String(),
			Frame:           rep.Frame,
			StartPos:        rep.StartPos,
			EndPos:          rep.EndPos,
			SkipPos:         rep.SkipPos,
			Suppressed:      rep.Suppressed,
			Corrupted:       rep.Corrupted,
			CorruptedReason: rep.CorruptedReason,
			Executor:        rep.Executor,
			Report:          string(rep.Report),
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		tool.Fail(err)
	}
}

func printHuman(reports []*report.Report) {
	for idx, rep := range reports {
		fmt.Printf("Crash #%d\n", idx+1)
		fmt.Printf("Title: %s\n", rep.Title)
		fmt.Printf("Type: %s\n", rep.Type.String())
		if len(rep.AltTitles) > 0 {
			fmt.Printf("Alt titles: %s\n", strings.Join(rep.AltTitles, ", "))
		}
		if rep.Frame != "" {
			fmt.Printf("Frame: %s\n", rep.Frame)
		}
		fmt.Printf("Range: [%d, %d], next %d\n", rep.StartPos, rep.EndPos, rep.SkipPos)
		fmt.Printf("Suppressed: %v\n", rep.Suppressed)
		fmt.Printf("Corrupted: %v", rep.Corrupted)
		if rep.CorruptedReason != "" {
			fmt.Printf(" (%s)", rep.CorruptedReason)
		}
		fmt.Printf("\n\n")
		body := rep.Report
		if len(body) == 0 {
			fmt.Printf("(empty report body)\n")
		} else {
			if _, err := os.Stdout.Write(body); err != nil {
				tool.Fail(err)
			}
			if body[len(body)-1] != '\n' {
				fmt.Printf("\n")
			}
		}
		if idx+1 < len(reports) {
			fmt.Printf("\n---\n\n")
		}
	}
}
