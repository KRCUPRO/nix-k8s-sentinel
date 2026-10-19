package main

import (
	"fmt"
	"os"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/report"
)

// runReportExport handles SARIF v2.1.0 and structured JSON report formatting and file persistence.
func runReportExport(cfg SentinelConfig, reportOpts report.ReportOptions, logErr func(string, ...any)) {
	if cfg.Format == "sarif" {
		sarifLog, err := report.BuildSARIFReport(reportOpts)
		if err != nil {
			logErr("[-] Failed to build SARIF report: %v\n", err)
			os.Exit(1)
		}

		if cfg.OutFile != "" {
			if err := report.WriteSARIFToFile(sarifLog, cfg.OutFile, true); err != nil {
				logErr("[-] Failed to write SARIF report to %s: %v\n", cfg.OutFile, err)
				os.Exit(1)
			}
			fmt.Printf("[+] SARIF v2.1.0 security report written to: %s (Total Findings: %d)\n", cfg.OutFile, len(sarifLog.Runs[0].Results))
		} else {
			data, err := report.FormatSARIF(sarifLog, true)
			if err != nil {
				logErr("[-] Failed to format SARIF report: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(string(data))
		}
		return
	}

	if cfg.Format == "json" {
		jsonReport, err := report.BuildJSONReport(reportOpts)
		if err != nil {
			logErr("[-] Failed to build JSON report: %v\n", err)
			os.Exit(1)
		}

		if cfg.OutFile != "" {
			if err := report.WriteJSONToFile(jsonReport, cfg.OutFile, true); err != nil {
				logErr("[-] Failed to write JSON report to %s: %v\n", cfg.OutFile, err)
				os.Exit(1)
			}
			fmt.Printf("[+] JSON security report written to: %s\n", cfg.OutFile)
		} else {
			data, err := report.FormatJSON(jsonReport, true)
			if err != nil {
				logErr("[-] Failed to format JSON report: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(string(data))
		}
		return
	}
}
