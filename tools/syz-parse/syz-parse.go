// Copied from google/syzkaller/tools/syz-parse/syz-parse.go
package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}

	file := os.Args[1]

	kernelSrc := ""
	if len(os.Args) > 2 {
		kernelSrc = os.Args[2]
	}

	parseReport(file, kernelSrc)
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "  syz-parse <CRASH.log> [<kernel src>]\n")
	os.Exit(1)
}

func parseReport(file, kernelSrc string) {
	log, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	cfg := &mgrconfig.Config{
		TargetOS:   "linux",
		TargetArch: "amd64",
		KernelSrc:  kernelSrc,
	}
	reporter, err := report.NewReporter(cfg)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Tweak log here to get better reporting from syzkaller/pkg/report
	log = bytes.Replace(log, []byte("QDF BUG in"), []byte("BUG: QDF"), -1)
	log = bytes.Replace(log, []byte("DEBUG"), []byte("debug"), -1)
	log = bytes.Replace(log, []byte("WARNING"), []byte("warning"), -1)

	// Special case: watchdog bite caused by ol_tx_flow_pool_map_handler
	if bytes.Contains(log, []byte("Causing a watchdog bite")) && bytes.Contains(log, []byte("ol_tx_flow_pool_map_handler")) {
		log = bytes.Replace(log, []byte("Causing a watchdog bite"), []byte("BUG: ol_tx_flow_pool_map_handler (watchdog bite)"), -1)
	}

	rep := reporter.Parse(log)
	if rep == nil {
		fmt.Printf("Couldn't find any reports\n")
		return
	}
	fmt.Printf("=======\n")
	fmt.Printf("Title: %v\n", rep.Title)
	fmt.Printf("Corrupted: %v\n", rep.Corrupted)
	fmt.Printf("Report:\n")
	logStartPos := bytes.LastIndex(log, []byte("kfuz_hwiotrace_init"))
	logEndPos := rep.StartPos - 1
	if logStartPos > -1 && logStartPos < logEndPos {
		fmt.Printf("... %s\n", string(log[logStartPos:logEndPos]))
	}
	fmt.Printf("%s\n", string(log[rep.StartPos:rep.EndPos]))
}
