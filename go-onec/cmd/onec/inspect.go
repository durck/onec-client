package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"onec/inspect"
	"os"
)

func runInspect(args []string, out, diagnostic io.Writer) error {
	f := flag.NewFlagSet("onec inspect", flag.ContinueOnError)
	// Flag parser errors may contain user input (including mistakenly supplied
	// credentials). Return a fixed message instead of forwarding that text.
	f.SetOutput(io.Discard)
	var input, format string
	var jsonOutput bool
	var options inspect.Options
	f.StringVar(&input, "input", "", "raw unidirectional reassembled TCP payload file")
	f.StringVar(&format, "format", "human", "human or json")
	f.BoolVar(&jsonOutput, "json", false, "write JSON (alias for --format json)")
	f.IntVar(&options.InputBytes, "max-input-bytes", inspect.MaxInputBytes, "input byte limit; maximum 67108864")
	f.IntVar(&options.RecordBytes, "max-record-bytes", 1024*1024, "decoded record limit; maximum 16777216")
	f.IntVar(&options.Atoms, "max-atoms", 100000, "atoms/values per record; maximum 250000")
	f.IntVar(&options.Events, "max-events", 4096, "retained event limit; maximum 16384")
	f.Usage = func() {
		fmt.Fprintln(diagnostic, "Usage: onec inspect [options] <tcp-payload-file>\nOffline, redacted inspection of one reassembled TCP direction. PCAP/PCAPNG and hex dumps require extraction first. No network access occurs.")
		f.SetOutput(diagnostic)
		printFlagGroups(f, diagnostic)
		f.SetOutput(io.Discard)
	}
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return cliUsage(errors.New("invalid inspect options; use onec inspect --help"))
	}
	if f.NArg() == 1 && input == "" {
		input = f.Arg(0)
	} else if f.NArg() != 0 {
		return errors.New("inspect requires exactly one input file")
	}
	if input == "" {
		return errors.New("inspect requires an input file")
	}
	if format != "human" && format != "json" {
		return errors.New("inspect format must be human or json")
	}
	if jsonOutput || wantsJSON(out) {
		format = "json"
	}
	if options.InputBytes < 1 || options.RecordBytes < 1 || options.Atoms < 1 || options.Events < 1 {
		return errors.New("inspect limits must be positive")
	}
	file, err := os.Open(input)
	if err != nil {
		return errors.New("cannot open inspect input file")
	}
	defer file.Close()
	report, err := inspect.Analyze(file, options)
	if err != nil {
		return err
	}
	if format == "json" {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(report)
	} else {
		err = inspect.WriteText(out, report)
	}
	if err != nil {
		return errors.New("cannot write inspection report")
	}
	if !report.Complete {
		return errors.New("inspection incomplete; see redacted report issues")
	}
	return nil
}
