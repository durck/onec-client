package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"onec"
	"onec/wire"
	"os"
)

// This inspector is offline and has no connection or credential flags.
func runEPFLifecycle(args []string, out, diagnostic io.Writer) error {
	f := flag.NewFlagSet("onec epf lifecycle", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	input := f.String("elements", "", "strict JSON elements document, without the response envelope")
	f.Usage = func() {
		fmt.Fprintln(diagnostic, "Usage: onec epf lifecycle --elements elements.json\nOffline inspection of form-level event chains. No server connection or code execution.")
		f.SetOutput(diagnostic)
		printFlagGroups(f, diagnostic)
		f.SetOutput(io.Discard)
	}
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return cliUsage(errors.New("invalid lifecycle options; use onec epf lifecycle --help"))
	}
	if *input == "" || f.NArg() != 0 {
		return cliUsage(errors.New("lifecycle requires --elements and no positional arguments"))
	}
	file, err := os.Open(*input)
	if err != nil {
		return errors.New("cannot open lifecycle elements file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > wire.MaxFile {
		return errors.New("lifecycle input must be a regular file no larger than 512 KiB")
	}
	data, err := io.ReadAll(io.LimitReader(file, wire.MaxFile+1))
	if err != nil {
		return errors.New("cannot read lifecycle elements file")
	}
	plan, err := onec.InspectFormLifecycle(data)
	if err != nil {
		return err
	}
	if err := writeIndentedCommandReport(out, plan); err != nil {
		return errors.New("cannot write lifecycle report")
	}
	return nil
}
