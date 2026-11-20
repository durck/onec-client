package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"onec"
	"onec/internal/valueinput"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// All external-processing flags and application operations belong to the epf
// group. Root commands only share connection, authentication and session setup.
type epfOptions struct {
	path, upload, form, method, expect string
	parameters, arguments              []string
	argumentsJSON                      string
	confirmOpen                        bool
}

func runEPF(args []string, out, diagnostic io.Writer) error {
	if len(args) > 0 && args[0] == "lifecycle" {
		return runEPFLifecycle(args[1:], out, diagnostic)
	}
	if len(args) > 0 && args[0] == "ui" {
		return runEPFUI(args[1:], out, diagnostic)
	}
	if len(args) == 0 || isHelp(args[0]) {
		printGroupHelp(out, "epf", "Work with the supported managed-form subset of external processing files.", []helpCommand{
			{"methods", "Discover server-method metadata"},
			{"modules", "Retrieve compiled client images without execution"},
			{"run", "Call a server function without context"},
			{"ui", "Open a local form and server-method workbench"},
			{"lifecycle", "Inspect saved form events offline"},
		})
		return nil
	}
	command := args[0]
	if command != "methods" && command != "run" && command != "modules" {
		return cliUsage(errors.New("unknown epf command; use onec epf --help"))
	}
	flags, common := newCommandFlags("onec epf "+command, diagnostic)
	options := addEPFFlags(flags, command)
	flags.BoolVar(&options.confirmOpen, "confirm-open", false, "explicitly accept this EPF's opening warning once; the platform may retain this decision")
	if help, err := parseCommandFlags(flags, args[1:]); help || err != nil {
		return err
	}
	cfg, err := common.config(true)
	if err != nil {
		return err
	}
	formOptions, arguments, err := options.validate(command)
	if err != nil {
		return err
	}
	if !common.apply {
		preview := common.preview(command, cfg)
		for key, value := range map[string]any{"command_group": "epf", "epf": options.path, "upload": options.upload, "form": formOptions.Name, "parameters": formOptions.Parameters, "method": options.method, "arguments": arguments, "expect": options.expect, "invocation_planned": command == "run", "form_close_planned": true} {
			preview[key] = value
		}
		preview["confirm_open"] = options.confirmOpen
		return writePreview(out, preview)
	}
	cleanup, err := common.prepareSecurity(&cfg, diagnostic)
	if err != nil {
		return err
	}
	defer cleanup()
	credentials, err := common.credentials(cfg, diagnostic)
	if err != nil {
		return err
	}
	epf, err := readEPF(options.path)
	if err != nil {
		return err
	}
	fields := map[string]any{"command_group": "epf", "upload": options.upload, "form_close_confirmed": false}
	return executeCommand(cfg, command, fields, out, func(ctx context.Context, client *onec.Client) (any, error) {
		err := client.Login(ctx, credentials)
		credentials = onec.Credentials{}
		if err != nil {
			return nil, err
		}
		result, closed, err := options.execute(ctx, client, command, epf, formOptions, arguments)
		fields["form_close_confirmed"] = closed
		return result, err
	})
}

func addEPFFlags(f *flag.FlagSet, command string) *epfOptions {
	o := &epfOptions{}
	f.StringVar(&o.path, "epf", "", "EPF file path (required)")
	f.StringVar(&o.upload, "upload", "open-document", "EPF upload route: open-document or extmd")
	f.StringVar(&o.form, "form", "", "local form name; empty selects the default form")
	f.Func("param", "String form-opening parameter name=value; repeatable", func(value string) error {
		o.parameters = append(o.parameters, value)
		return nil
	})
	if command == "run" {
		f.StringVar(&o.method, "method", "", "server no-context form function (required)")
		f.StringVar(&o.expect, "expect", "", "expected string result; mismatch fails")
		f.StringVar(&o.argumentsJSON, "args-json", "", "JSON argument array: strings or typed number/boolean/date objects; excludes --arg")
		f.Func("arg", "String function argument; repeatable", func(value string) error {
			o.arguments = append(o.arguments, value)
			return nil
		})
	}
	return o
}

func (o *epfOptions) validate(command string) (onec.FormOptions, []onec.Value, error) {
	if o.upload != "open-document" && o.upload != "extmd" {
		return onec.FormOptions{}, nil, errors.New("--upload must be open-document or extmd")
	}
	if command == "run" && (o.path == "" || o.method == "") {
		return onec.FormOptions{}, nil, errors.New("epf run requires --epf and --method")
	}
	if (command == "methods" || command == "modules") && o.path == "" {
		return onec.FormOptions{}, nil, errors.New("EPF inspection requires --epf")
	}
	options, arguments, err := parseFormInputs(o.form, o.parameters, o.arguments)
	if err != nil {
		return options, nil, err
	}
	if o.argumentsJSON != "" {
		if len(o.arguments) != 0 {
			return options, nil, errors.New("--args-json excludes --arg")
		}
		arguments, err = valueinput.Arguments([]byte(o.argumentsJSON))
	}
	return options, arguments, err
}

func readEPF(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open EPF: %w", err)
	}
	defer file.Close()
	epf, err := io.ReadAll(io.LimitReader(file, onec.MaxEPF+1))
	if err != nil || len(epf) == 0 || len(epf) > onec.MaxEPF {
		return nil, errors.New("EPF read error or unsupported size")
	}
	return epf, nil
}

func (o *epfOptions) execute(ctx context.Context, client *onec.Client, command string, epf []byte, options onec.FormOptions, arguments []onec.Value) (result any, formClosed bool, err error) {
	upload := func() (onec.Processing, error) {
		if o.upload == "extmd" {
			return client.AttachProcessing(ctx, epf, filepath.Base(o.path))
		}
		return client.UploadProcessing(ctx, epf, filepath.Base(o.path))
	}
	processing, err := upload()
	var challenge *onec.ProcessingSecurityError
	if o.confirmOpen && errors.As(err, &challenge) {
		if err = client.ConfirmProcessingSecurity(ctx, challenge); err == nil {
			processing, err = upload()
		}
	}
	if err != nil {
		return nil, false, err
	}
	form, err := client.OpenFormWithOptions(ctx, processing, options)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		closeErr := client.CloseForm(cleanupCtx, form)
		formClosed = closeErr == nil
		err = errors.Join(err, closeErr)
	}()
	if command == "methods" {
		result, err = client.FormMethods(ctx, form)
		return result, false, err
	}
	if command == "modules" {
		result, err = client.FormModuleImages(ctx, form)
		return result, false, err
	}
	value, err := client.CallNoContext(ctx, form, o.method, arguments...)
	if err == nil && o.expect != "" {
		actual, ok := value.Value.(string)
		if !ok || actual != o.expect {
			err = errors.New("external processing result differs from --expect")
		}
	}
	return value, false, err
}

// CLI values are Strings. Split only at the first equals sign so empty values
// and values containing additional equals signs retain their meaning.
func parseFormInputs(name string, rawParameters, rawArguments []string) (onec.FormOptions, []onec.Value, error) {
	options := onec.FormOptions{Name: name}
	if name != "" && !validFormIdentifier(name) {
		return options, nil, errors.New("--form requires a local form identifier")
	}
	if len(rawParameters) > 32 || len(rawArguments) > 32 {
		return options, nil, errors.New("at most 32 form parameters and 32 function arguments are supported")
	}
	names := map[string]bool{}
	for _, raw := range rawParameters {
		key, value, found := strings.Cut(raw, "=")
		canonical := strings.ToUpper(key)
		if !found || !validFormIdentifier(key) || names[canonical] {
			return options, nil, errors.New("--param requires name=value with distinct parameter identifiers")
		}
		if !validStringInput(value) {
			return options, nil, errors.New("--param value must be valid UTF-8 with at most 65536 characters")
		}
		names[canonical] = true
		options.Parameters = append(options.Parameters, onec.FormParameter{Name: key, Value: onec.StringValue(value)})
	}
	var arguments []onec.Value
	for _, value := range rawArguments {
		if !validStringInput(value) {
			return options, nil, errors.New("--arg value must be valid UTF-8 with at most 65536 characters")
		}
		arguments = append(arguments, onec.StringValue(value))
	}
	return options, arguments, nil
}

func validFormIdentifier(value string) bool {
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 255 {
		return false
	}
	for i, r := range value {
		if r != '_' && !unicode.IsLetter(r) && !(i > 0 && unicode.IsDigit(r)) {
			return false
		}
	}
	return true
}

func validStringInput(value string) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) <= 65536
}
