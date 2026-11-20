package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"onec"
	"onec/internal/epfui"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"time"
)

func runEPFUI(args []string, out, diagnostic io.Writer) error {
	flags, common := newCommandFlags("onec epf ui", diagnostic)
	options := addEPFFlags(flags, "methods")
	duration := flags.Duration("duration", 20*time.Minute, "maximum UI session lifetime; closing a tab does not log out")
	port := flags.Int("port", 0, "local IPv4 loopback port; 0 selects a free port")
	language := flags.String("language", "ru", "form presentation language")
	interactive := flags.Bool("interactive", false, "enable scalar field edits and exported context functions when the form metadata matches the supported schema")
	if help, err := parseCommandFlags(flags, args); help || err != nil {
		return err
	}
	if *duration <= 0 || *duration > 8*time.Hour || *port < 0 || *port > 65535 {
		return errors.New("invalid UI duration or port")
	}
	cfg, err := common.config(true)
	if err != nil {
		return err
	}
	if cfg.Timeout > 5*time.Minute || !validUILanguage(*language) {
		return errors.New("UI requires a timeout at most 5m and an ASCII language tag up to 32 characters")
	}
	formOptions, _, err := options.validate("methods")
	if err != nil {
		return err
	}
	if !common.apply {
		preview := common.preview("ui", cfg)
		preview["command_group"] = "epf"
		preview["epf"], preview["upload"], preview["form"] = options.path, options.upload, formOptions.Name
		preview["listen"] = net.JoinHostPort("127.0.0.1", strconv.Itoa(*port))
		preview["duration"], preview["language"] = duration.String(), *language
		preview["form_preview_read_only"], preview["client_bsl_execution"] = !*interactive, false
		preview["interactive"] = *interactive
		preview["invocation_on_user_action_only"] = true
		return writePreview(out, preview)
	}
	securityCleanup, err := common.prepareSecurity(&cfg, diagnostic)
	if err != nil {
		return err
	}
	defer securityCleanup()
	credentials, err := common.credentials(cfg, diagnostic)
	if err != nil {
		return err
	}
	epf, err := readEPF(options.path)
	if err != nil {
		return err
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	lifetime, cancel := context.WithTimeout(signalCtx, *duration)
	defer cancel()
	initial, doneInitial := context.WithTimeout(lifetime, cfg.Timeout)
	client, err := onec.Dial(initial, cfg)
	if err != nil {
		doneInitial()
		return err
	}
	var form onec.Form
	var ui *epfui.Server
	opened := false
	finish := func(operationErr error) error {
		cancel()
		var formErr error
		if opened {
			cleanupCtx, done := context.WithTimeout(context.Background(), 10*time.Second)
			formErr = client.CloseForm(cleanupCtx, form)
			done()
		}
		closeErr := client.Close()
		report := map[string]any{"mode": "apply", "command_group": "epf", "operation": "ui", "success": operationErr == nil && formErr == nil && closeErr == nil, "form_opened": opened, "form_close_confirmed": opened && formErr == nil, "stats": client.Stats()}
		if ui != nil {
			report["ui"] = ui.Stats()
			report["lifecycle_success"] = operationErr == nil && formErr == nil && closeErr == nil
			report["success"] = operationErr == nil && formErr == nil && closeErr == nil && ui.Stats().Unconfirmed == 0
		}
		writeErr := writeCommandReport(out, report)
		return errors.Join(operationErr, formErr, closeErr, writeErr)
	}
	defer client.Close()
	if err := client.Login(initial, credentials); err != nil {
		doneInitial()
		return finish(err)
	}
	credentials = onec.Credentials{}
	var processing onec.Processing
	if options.upload == "extmd" {
		processing, err = client.AttachProcessing(initial, epf, filepath.Base(options.path))
	} else {
		processing, err = client.UploadProcessing(initial, epf, filepath.Base(options.path))
	}
	if err != nil {
		doneInitial()
		return finish(err)
	}
	form, err = client.OpenFormWithOptions(initial, processing, formOptions)
	if err != nil {
		doneInitial()
		return finish(err)
	}
	opened = true
	var snapshot onec.FormSnapshot
	var contextState *onec.FormContextState
	if *interactive {
		state, prepareErr := client.PrepareFormContext(initial, form, onec.FormSnapshotOptions{Language: *language})
		err = prepareErr
		contextState, snapshot = &state, state.Snapshot
	} else {
		snapshot, err = client.SnapshotForm(initial, form, onec.FormSnapshotOptions{Language: *language})
	}
	if err != nil {
		doneInitial()
		return finish(err)
	}
	methods, err := client.FormMethods(initial, form)
	doneInitial()
	if err != nil {
		return finish(err)
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)))
	if err != nil {
		return finish(err)
	}
	defer listener.Close()
	uiOptions := epfui.Options{Origin: "http://" + listener.Addr().String(), Model: epfui.Model{Snapshot: snapshot, Methods: methods, Context: contextState}, Timeout: cfg.Timeout, Call: func(ctx context.Context, name string, args ...onec.Value) (onec.Value, error) {
		return client.CallNoContext(ctx, form, name, args...)
	}}
	if *interactive {
		uiOptions.CallContext = func(ctx context.Context, name string, revision uint64, changes []onec.FormParameter, args ...onec.Value) (onec.FormContextResult, error) {
			return client.CallWithContext(ctx, form, name, revision, changes, args...)
		}
	}
	ui, err = epfui.New(uiOptions)
	if err != nil {
		return finish(err)
	}
	server := &http.Server{Handler: ui, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: cfg.Timeout + 5*time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, BaseContext: func(net.Listener) context.Context { return lifetime }}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	if _, err := fmt.Fprintf(diagnostic, "EPF UI: %s\nSession lifetime: %s. Use the Close session button or Ctrl+C; closing the browser tab alone does not log out.\n", ui.URL(), *duration); err != nil {
		cancel()
		_ = server.Close()
		return finish(err)
	}
	var operationErr error
	select {
	case <-ui.Done():
	case <-lifetime.Done():
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			operationErr = err
		}
	}
	cancel()
	shutdownCtx, doneShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	shutdownErr := server.Shutdown(shutdownCtx)
	doneShutdown()
	if shutdownErr != nil {
		_ = server.Close()
	}
	return finish(errors.Join(operationErr, shutdownErr))
}

func validUILanguage(language string) bool {
	if len(language) > 32 {
		return false
	}
	for _, ch := range language {
		if ch != '-' && ch != '_' && !(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') {
			return false
		}
	}
	return true
}
