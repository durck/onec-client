package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"onec"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	batchMaxFile     = 16 << 20
	batchMaxLines    = 10000
	batchMaxAttempts = 100000
)

// Secrets have no public fields or string representation. Go strings cannot
// guarantee erasure; this command does not persist or log their contents.
type batchInputs struct {
	mode             string
	users, passwords []string
}

func (batchInputs) String() string     { return "batch credentials (redacted)" }
func (b batchInputs) GoString() string { return b.String() }

func (b batchInputs) validate(limit int) (int, error) {
	if len(b.users) == 0 || len(b.users) > batchMaxLines || len(b.passwords) == 0 || len(b.passwords) > batchMaxLines {
		return 0, errors.New("batch requires 1..10000 user and password records")
	}
	if limit < 1 || limit > batchMaxAttempts {
		return 0, errors.New("--max-attempts must be between 1 and 100000")
	}
	count := len(b.users)
	switch b.mode {
	case "shared":
		if len(b.passwords) != 1 {
			return 0, errors.New("shared mode requires exactly one password record")
		}
	case "paired":
		if len(b.users) != len(b.passwords) {
			return 0, errors.New("paired mode requires equal user and password record counts")
		}
	case "matrix":
		count *= len(b.passwords)
	default:
		return 0, errors.New("--mode must be shared, paired or matrix")
	}
	if count > limit {
		return 0, fmt.Errorf("planned %d attempts exceeds --max-attempts %d", count, limit)
	}
	return count, nil
}

func (b batchInputs) at(index int, method onec.AuthMethod) (onec.Credentials, int, int) {
	u, p := index, 0
	if b.mode == "paired" {
		p = index
	}
	if b.mode == "matrix" {
		u, p = index/len(b.passwords), index%len(b.passwords)
	}
	return onec.Credentials{Method: method, Username: b.users[u], Password: b.passwords[p]}, u + 1, p + 1
}

func readBatchLines(r io.Reader, kind string) ([]string, error) {
	raw, err := io.ReadAll(io.LimitReader(r, batchMaxFile+1))
	defer clear(raw)
	if err != nil || len(raw) > batchMaxFile {
		return nil, fmt.Errorf("%s input read failed or exceeds 16 MiB", kind)
	}
	raw = bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})
	if len(raw) == 0 || !utf8.Valid(raw) {
		return nil, fmt.Errorf("%s input must be nonempty UTF-8", kind)
	}
	records := bytes.Count(raw, []byte("\n"))
	if raw[len(raw)-1] != '\n' {
		records++
	}
	if records > batchMaxLines {
		return nil, fmt.Errorf("%s input exceeds 10000 records", kind)
	}
	lines := bytes.Split(raw, []byte("\n"))
	if len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	result := make([]string, 0, len(lines))
	seen := map[string]bool{}
	for i, line := range lines {
		// Remove CR only when it belongs to a CRLF terminator.
		if i < len(lines)-1 || raw[len(raw)-1] == '\n' {
			line = bytes.TrimSuffix(line, []byte("\r"))
		}
		valid := len(line) <= 4096 && !bytes.ContainsAny(line, "\x00\x08\r\n")
		if kind == "users" {
			valid = valid && len(line) > 0 && utf8.RuneCount(line) <= 256
			for _, ch := range string(line) {
				if unicode.IsControl(ch) {
					valid = false
				}
			}
		}
		if !valid {
			return nil, fmt.Errorf("invalid %s record at line %d", kind, i+1)
		}
		value := string(line)
		if kind == "users" {
			key := strings.ToUpper(value)
			if seen[key] {
				return nil, fmt.Errorf("duplicate user record at line %d", i+1)
			}
			seen[key] = true
		}
		result = append(result, value)
	}
	return result, nil
}

func loadBatchLines(path, kind string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s file", kind)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > batchMaxFile {
		return nil, fmt.Errorf("%s input must be a regular file of at most 16 MiB", kind)
	}
	return readBatchLines(f, kind)
}

type batchSession interface {
	Login(context.Context, onec.Credentials) error
	Close() error
	Stats() onec.Stats
}
type batchDial func(context.Context, onec.Config) (batchSession, error)

type batchAttempt struct {
	Event              string `json:"event"`
	Attempt            int    `json:"attempt"`
	Worker             int    `json:"worker"`
	ConnectionID       int    `json:"connection_id"`
	ConnectionReused   bool   `json:"connection_reused"`
	ConnectionRetained bool   `json:"connection_retained"`
	UserLine           int    `json:"user_line"`
	PasswordLine       int    `json:"password_line"`
	Username           string `json:"username"`
	Status             string `json:"status"`
	HTTPStatus         int    `json:"http_status,omitempty"`
	LoginAttempted     bool   `json:"login_attempted"`
	LoginConfirmed     bool   `json:"login_confirmed"`
	LogoutConfirmed    bool   `json:"logout_confirmed"`
	ContextReleased    bool   `json:"context_released"`
	SecurityClosed     bool   `json:"security_closed"`
	ConnectionClosed   bool   `json:"connection_closed"`
	CleanupError       bool   `json:"cleanup_error"`
	DurationMS         int64  `json:"duration_ms"`
}
type batchSummary struct {
	Event             string `json:"event"`
	Planned           int    `json:"planned"`
	Started           int    `json:"started"`
	Recorded          int    `json:"recorded"`
	ConnectionsOpened int    `json:"connections_opened"`
	ConnectionsClosed int    `json:"connections_closed"`
	CleanupErrors     int    `json:"cleanup_errors"`
	Accepted          int    `json:"accepted"`
	NotAccepted       int    `json:"not_accepted"`
	Errors            int    `json:"errors"`
	Completed         bool   `json:"completed"`
	StoppedReason     string `json:"stopped_reason,omitempty"`
}

func batchCSVName(name string) string {
	trimmed := strings.TrimLeft(name, " ")
	if len(trimmed) > 0 && strings.ContainsAny(trimmed[:1], "=+-@") {
		return "'" + name
	}
	return name
}

// Authentication refusals are not definitive evidence of a wrong password.
// All other failures stop the batch; no alternate method, retry or backoff.
func batchLoginStatus(err error) (string, int, bool) {
	if err == nil {
		return "accepted", 0, true
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled", 0, false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout", 0, false
	}
	var ne net.Error
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return "timeout", 0, false
		}
		return "network_error", 0, false
	}
	var status *onec.StatusError
	if errors.As(err, &status) {
		if (status.Operation == "login" || status.Operation == "secure login") && (status.Status == 401 || status.Status == 402) {
			return "not_accepted", status.Status, true
		}
		if status.Status == 403 || status.Status == 423 || status.Status == 429 {
			return "policy_or_limit", status.Status, false
		}
		return "unexpected_http_status", status.Status, false
	}
	return "protocol_or_io_error", 0, false
}

func executeLoginBatch(ctx context.Context, cfg onec.Config, method onec.AuthMethod, input batchInputs,
	interval time.Duration, emit func(batchAttempt) error, dial batchDial, opts ...batchExecutionOptions) (batchSummary, error) {
	options := batchExecutionOptions{workers: 1}
	if len(opts) > 0 {
		options = opts[0]
	}
	return executeLoginPool(ctx, cfg, method, input, interval, emit, dial, options)
}

func runLoginBatch(args []string, out, diagnostic io.Writer) (resultErr error) {
	flags, common := newCommandFlags("onec login-batch", diagnostic)
	common.auth = ""
	flags.Lookup("auth").DefValue = ""
	flags.Lookup("timeout").Usage = "timeout for each dial/login attempt; cleanup has its own timeout"
	flags.Lookup("password-stdin").Usage = "read the shared password from stdin; shared mode only"
	var mode, usersPath, passwordsPath, reportPath, format, connectionMode string
	var interval time.Duration
	var limit, workers int
	flags.StringVar(&mode, "mode", "", "shared, paired (matching lines), or matrix (all combinations); required")
	flags.StringVar(&usersPath, "users-file", "", "UTF-8 usernames, one per line; required")
	flags.StringVar(&passwordsPath, "passwords-file", "", "UTF-8 passwords, one per line; shared mode requires one line")
	flags.StringVar(&reportPath, "report-file", "", "create a new report file; existing files are never overwritten")
	flags.StringVar(&format, "format", "jsonl", "report format: jsonl or csv")
	flags.DurationVar(&interval, "interval", time.Second, "global dispatch spacing; with one worker, pause after each attempt")
	flags.IntVar(&limit, "max-attempts", 1000, "maximum planned attempts, 1..100000")
	flags.IntVar(&workers, "workers", 1, "maximum concurrent connections, 1..16")
	flags.StringVar(&connectionMode, "connection-mode", "fresh", "fresh or reuse-refused (legacy only, retain after a clean refusal)")
	if help, err := parseCommandFlags(flags, args); help || err != nil {
		return err
	}
	if mode != "shared" && mode != "paired" && mode != "matrix" {
		return errors.New("explicit --mode shared|paired|matrix is required")
	}
	if common.auth != "legacy" && common.auth != "v1" && common.auth != "v2" && common.auth != "v3" {
		return errors.New("batch requires explicit --auth legacy|v1|v2|v3; Windows identity cannot select arbitrary infobase users")
	}
	if common.user != "" || common.ticketFile != "" || common.kerberosSPN != "" || common.kdc != "" ||
		common.ntlm != "" || common.ntlmDomain != "" || common.ntlmUser != "" || common.ntlmSecretStdin {
		return errors.New("batch uses infobase usernames/passwords; single-user and explicit OS-credential flags are excluded")
	}
	if usersPath == "" || (mode != "shared" && passwordsPath == "") ||
		(common.passwordStdin && (mode != "shared" || passwordsPath != "")) {
		return errors.New("provide --users-file and a password source compatible with the selected mode")
	}
	if format != "jsonl" && format != "csv" {
		return errors.New("--format must be jsonl or csv")
	}
	if interval < 0 || interval > time.Hour {
		return errors.New("--interval must be between 0 and 1h")
	}
	if workers < 1 || workers > 16 {
		return errors.New("--workers must be between 1 and 16")
	}
	if connectionMode != "fresh" && connectionMode != "reuse-refused" {
		return errors.New("--connection-mode must be fresh or reuse-refused")
	}
	if connectionMode == "reuse-refused" && common.auth != "legacy" {
		return errors.New("connection reuse is currently supported only with --auth legacy")
	}
	configOptions := *common
	configOptions.passwordStdin = false
	cfg, err := configOptions.config(true)
	if err != nil {
		return err
	}
	users, err := loadBatchLines(usersPath, "users")
	if err != nil {
		return err
	}
	passwords := []string{""} // Placeholder for shared input, never used to connect.
	if passwordsPath != "" {
		passwords, err = loadBatchLines(passwordsPath, "passwords")
		if err != nil {
			return err
		}
	}
	input := batchInputs{mode: mode, users: users, passwords: passwords}
	defer func() { clear(input.passwords) }()
	count, err := input.validate(limit)
	if err != nil {
		return err
	}
	plan := common.preview("login-batch", cfg)
	plan["event"], plan["batch_mode"] = "plan", mode
	plan["users"], plan["password_records"], plan["attempts"] = len(users), len(passwords), count
	plan["interval"], plan["report_format"] = interval.String(), format
	plan["workers"], plan["connection_mode"] = workers, connectionMode
	plan["password_file_read"], plan["password_input_required"] = passwordsPath != "", passwordsPath == ""
	plan["account_change_planned"], plan["business_calls_planned"] = false, false
	if !common.apply {
		return writePreview(out, plan)
	}

	// Establish the report destination before prompting or opening a connection.
	destination := out
	if reportPath != "" {
		file, err := os.OpenFile(reportPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return errors.New("cannot create new report file; choose a nonexistent writable path")
		}
		defer func() {
			if e := file.Close(); e != nil {
				resultErr = errors.Join(resultErr, errors.New("report close failed"))
			}
		}()
		destination = file
	}
	if passwordsPath == "" {
		var parsed []string
		var err error
		if common.passwordStdin {
			parsed, err = readBatchLines(os.Stdin, "passwords")
		} else {
			promptOptions := *common
			promptOptions.user = users[0]
			credential, promptErr := promptOptions.credentials(cfg, diagnostic)
			if promptErr != nil {
				return errors.New("could not read shared password; use a terminal, --password-stdin or a one-line --passwords-file")
			}
			// An explicitly empty hidden password is one record.
			parsed, err = readBatchLines(strings.NewReader(credential.Password+"\n"), "passwords")
			credential = onec.Credentials{}
		}
		if err != nil || len(parsed) != 1 {
			return errors.New("shared password must be one valid line")
		}
		input.passwords = parsed
	}
	plan["mode"] = "apply"
	plan["password_input_required"] = false
	encoder := json.NewEncoder(destination)
	csvOut := csv.NewWriter(destination)
	if format == "jsonl" {
		if err := encoder.Encode(plan); err != nil {
			return errors.New("cannot write batch plan")
		}
	} else {
		if err := csvOut.Write([]string{"attempt", "user_line", "password_line", "username", "status", "http_status", "login_attempted", "login_confirmed", "logout_confirmed", "context_released", "security_closed", "connection_closed", "cleanup_error", "duration_ms", "event", "worker", "connection_id", "connection_reused", "connection_retained"}); err != nil {
			return errors.New("cannot write report header")
		}
		csvOut.Flush()
		if csvOut.Error() != nil {
			return errors.New("cannot write report header")
		}
	}
	emit := func(r batchAttempt) error {
		if format == "jsonl" {
			return encoder.Encode(r)
		}
		name := batchCSVName(r.Username)
		err := csvOut.Write([]string{strconv.Itoa(r.Attempt), strconv.Itoa(r.UserLine), strconv.Itoa(r.PasswordLine),
			name, r.Status, strconv.Itoa(r.HTTPStatus), strconv.FormatBool(r.LoginAttempted), strconv.FormatBool(r.LoginConfirmed),
			strconv.FormatBool(r.LogoutConfirmed), strconv.FormatBool(r.ContextReleased), strconv.FormatBool(r.SecurityClosed),
			strconv.FormatBool(r.ConnectionClosed), strconv.FormatBool(r.CleanupError), strconv.FormatInt(r.DurationMS, 10),
			r.Event, strconv.Itoa(r.Worker), strconv.Itoa(r.ConnectionID), strconv.FormatBool(r.ConnectionReused), strconv.FormatBool(r.ConnectionRetained)})
		csvOut.Flush()
		return errors.Join(err, csvOut.Error())
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	summary, runErr := executeLoginBatch(ctx, cfg, onec.AuthMethod(common.auth), input, interval, emit,
		func(ctx context.Context, cfg onec.Config) (batchSession, error) {
			client, err := onec.Dial(ctx, cfg)
			if err != nil {
				return nil, err
			}
			return client, nil
		}, batchExecutionOptions{workers: workers, reuse: connectionMode == "reuse-refused"})
	summaryOut := diagnostic
	if format == "jsonl" {
		summaryOut = destination
	}
	if err := json.NewEncoder(summaryOut).Encode(summary); err != nil {
		return errors.Join(runErr, errors.New("cannot write batch summary"))
	}
	return runErr
}
