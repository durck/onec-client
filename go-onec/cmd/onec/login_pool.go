package main

import (
	"context"
	"errors"
	"onec"
	"sync"
	"time"
)

type batchExecutionOptions struct {
	workers int
	reuse   bool
}

type batchReusableSession interface {
	CanRetryLogin() bool
	RetryLogin(context.Context, onec.Credentials) error
}

type batchStop string

func (s batchStop) Error() string { return string(s) }

type batchResult struct {
	record *batchAttempt
	done   bool // Completes a dispatched attempt, including cancellation before Dial.
	opened bool
}

// A worker owns its connection exclusively. Report writes belong to the
// coordinator. Every dispatched job produces a result, including on cancellation.
func batchWorker(ctx context.Context, cancel context.CancelCauseFunc, worker int, cfg onec.Config,
	method onec.AuthMethod, input batchInputs, reuse bool, jobs <-chan int, results chan<- batchResult, dial batchDial) {
	var client batchSession
	var connectionID int
	closeClient := func(record *batchAttempt) {
		cleanupErr := client.Close() // Independent cleanup deadline, even after cancellation.
		stats := client.Stats()
		record.LogoutConfirmed, record.ContextReleased = stats.LogoutConfirmed, stats.ContextReleased
		record.SecurityClosed, record.ConnectionClosed = stats.SecurityClosed, stats.Closed
		record.CleanupError = cleanupErr != nil || !stats.ContextReleased || !stats.SecurityClosed || !stats.Closed ||
			(stats.Authenticated && !stats.LogoutConfirmed)
		client = nil
		if record.CleanupError {
			record.Status = "cleanup_failed"
			cancel(batchStop(record.Status))
		}
	}
	defer func() {
		if client != nil {
			started := time.Now()
			r := batchAttempt{Event: "connection", Worker: worker, ConnectionID: connectionID, Status: "closed"}
			closeClient(&r)
			r.DurationMS = time.Since(started).Milliseconds()
			results <- batchResult{record: &r}
		}
	}()
	for index := range jobs {
		if ctx.Err() != nil {
			results <- batchResult{done: true}
			continue
		}
		started := time.Now()
		credentials, userLine, passwordLine := input.at(index, method)
		r := batchAttempt{Event: "attempt", Attempt: index + 1, Worker: worker,
			UserLine: userLine, PasswordLine: passwordLine, Username: credentials.Username}
		attemptCtx, stopAttempt := context.WithTimeout(ctx, cfg.Timeout)
		reused, opened := client != nil, false
		var dialErr error
		if client == nil {
			connectionID = index + 1 // Unique within the batch, without shared mutable state.
			client, dialErr = dial(attemptCtx, cfg)
			opened = client != nil && dialErr == nil
		}
		r.ConnectionID, r.ConnectionReused = connectionID, reused
		proceed := false
		if dialErr != nil || client == nil {
			r.Status = "connection_failed"
		} else {
			r.LoginAttempted = true
			var loginErr error
			if reused {
				retry, ok := client.(batchReusableSession)
				if !ok {
					loginErr = errors.New("session cannot retry login")
				} else {
					loginErr = retry.RetryLogin(attemptCtx, credentials)
				}
			} else {
				loginErr = client.Login(attemptCtx, credentials)
			}
			r.Status, r.HTTPStatus, proceed = batchLoginStatus(loginErr)
			r.LoginConfirmed = loginErr == nil && client.Stats().Authenticated
			if loginErr == nil && !r.LoginConfirmed {
				r.Status, proceed = "unconfirmed_login", false
			}
		}
		credentials = onec.Credentials{}
		stopAttempt()
		// Stop dispatch before potentially slow cleanup of the failing connection.
		if !proceed {
			cancel(batchStop(r.Status))
		}
		if client != nil {
			retry, ok := client.(batchReusableSession)
			keep := reuse && proceed && r.Status == "not_accepted" && ok && retry.CanRetryLogin() && ctx.Err() == nil
			if keep {
				r.ConnectionRetained = true
			} else {
				closeClient(&r)
			}
		}
		r.DurationMS = time.Since(started).Milliseconds()
		results <- batchResult{record: &r, done: true, opened: opened}
	}
}

func executeLoginPool(ctx context.Context, cfg onec.Config, method onec.AuthMethod, input batchInputs,
	interval time.Duration, emit func(batchAttempt) error, dial batchDial, options batchExecutionOptions) (batchSummary, error) {
	total, err := input.validate(batchMaxAttempts)
	summary := batchSummary{Event: "summary", Planned: total}
	if err != nil {
		return summary, err
	}
	if options.workers < 1 || options.workers > 16 {
		return summary, errors.New("--workers must be between 1 and 16")
	}
	if interval < 0 || interval > time.Hour || cfg.Timeout <= 0 {
		return summary, errors.New("invalid batch interval or timeout")
	}
	if options.reuse && method != onec.LegacyAuth {
		return summary, errors.New("connection reuse is currently supported only with --auth legacy")
	}
	runCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	jobs := make(chan int)
	results := make(chan batchResult, options.workers)
	var workers sync.WaitGroup
	for i := 1; i <= options.workers; i++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			batchWorker(runCtx, cancel, worker, cfg, method, input, options.reuse, jobs, results, dial)
		}(i)
	}
	go func() { workers.Wait(); close(results) }()
	active, next := 0, 0
	closedJobs, reportFailed := false, false
	var nextAt time.Time
	cancelled := runCtx.Done()
	for {
		if !closedJobs && (runCtx.Err() != nil || next == total) {
			close(jobs)
			closedJobs = true
			cancelled = nil
		}
		var dispatch chan int
		var tick <-chan time.Time
		var timer *time.Timer
		if !closedJobs && active < options.workers {
			if delay := time.Until(nextAt); delay > 0 {
				timer = time.NewTimer(delay)
				tick = timer.C
			} else {
				dispatch = jobs
			}
		}
		select {
		case dispatch <- next:
			next++
			active++
			nextAt = time.Now().Add(interval)
		case <-tick:
		case <-cancelled:
		case result, ok := <-results:
			if timer != nil {
				timer.Stop()
			}
			if !ok {
				if reportFailed {
					summary.StoppedReason = "report_write_failed"
				} else if cause := context.Cause(runCtx); cause != nil {
					if reason, ok := cause.(batchStop); ok {
						summary.StoppedReason = string(reason)
					} else {
						summary.StoppedReason = "cancelled"
					}
				}
				summary.Completed = summary.StoppedReason == "" && summary.Recorded == total
				if !summary.Completed {
					return summary, errors.New("batch stopped after connection cleanup; inspect the sanitized report")
				}
				return summary, nil
			}
			if result.done {
				active--
				if options.workers == 1 {
					// Preserve the serial command's pause after each completed attempt.
					nextAt = time.Now().Add(interval)
				}
			}
			if result.opened {
				summary.ConnectionsOpened++
			}
			if result.record == nil {
				continue
			}
			r := *result.record
			if r.ConnectionClosed {
				summary.ConnectionsClosed++
			}
			if r.CleanupError {
				summary.CleanupErrors++
			}
			if r.Event == "attempt" {
				summary.Started++
				if r.LoginConfirmed {
					summary.Accepted++
				} else if r.Status == "not_accepted" {
					summary.NotAccepted++
				}
				if r.Status != "accepted" && r.Status != "not_accepted" {
					summary.Errors++
				}
			}
			if !reportFailed {
				if err := emit(r); err != nil {
					reportFailed = true
					cancel(batchStop("report_write_failed"))
				} else if r.Event == "attempt" {
					summary.Recorded++
				}
			}
		}
		if timer != nil {
			timer.Stop()
		}
	}
}
