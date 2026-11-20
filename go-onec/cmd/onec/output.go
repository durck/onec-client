package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func writeCommandReport(out io.Writer, report any) error {
	w, ok := out.(*consoleWriter)
	if !ok || !w.human() {
		return json.NewEncoder(out).Encode(report)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err = decoder.Decode(&value); err != nil {
		return err
	}
	var b strings.Builder
	heading, code, operation := "RESULT", "96", ""
	if fields, ok := value.(map[string]any); ok {
		operation, _ = fields["operation"].(string)
		if group, ok := fields["command_group"].(string); ok {
			operation = group + " " + operation
		}
		if fields["mode"] == "preview" {
			heading, code = "PREVIEW", "93"
		} else if operation == "checklist" {
			heading, code = "INCOMPLETE", "93"
			if fields["completed"] == true {
				heading, code = "COMPLETED", "92"
			}
			if summary, ok := fields["summary"].(map[string]any); ok {
				if findings, ok := summary["findings"].(json.Number); ok && findings != "0" {
					heading += " / FINDINGS"
					code = "93"
				}
			}
		} else if success, ok := fields["success"].(bool); ok {
			if success {
				heading, code = "SUCCESS", "92"
			} else {
				heading, code = "FAILED", "91"
			}
		}
	}
	fmt.Fprintf(&b, "\n  %s  %s\n", terminalAccent(w, code, heading), terminalText(operation))
	fmt.Fprintln(&b, "  "+strings.Repeat("─", min(max(w.width-4, 36), 76)))
	renderReportValue(&b, value, "  ", w.verbose, 0, w.width)
	if heading == "PREVIEW" {
		fmt.Fprintln(&b, "\n  No network requests sent. Add --execute to perform this operation.")
	}
	if !w.verbose {
		fmt.Fprintln(&b, "\n  More detail: onec --verbose <command>  ·  JSON: onec --output json <command>")
	}
	fmt.Fprintln(&b)
	_, err = io.WriteString(out, b.String())
	return err
}

func writeIndentedCommandReport(out io.Writer, report any) error {
	if w, ok := out.(*consoleWriter); ok && w.human() {
		return writeCommandReport(out, report)
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

var reportLabels = map[string]string{
	"operation_timeout_ns": "Operation timeout", "total_timeout_ns": "Total timeout", "credential_interval_ns": "Credential interval",
	"coverage": "Coverage", "report_file": "Report file", "summary": "Summary", "options": "Options", "results": "Results",
	"infobase": "Database", "server": "Manager", "worker": "Worker", "authentication": "Authentication", "security_provider": "Security provider",
	"network_requests_sent": "Network requests", "credentials_read": "Credentials read", "infobases": "Databases", "result": "Result", "data": "Data",
	"logout_confirmed": "Logout confirmed", "context_released": "Context released", "security_closed": "Security closed", "closed": "Connection closed",
	"client_version": "Client version", "duration": "Session lifetime", "epf": "Processing file", "upload": "Upload mode", "form": "Form", "success": "Success",
	"bytes_sent": "Bytes sent", "bytes_received": "Bytes received", "rpc_rounds": "RPC rounds", "id": "ID", "url": "URL", "http_status": "HTTP status",
	"name": "Name", "description": "Description", "transport": "Transport", "agent": "Agent", "cluster": "Cluster", "session": "Session",
}

func reportLabel(key string) string {
	if label, ok := reportLabels[key]; ok {
		return label
	}
	label := strings.ReplaceAll(key, "_", " ")
	if label != "" {
		label = strings.ToUpper(label[:1]) + label[1:]
	}
	return label
}

func reportKeys(fields map[string]any) []string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	priority := map[string]int{"summary": 1, "coverage": 2, "report_file": 3, "worker": 1, "server": 2, "agent": 3, "url": 4, "infobase": 5, "authentication": 6, "transport": 7, "epf": 8, "form": 9, "method": 10, "result": 20, "infobases": 21, "data": 22, "stats": 90}
	sort.SliceStable(keys, func(i, j int) bool {
		a, b := priority[keys[i]], priority[keys[j]]
		if a == 0 {
			a = 50
		}
		if b == 0 {
			b = 50
		}
		return a < b
	})
	return keys
}

func renderReportValue(b *strings.Builder, value any, indent string, verbose bool, depth, width int) {
	if depth > 12 {
		data, _ := json.Marshal(value)
		fmt.Fprintln(b, indent+terminalText(string(data)))
		return
	}
	switch value := value.(type) {
	case map[string]any:
		for _, key := range reportKeys(value) {
			item := value[key]
			if depth == 0 && (key == "mode" || key == "operation" || key == "command_group" || key == "success") {
				continue
			}
			if !verbose {
				if item == nil || item == "" || key == "profile" || key == "network_requests_sent" {
					continue
				}
				if key == "server" && value["worker"] != nil && value["worker"] != "" {
					continue
				}
				if depth > 0 && (key == "security_contexts" || key == "connections") {
					continue
				}
			}
			label := terminalText(reportLabel(key))
			if formatted, ok := reportField(key, item); ok {
				fmt.Fprintf(b, "%s%-24s %s\n", indent, label, formatted)
				continue
			}
			switch item.(type) {
			case map[string]any, []any:
				fmt.Fprintln(b, "\n"+indent+label)
				renderReportValue(b, item, indent+"  ", verbose, depth+1, width)
			default:
				fmt.Fprintf(b, "%s%-24s %s\n", indent, label, reportScalar(item))
			}
		}
	case []any:
		if len(value) == 0 {
			fmt.Fprintln(b, indent+"(empty)")
			return
		}
		if renderReportTable(b, value, indent, verbose, width) {
			return
		}
		limit := len(value)
		if !verbose {
			limit = min(limit, 20)
		}
		for i, item := range value[:limit] {
			if _, ok := item.(map[string]any); ok {
				fmt.Fprintf(b, "%s[%d]\n", indent, i+1)
				renderReportValue(b, item, indent+"  ", verbose, depth+1, width)
			} else {
				fmt.Fprintln(b, indent+"• "+reportScalar(item))
			}
		}
		if limit < len(value) {
			fmt.Fprintf(b, "%s… %d more; use --verbose or --output json.\n", indent, len(value)-limit)
		}
	default:
		fmt.Fprintln(b, indent+reportScalar(value))
	}
}

// Human formatting is independent of the JSON schema and never changes values.
func reportField(key string, value any) (string, bool) {
	if key == "coverage" && value == "discovered_objects_only" {
		return "Discovered objects only (partial inventory)", true
	}
	if key == "operation_timeout_ns" || key == "total_timeout_ns" || key == "credential_interval_ns" {
		if number, ok := value.(json.Number); ok {
			if n, err := number.Int64(); err == nil {
				return time.Duration(n).String(), true
			}
		}
	}
	if key != "worker_ports" {
		return "", false
	}
	items, ok := value.([]any)
	if !ok {
		return "", false
	}
	if len(items) == 0 {
		return "none", true
	}
	var ports []int
	for _, item := range items {
		n, ok := item.(json.Number)
		if !ok {
			return "", false
		}
		port, err := strconv.Atoi(n.String())
		if err != nil || port < 1 || port > 65535 {
			return "", false
		}
		ports = append(ports, port)
	}
	var ranges []string
	for i := 0; i < len(ports); i++ {
		start := ports[i]
		for i+1 < len(ports) && ports[i+1] == ports[i]+1 {
			i++
		}
		text := strconv.Itoa(start)
		if start != ports[i] {
			text += "-" + strconv.Itoa(ports[i])
		}
		ranges = append(ranges, text)
	}
	return strings.Join(ranges, ", "), true
}

func reportScalar(value any) string {
	switch value := value.(type) {
	case nil:
		return "—"
	case bool:
		if value {
			return "yes"
		}
		return "no"
	case string:
		return terminalText(value)
	case json.Number:
		return value.String()
	default:
		data, _ := json.Marshal(value)
		return terminalText(string(data))
	}
}

// Tables are used only when every column fits. Wide or nested records retain
// their full values in a vertical view instead of silently truncating IDs.
func renderReportTable(b *strings.Builder, rows []any, indent string, verbose bool, width int) bool {
	first, ok := rows[0].(map[string]any)
	if !ok || len(first) == 0 || len(first) > 6 {
		return false
	}
	keys := reportKeys(first)
	widths := make([]int, len(keys))
	for i, key := range keys {
		widths[i] = utf8.RuneCountInString(terminalText(reportLabel(key)))
	}
	for _, item := range rows {
		row, ok := item.(map[string]any)
		if !ok || len(row) != len(keys) {
			return false
		}
		for i, key := range keys {
			value, ok := row[key]
			if !ok {
				return false
			}
			switch value.(type) {
			case []any, map[string]any:
				return false
			}
			widths[i] = max(widths[i], utf8.RuneCountInString(reportScalar(value)))
		}
	}
	total := len(indent)
	for _, n := range widths {
		total += n + 3
	}
	if total > max(width, 60) {
		return false
	}
	writeRow := func(values []string) {
		b.WriteString(indent)
		for i, value := range values {
			b.WriteString(value)
			if i < len(values)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-utf8.RuneCountInString(value)+3))
			}
		}
		b.WriteByte('\n')
	}
	headers := make([]string, len(keys))
	for i, key := range keys {
		headers[i] = terminalText(reportLabel(key))
	}
	writeRow(headers)
	limit := len(rows)
	if !verbose {
		limit = min(limit, 20)
	}
	for _, item := range rows[:limit] {
		values := make([]string, len(keys))
		for i, key := range keys {
			values[i] = reportScalar(item.(map[string]any)[key])
		}
		writeRow(values)
	}
	if limit < len(rows) {
		fmt.Fprintf(b, "%s… %d more; use --verbose or --output json.\n", indent, len(rows)-limit)
	}
	return true
}
