// Package wire implements the observed native 1C framing, ListStream and HTTP
// envelope subset. It deliberately rejects unsupported atom types and layouts.
// Request and response bytes can contain authentication and session material.
package wire
