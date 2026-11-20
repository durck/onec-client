# Offline traffic inspector

`onec inspect` reads **one direction of a reassembled TCP byte stream** and
prints a redacted structural report. It runs locally, opens no sockets, does
not authenticate, and never changes its input file. It understands the bounded
native protocol subset already implemented in `wire`; this is not a complete
1C protocol decoder or a statement of server limits.

## Input and invocation

The input is binary TCP application payload, after sequence-aware TCP
reassembly, retransmission removal, and separation of the two directions.
An initial server greeting is optional. Start at a known record/control
boundary, or at the greeting. A stream that starts in the middle of a record
cannot be reconstructed reliably from its bytes alone.

PCAP, PCAPNG, packet headers, hex dumps, and TShark follow text are **not** CLI
inputs. Recognized PCAP/PCAPNG magic numbers produce a fixed diagnostic. Export
each reassembled direction as raw bytes using the existing offline capture
workflow first; packet-payload concatenation alone is not TCP reassembly.
Keep both directions in separate files. The inspector does not associate
requests with replies across files or verify capture completeness.

Run from the module directory:

```powershell
go run ./cmd/onec inspect test-results/inspector-demo/request.tcp-payload.bin
go run ./cmd/onec inspect --json test-results/inspector-demo/response.tcp-payload.bin
go run ./cmd/onec inspect --format json --input test-results/client-direction.bin
go run ./cmd/onec inspect --help
```

Flags precede the positional file. `--input` is an alternative to that file,
and `--json` is an alias for `--format json`. There is no `--apply` option or
raw-content switch. A successful command exits with status zero. An input,
framing, supported-format, body-structure, or resource-limit failure returns
a nonzero status **after writing the available redacted report**. Invalid
options or an input file that cannot be opened fail before a report is created.
Diagnostics never echo input paths or arbitrary flag/decoder error text.

To create the synthetic payload files used above, first run the documentation
generator. Its output stays in the ignored `test-results/` directory:

```powershell
go run ./docs/examples/http-tcp test-results/inspector-demo
go run ./cmd/onec inspect --json test-results/inspector-demo/request.tcp-payload.bin
go run ./cmd/onec inspect --json test-results/inspector-demo/response.tcp-payload.bin
```

Those generated packets contain demonstration values. They are encoding
fixtures, not evidence of a valid new login or a live exchange.

## Report contents and offsets

The JSON format identifier is `onec-reassembled-tcp-v1`. Reports include byte
counts, configured limits, event counts, complete events, and fixed issue
codes. Human output is a concise view of the same safe fields.

| Layer | Reported information |
| --- | --- |
| Transport | Initial greeting, records, Control2, opaque Control3 length, raw offsets |
| RPC | Binary/text/introduction classification, atom kind counts, number and structural summaries of top-level values |
| HTTP RPC | Recognized request/reply shape, second top-level reply marker, security blob counts and byte lengths |
| HTTPFile | Chunk byte lengths, decoded-record offsets, reconstructed PDU size |
| HTTP | Request/response, allowlisted method and exact endpoint, status, query presence, header counts, allowlisted content type/encoding |
| Body | Byte counts; JSON object/array/property/scalar counts or XML element/attribute counts; nesting and validity |

All offsets are **zero based, with an exclusive end**:

- `wire_start` / `wire_end` refer to bytes in the input direction. Record
  ranges include the End marker and any intervening controls. Control events
  therefore can overlap a record range. Leading controls are separate.
- `record_offset` / `record_end` refer to the unescaped decoded record.
  Chunk ranges include their binary atom tag and length prefix. A list summary
  spans its descendant scalar atoms, excluding structural delimiter atoms.
  Empty lists use `-1` for unavailable scalar boundaries.
- Event issue offsets refer to the decoded record; report-level issue offsets
  refer to the raw input. Body issues point to the containing HTTPFile.

Escaping changes byte positions, so decoded offsets cannot be added directly
to `wire_start` to recover raw offsets. No packet/frame/timestamp mapping is
claimed. `input_bytes_read` can be one greater than the configured input limit
because the reader probes for excess input. `bytes_examined` records how much
of the retained raw input was fed to the framing layer; parsing stops on a
transport/event limit while preserving already completed events.

`complete: true` means that this input ended cleanly and no supported-layer
issue was reported. Unknown but syntactically valid RPC shapes remain
`unclassified`; unknown body media can remain `opaque`. This flag does not
confirm application success, authentication, a complete capture, or complete
knowledge of the protocol. Control semantics are not inferred.

## Redaction boundary

The report never includes arbitrary string values, GUID values, authentication
blobs, credential names, tickets, passwords, session identifiers, cookie values,
custom header names or values, URL query text, body text, JSON keys, XML names,
or parser error strings. Unknown HTTP methods and media values become `other`;
unknown paths become `redacted`. Only an exact fixed endpoint allowlist may be
printed. Header summaries expose counts for a fixed list of names, including
the presence of authentication/session/cookie headers, never their values.

There is intentionally no unsafe output mode. The original source still
contains sensitive bytes and should retain its existing access controls.
Redacted reports still reveal traffic sizes, structure, and known operations.

## Bounds and supported subset

| Limit | Default | Hard ceiling |
| --- | ---: | ---: |
| Input bytes (`--max-input-bytes`) | 64 MiB | 64 MiB |
| Decoded record (`--max-record-bytes`) | 1 MiB | 16 MiB |
| Atoms/values per record (`--max-atoms`) | 100,000 | 250,000 |
| Retained events (`--max-events`) | 4,096 | 16,384 |
| Binary nesting (`wire`) | 64 | 64 |
| Text record/nesting (`wire`) | 1 MiB / 32 | fixed |
| HTTP PDU / headers (`wire`) | 512 KiB / 64 KiB | fixed |
| HTTPFile chunks | 16,384 bytes, final chunk strictly shorter | fixed |
| Decoded body | 1 MiB | fixed |
| JSON/XML structural nodes / depth | 100,000 / 64 | fixed |
| HTTPFiles per record | 32 | fixed |
| Top-level value summaries per record | 16 | fixed |
| Detailed issues per record | 64 | fixed |

The atom preflight checks lengths and counts before `wire.DecodeAtoms` allocates
objects. Byte strings, security blobs, HTTPFile chunk boundaries, and RPC reply
trailers retain the existing `wire` checks. A file exactly divisible by 16,384
requires the final empty chunk. Binary comma/flag grammar is only as strict as
the existing tree builder; a structural report is not full protocol validation.
Summary omissions are counted. Reaching a file/event/parse limit reports an
issue; omitted top-level descriptions do not prevent analysis of the values.

HTTP parsing supports the observed Content-Length subset, including a bounded
zero-length response that ends at the HTTPFile boundary. Transfer-Encoding is
unsupported. Bodies support identity and the observed **raw DEFLATE** encoding;
compressed trailing bytes and expansion beyond 1 MiB are rejected. Gzip, zlib
wrappers, other encodings, and XML directives are outside this subset. JSON/XML
inspection checks bounded structure, not application schema, JSON key
uniqueness, XML namespace semantics, or business meaning. No external XML
resources are fetched. Invalid or unsupported bodies retain safe byte counts
and a fixed issue code.

## Library

`inspect.Analyze(io.Reader, inspect.Options)` returns the structured report.
Input and parse failures are report issues; an invalid options configuration is
returned as an error. `inspect.WriteText` formats a report produced by `Analyze`.

Recognizing a saved frame does not establish server interoperability or complete
application semantics. Unsupported or partial input retains the bounds and
redaction behavior described above.
