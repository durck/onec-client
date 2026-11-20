package onec

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"onec/wire"
	"strings"
)

// AttachProcessing uploads an EPF through the extmd component attachment route.
// Unlike UploadProcessing's openDocument route, it sends only a multipart file
// and consumes a Location header. Both return a session-owned component handle;
// neither opens a form or promises that the server avoids internal disk writes.
// The extmd sequence is live-tested on 8.3.18.1208 only.
// Selecting this API explicitly selects the extmd multipart/Location contract.
// The server must acknowledge its exact supported Location schema; an error
// never falls back to openDocument or retries the attachment.
func (c *Client) AttachProcessing(ctx context.Context, epf []byte, filename string) (Processing, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.applicationReady(); err != nil {
		return Processing{}, err
	}
	if err := validateEPF(epf, filename); err != nil {
		return Processing{}, err
	}
	boundaryID, err := wire.NewUUID()
	if err != nil {
		return Processing{}, err
	}
	boundary := "onec-" + hex.EncodeToString(boundaryID[:])
	if bytes.Contains(epf, []byte(boundary)) {
		return Processing{}, errors.New("multipart boundary collision")
	}
	var body bytes.Buffer
	fmt.Fprintf(&body, "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n", boundary, filename)
	body.Write(epf)
	fmt.Fprintf(&body, "\r\n--%s--\r\n", boundary)
	pdu, err := c.pdu("POST", "/e1cib/extmd/processing", body.Bytes(), "multipart/form-data; boundary="+boundary, "application/json", c.session.raw, 0)
	if err != nil {
		return Processing{}, err
	}
	h, err := c.exchangeHTTP(ctx, pdu)
	if err != nil {
		return Processing{}, err
	}
	if h.Status != 201 {
		return Processing{}, c.processingUploadError(h, epf, "attach processing")
	}
	if _, err := decodeBody(h, wire.MaxFile); err != nil {
		return Processing{}, err
	}
	locations := h.Header("location")
	if len(locations) != 1 {
		return Processing{}, errors.New("missing unique attachment Location")
	}
	reference, err := parseAttachmentLocation(locations[0])
	if err != nil {
		return Processing{}, err
	}
	return Processing{owner: c, reference: reference}, nil
}

// Location is parsed as an identity, never followed as a network redirect.
func parseAttachmentLocation(location string) (string, error) {
	bad := errors.New("unsupported attachment Location")
	if !validValueText(location, 8192) {
		return "", bad
	}
	u, err := url.Parse(location)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(location, "#") {
		return "", bad
	}
	const prefix = "/e1cib/extmd/processing/"
	if !strings.HasPrefix(u.Path, prefix) {
		return "", bad
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, prefix), "/")
	if len(parts) != 2 || len(parts[1]) != 40 {
		return "", bad
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return "", bad
	}
	kind, name, ok := strings.Cut(parts[0], ".")
	if !ok || (kind != "ExternalDataProcessor" && kind != "ВнешняяОбработка") || !validFormName(name) {
		return "", bad
	}
	return parts[0], nil
}

func validateEPF(epf []byte, filename string) error {
	if len(epf) == 0 || len(epf) > MaxEPF {
		return errors.New("EPF exceeds supported size")
	}
	if !validValueText(filename, 255) || strings.ContainsAny(filename, "/\\\"") || !strings.HasSuffix(strings.ToLower(filename), ".epf") {
		return errors.New("expected a simple EPF filename")
	}
	for _, r := range filename {
		if r > 127 {
			return errors.New("EPF filename must be ASCII")
		}
	}
	return nil
}
