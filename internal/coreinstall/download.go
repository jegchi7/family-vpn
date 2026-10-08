package coreinstall

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

func permittedURL(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	switch u.Hostname() {
	case "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
		return true
	}
	return false
}

func redirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 || !permittedURL(req.URL) {
		return ErrDownload
	}
	return nil
}

func downloadClient() *http.Client {
	return &http.Client{Timeout: 3 * time.Minute, CheckRedirect: redirect, Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 20 * time.Second, DisableCompression: true}}
}

// download is bounded by the catalogue length, not an HTTP supplied length.
// No response, transport or URL error is propagated to reports.
func download(ctx context.Context, a Artifact, dst io.Writer, client *http.Client) error {
	u, e := url.Parse(a.URL)
	if e != nil || !permittedURL(u) {
		return ErrDownload
	}
	r, e := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if e != nil {
		return ErrDownload
	}
	r.Header.Set("User-Agent", "family-vpn-core-installer/1")
	r.Header.Set("Accept-Encoding", "identity")
	resp, e := client.Do(r)
	if e != nil {
		return ErrDownload
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || (resp.ContentLength >= 0 && resp.ContentLength != a.ArchiveSize) || (resp.Header.Get("Content-Encoding") != "" && resp.Header.Get("Content-Encoding") != "identity") {
		return ErrDownload
	}
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(dst, h), io.LimitReader(resp.Body, a.ArchiveSize+1))
	if e != nil {
		return ErrDownload
	}
	if n != a.ArchiveSize || hex.EncodeToString(h.Sum(nil)) != a.ArchiveSHA256 {
		return ErrIntegrity
	}
	return nil
}
