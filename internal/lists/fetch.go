// SPDX-License-Identifier: GPL-3.0-only

package lists

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"
)

// MaxListBytes caps a single download. The largest list today (HaGeZi TIF,
// wildcard) is about 48 MiB; the cap only exists so a misbehaving mirror
// cannot fill the runner's disk.
const MaxListBytes = 512 << 20

// Download is a fetched list body plus the facts recorded in the manifest.
type Download struct {
	Body      []byte
	SHA256    string
	FetchedAt time.Time
}

// Fetcher downloads lists with retries.
type Fetcher struct {
	Client    *http.Client
	UserAgent string
	Attempts  int
	Backoff   time.Duration
}

// Fetch GETs url, retrying transient failures. Any non-200 response is an
// error: publishing a list built from an error page would be worse than
// publishing nothing.
func (f *Fetcher) Fetch(ctx context.Context, url string) (*Download, error) {
	attempts := max(f.Attempts, 1)
	var lastErr error
	for i := range attempts {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(f.Backoff * time.Duration(i)):
			}
		}
		d, retry, err := f.fetchOnce(ctx, url)
		if err == nil {
			return d, nil
		}
		lastErr = err
		if !retry {
			break
		}
	}
	return nil, fmt.Errorf("fetch %s: %w", url, lastErr)
}

func (f *Fetcher) fetchOnce(ctx context.Context, url string) (d *Download, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	if f.UserAgent != "" {
		req.Header.Set("User-Agent", f.UserAgent)
	}
	client := f.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, true, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		retry = resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, retry, fmt.Errorf("unexpected status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxListBytes+1))
	if err != nil {
		return nil, true, err
	}
	if len(body) > MaxListBytes {
		return nil, false, fmt.Errorf("body exceeds %d bytes", MaxListBytes)
	}
	sum := sha256.Sum256(body)
	return &Download{
		Body:      body,
		SHA256:    hex.EncodeToString(sum[:]),
		FetchedAt: time.Now().UTC(),
	}, false, nil
}
