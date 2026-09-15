package darkapi

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

type BadDomainList struct {
	Updated  time.Time `json:"updated"`
	Count    int       `json:"count"`
	Domains  []string  `json:"domains"`
	Checksum string    `json:"checksum,omitempty"`
}
type BadIPList struct {
	Updated  time.Time `json:"updated"`
	Count    int       `json:"count"`
	IPs      []string  `json:"ips"`
	Checksum string    `json:"checksum,omitempty"`
}

// ThreatSnapshot is a bounded snapshot of feeds accessible to the account.
// It is not a claim of complete Internet threat coverage.
func (c *Client) ThreatSnapshot(ctx context.Context, since time.Time) (*BadDomainList, *BadIPList, error) {
	var catalog struct {
		Feeds []struct {
			Name       string `json:"feed_name"`
			Accessible bool   `json:"accessible"`
		} `json:"feeds"`
	}
	if err := c.request(ctx, "GET", "/v1/feeds", "account", nil, &catalog, true); err != nil {
		return nil, nil, err
	}
	domains := &BadDomainList{Updated: time.Now()}
	ips := &BadIPList{Updated: domains.Updated}
	seenD := map[string]bool{}
	seenIP := map[string]bool{}
	accessible, total := 0, 0
	for _, feed := range catalog.Feeds {
		if !feed.Accessible {
			continue
		}
		accessible++
		if accessible > 100 {
			return nil, nil, fmt.Errorf("feed catalog exceeds 100-feed snapshot limit")
		}
		if feed.Name == "" {
			return nil, nil, fmt.Errorf("invalid feed catalog")
		}
		for offset := 0; ; offset += 1000 {
			query := url.Values{"limit": {"1000"}, "offset": {fmt.Sprint(offset)}}
			if !since.IsZero() {
				query.Set("since", since.UTC().Format(time.RFC3339))
			}
			var page struct {
				Entries []struct {
					Type  string `json:"indicator_type"`
					Value string `json:"indicator_value"`
				} `json:"entries"`
				Returned int `json:"returned"`
			}
			if err := c.request(ctx, "GET", "/v1/feeds/"+url.PathEscape(feed.Name)+"?"+query.Encode(), "account", nil, &page, true); err != nil {
				return nil, nil, err
			}
			if page.Entries == nil || page.Returned != len(page.Entries) {
				return nil, nil, fmt.Errorf("invalid feed page")
			}
			total += len(page.Entries)
			if total > 100000 {
				return nil, nil, fmt.Errorf("feed snapshot exceeds 100000-entry limit")
			}
			for _, entry := range page.Entries {
				switch entry.Type {
				case "domain":
					if !seenD[entry.Value] {
						domains.Domains = append(domains.Domains, entry.Value)
						seenD[entry.Value] = true
					}
				case "ip":
					if !seenIP[entry.Value] {
						ips.IPs = append(ips.IPs, entry.Value)
						seenIP[entry.Value] = true
					}
				}
			}
			if len(page.Entries) < 1000 {
				break
			}
		}
	}
	if accessible == 0 {
		return nil, nil, fmt.Errorf("no accessible DarkAPI threat feeds")
	}
	domains.Count = len(domains.Domains)
	ips.Count = len(ips.IPs)
	return domains, ips, nil
}
func (c *Client) GetBadDomains(ctx context.Context) (*BadDomainList, error) {
	d, _, e := c.ThreatSnapshot(ctx, time.Time{})
	return d, e
}
func (c *Client) GetBadIPs(ctx context.Context) (*BadIPList, error) {
	_, i, e := c.ThreatSnapshot(ctx, time.Time{})
	return i, e
}
func (c *Client) GetBadDomainsIncremental(ctx context.Context, since time.Time) (*BadDomainList, error) {
	d, _, e := c.ThreatSnapshot(ctx, since)
	return d, e
}
func (c *Client) GetBadIPsIncremental(ctx context.Context, since time.Time) (*BadIPList, error) {
	_, i, e := c.ThreatSnapshot(ctx, since)
	return i, e
}
