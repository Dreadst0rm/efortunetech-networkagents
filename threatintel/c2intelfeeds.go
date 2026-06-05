// Package threatintel provides C2 indicator parsing from the C2IntelFeeds CSV repository.
package threatintel

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// C2IntelFeedsURL is the GitHub raw URL for the full IOC list.
const C2IntelFeedsURL = "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s.csv"

// C2IntelFeeds30DayURL is the GitHub raw URL for the 30-day active IOC list.
const C2IntelFeeds30DayURL = "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv"

// C2IntelFeedsIPPortURL is the GitHub raw URL for the IP+port C2 list.
const C2IntelFeedsIPPortURL = "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPPortC2s.csv"

// C2IntelFeedsDomainURL is the GitHub raw URL for the domain C2 list.
const C2IntelFeedsDomainURL = "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s.csv"

// C2IntelFeedsClient fetches C2 indicators from the C2IntelFeeds CSV repository.
type C2IntelFeedsClient struct {
	HTTPClient *http.Client
	Timeout    time.Duration
}

// NewC2IntelFeedsClient creates a client with sensible defaults.
func NewC2IntelFeedsClient(timeout time.Duration) *C2IntelFeedsClient {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &C2IntelFeedsClient{
		HTTPClient: &http.Client{Timeout: timeout},
		Timeout:    timeout,
	}
}

// FetchAllIOCs fetches all C2 indicator feeds and returns them as local IOC structs.
// It fetches IP-based, IP+port-based, and domain-based feeds in parallel.
func (c *C2IntelFeedsClient) FetchAllIOCs() ([]IOC, error) {
	var (
		iocs []IOC
		errs []error
	)

	// Fetch IP-based feed.
	ipIOCs, err := c.fetchIPFeed(C2IntelFeedsURL)
	if err != nil {
		errs = append(errs, fmt.Errorf("IP feed: %w", err))
	} else {
		iocs = append(iocs, ipIOCs...)
	}

	// Fetch IP+port feed.
	ipPortIOCs, err := c.fetchIPPortFeed(C2IntelFeedsIPPortURL)
	if err != nil {
		errs = append(errs, fmt.Errorf("IP+port feed: %w", err))
	} else {
		iocs = append(iocs, ipPortIOCs...)
	}

	// Fetch domain feed.
	domainIOCs, err := c.fetchDomainFeed(C2IntelFeedsDomainURL)
	if err != nil {
		errs = append(errs, fmt.Errorf("domain feed: %w", err))
	} else {
		iocs = append(iocs, domainIOCs...)
	}

	if len(iocs) == 0 && len(errs) > 0 {
		var reason strings.Builder
		for _, e := range errs {
			if reason.Len() > 0 {
				reason.WriteString("; ")
			}
			reason.WriteString(e.Error())
		}
		return nil, fmt.Errorf("c2intelfeeds: all feeds failed: %s", reason.String())
	}

	return iocs, nil
}

// Fetch30DayIOCs fetches only the 30-day active IOC list.
func (c *C2IntelFeedsClient) Fetch30DayIOCs() ([]IOC, error) {
	iocs, err := c.fetchIPFeed(C2IntelFeeds30DayURL)
	if err != nil {
		return nil, fmt.Errorf("30-day feed: %w", err)
	}
	return iocs, nil
}

// fetchIPFeed downloads and parses the IP-based C2 feed.
// Format: #ip,ioc (comment header, then IP lines with description).
func (c *C2IntelFeedsClient) fetchIPFeed(url string) ([]IOC, error) {
	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d from %s", resp.StatusCode, url)
	}

	return parseIPFeed(resp.Body)
}

// fetchIPPortFeed downloads and parses the IP+port C2 feed.
// Format: #ip,port,ioc (three-column CSV).
func (c *C2IntelFeedsClient) fetchIPPortFeed(url string) ([]IOC, error) {
	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d from %s", resp.StatusCode, url)
	}

	return parseIPPortFeed(resp.Body)
}

// fetchDomainFeed downloads and parses the domain C2 feed.
// Format: #domain,ioc (comment header, then domain lines with description).
func (c *C2IntelFeedsClient) fetchDomainFeed(url string) ([]IOC, error) {
	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d from %s", resp.StatusCode, url)
	}

	return parseDomainFeed(resp.Body)
}

// parseIPFeed parses a two-column CSV: ip,ioc_description.
func parseIPFeed(r io.Reader) ([]IOC, error) {
	cr := csv.NewReader(r)
	cr.Comment = '#'
	var iocs []IOC

	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(record) < 2 {
			continue
		}

		ip := strings.TrimSpace(record[0])
		desc := strings.TrimSpace(record[1])

		if ip == "" || ip == "ip" {
			continue
		}

		iocs = append(iocs, IOC{
			Indicator:     ip,
			IndicatorType: "ipv4",
			MalwareFamily: detectMalwareFamily(desc),
			Country:       "",
			Confidence:    70,
			Tags:          []string{"c2intelfeeds", "cobaltstrike"},
			Source:        "c2intelfeeds",
			Status:        "active",
		})
	}

	return iocs, nil
}

// parseIPPortFeed parses a three-column CSV: ip,port,ioc_description.
func parseIPPortFeed(r io.Reader) ([]IOC, error) {
	cr := csv.NewReader(r)
	cr.Comment = '#'
	var iocs []IOC

	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(record) < 3 {
			continue
		}

		ip := strings.TrimSpace(record[0])
		portStr := strings.TrimSpace(record[1])
		desc := strings.TrimSpace(record[2])

		if ip == "" || ip == "ip" {
			continue
		}

		port := 0
		if len(portStr) > 0 {
			fmt.Sscanf(portStr, "%d", &port)
		}

		iocs = append(iocs, IOC{
			Indicator:     ip,
			IndicatorType: "ipv4",
			MalwareFamily: detectMalwareFamily(desc),
			Country:       "",
			Confidence:    75,
			Tags:          []string{"c2intelfeeds", "cobaltstrike", fmt.Sprintf("port-%d", port)},
			Source:        "c2intelfeeds_ipport",
			Status:        "active",
			Port:          port,
		})
	}

	return iocs, nil
}

// parseDomainFeed parses a two-column CSV: domain,ioc_description.
func parseDomainFeed(r io.Reader) ([]IOC, error) {
	cr := csv.NewReader(r)
	cr.Comment = '#'
	var iocs []IOC

	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(record) < 2 {
			continue
		}

		domain := strings.TrimSpace(record[0])
		desc := strings.TrimSpace(record[1])

		if domain == "" || domain == "domain" {
			continue
		}

		iocs = append(iocs, IOC{
			Indicator:     domain,
			IndicatorType: "domain",
			MalwareFamily: detectMalwareFamily(desc),
			Country:       "",
			Confidence:    70,
			Tags:          []string{"c2intelfeeds", "cobaltstrike"},
			Source:        "c2intelfeeds_domain",
			Status:        "active",
		})
	}

	return iocs, nil
}

// detectMalwareFamily extracts a malware family name from the IOC description.
func detectMalwareFamily(desc string) string {
	lower := strings.ToLower(desc)
	if strings.Contains(lower, "cobalt strike") || strings.Contains(lower, "cobaltstrike") {
		return "CobaltStrike"
	}
	if strings.Contains(lower, "metasploit") {
		return "Metasploit"
	}
	if strings.Contains(lower, "empire") {
		return "Empire"
	}
	if strings.Contains(lower, "sliver") {
		return "Sliver"
	}
	if strings.Contains(lower, "front") {
		return "C2Fronting"
	}
	return "CobaltStrike"
}
