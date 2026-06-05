// C2IntelFeeds updater — standalone binary that fetches C2 indicators from
// the C2IntelFeeds CSV repository and writes them to a JSON feed file.
//
// Usage:
//   c2update -output feed.json                          # update all feeds
//   c2update -output feed.json -30day                   # update only 30-day active IPs
//   c2update -output feed.json -domain                  # update only domain feed
//   c2update -output feed.json -ipport                  # update only IP+port feed
//   c2update -output feed.json -timeout 30              # custom HTTP timeout
//
// This binary is independent of networksentinel and can be scheduled via
// cron, systemd timer, or Windows Task Scheduler.
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	output  = flag.String("output", "c2intel_feeds.json", "Output JSON feed file path")
	threeDay = flag.Bool("30day", false, "Fetch only the 30-day active IP list")
	domain  = flag.Bool("domain", false, "Fetch only the domain C2 list")
	ipport  = flag.Bool("ipport", false, "Fetch only the IP+port C2 list")
	timeout = flag.Int("timeout", 10, "HTTP timeout in seconds")
)

const (
	feedURLFull      = "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s.csv"
	feedURL30Day     = "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv"
	feedURLIPPort    = "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPPortC2s.csv"
	feedURLDomain    = "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s.csv"
)

func main() {
	flag.Parse()

	httpClient := &http.Client{Timeout: time.Duration(*timeout) * time.Second}
	var iocs []IOC
	var source string

	switch {
	case *threeDay:
		iocs, source, _ = fetchFeed(httpClient, feedURL30Day, "ip")
	case *domain:
		iocs, source, _ = fetchFeed(httpClient, feedURLDomain, "domain")
	case *ipport:
		iocs, source, _ = fetchIPPortFeed(httpClient)
	default:
		// Fetch all feeds and merge.
		var all []IOC
		var src string

		ipIOCs, s, _ := fetchFeed(httpClient, feedURLFull, "ip")
		all = append(all, ipIOCs...)
		src = s

		ipPortIOCs, s2, _ := fetchIPPortFeed(httpClient)
		all = append(all, ipPortIOCs...)
		src += "+" + s2

		domainIOCs, s3, _ := fetchFeed(httpClient, feedURLDomain, "domain")
		all = append(all, domainIOCs...)
		src += "+" + s3

		iocs = dedup(all)
		source = src
	}

	if len(iocs) == 0 {
		log.Fatalf("No indicators returned from %s", source)
	}

	envelope := FeedEnvelope{
		Format:    "c2intelfeeds",
		Source:    source,
		Generated: time.Now().UTC().Format(time.RFC3339),
		Count:     len(iocs),
		IOCs:      iocs,
	}

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		log.Fatalf("Marshal failed: %v", err)
	}

	if err := os.WriteFile(*output, data, 0644); err != nil {
		log.Fatalf("Write failed: %v", err)
	}

	fmt.Printf("Updated %d indicators -> %s\n", len(iocs), *output)
}

// IOC represents a single indicator of compromise.
type IOC struct {
	Indicator     string   `json:"indicator"`
	IndicatorType string   `json:"indicator_type"`
	MalwareFamily string   `json:"malware_family"`
	Country       string   `json:"country"`
	Confidence    int      `json:"confidence"`
	Tags          []string `json:"tags"`
	Source        string   `json:"source"`
	Status        string   `json:"status"`
	Port          int      `json:"port,omitempty"`
}

// FeedEnvelope wraps indicators with metadata.
type FeedEnvelope struct {
	Format    string `json:"format"`
	Source    string `json:"source"`
	Generated string `json:"generated_at"`
	Count     int    `json:"indicator_count"`
	IOCs      []IOC  `json:"indicators"`
}

// fetchFeed downloads a two-column CSV (ip,ioc or domain,ioc) and parses it.
func fetchFeed(client *http.Client, url, colType string) ([]IOC, string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("status %d from %s", resp.StatusCode, url)
	}

	var iocs []IOC
	cr := csv.NewReader(resp.Body)
	cr.Comment = '#'

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

		val := strings.TrimSpace(record[0])
		desc := strings.TrimSpace(record[1])
		if val == "" || val == "ip" || val == "domain" {
			continue
		}

		iocs = append(iocs, IOC{
			Indicator:     val,
			IndicatorType: colType,
			MalwareFamily: detectFamily(desc),
			Country:       "",
			Confidence:    70,
			Tags:          []string{"c2intelfeeds", "cobaltstrike"},
			Source:        "c2intelfeeds",
			Status:        "active",
		})
	}

	source := strings.ReplaceAll(url, "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/", "")
	source = strings.TrimSuffix(source, ".csv")
	return iocs, source, nil
}

// fetchIPPortFeed downloads and parses the IP+port C2 feed (3-column CSV).
func fetchIPPortFeed(client *http.Client) ([]IOC, string, error) {
	resp, err := client.Get(feedURLIPPort)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("status %d from %s", resp.StatusCode, feedURLIPPort)
	}

	var iocs []IOC
	cr := csv.NewReader(resp.Body)
	cr.Comment = '#'

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
		fmt.Sscanf(portStr, "%d", &port)

		tags := []string{"c2intelfeeds", "cobaltstrike", fmt.Sprintf("port-%d", port)}
		iocs = append(iocs, IOC{
			Indicator:     ip,
			IndicatorType: "ipv4",
			MalwareFamily: detectFamily(desc),
			Country:       "",
			Confidence:    75,
			Tags:          tags,
			Source:        "c2intelfeeds_ipport",
			Status:        "active",
			Port:          port,
		})
	}

	return iocs, "IPPortC2s", nil
}

// detectFamily extracts malware family from description text.
func detectFamily(desc string) string {
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

// dedup removes duplicate indicators, keeping the first occurrence.
func dedup(iocs []IOC) []IOC {
	seen := make(map[string]bool)
	result := make([]IOC, 0, len(iocs))
	for _, i := range iocs {
		if !seen[i.Indicator] {
			seen[i.Indicator] = true
			result = append(result, i)
		}
	}
	return result
}
