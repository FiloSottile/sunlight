// Command heliograph-dashboard generates a static HTML dashboard summarising a
// Sunlight CT log's cost and activity from Prometheus metrics.
//
// The submission charts read the recording rules in rules.yml, which must be
// loaded by the Prometheus server being queried.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"html/template"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	log.SetFlags(0)
	var (
		promURL     = flag.String("prometheus", "http://localhost:9090", "Prometheus base URL")
		outPath     = flag.String("o", "-", "output path; - means stdout")
		title       = flag.String("title", "Sunlight CT log", "page title")
		window      = flag.Duration("window", 7*24*time.Hour, "chart time window")
		step        = flag.Duration("step", 0, "chart step (0 = auto-scale to ~2000 points)")
		logName     = flag.String("log-name", "tuscolo", "log family name (matches sunlight job and log label prefix)")
		skylightJob = flag.String("skylight-job", "skylight", "Prometheus job label for skylight")
		datasetF    = flag.String("zfs-dataset", "tank/logs/,tank/caches/", "comma-separated ZFS parent datasets (each must end with /)")
		netDevice   = flag.String("network-device", "enp.*", "regex for physical NIC device labels")
		nodeJob     = flag.String("node-job", "node", "Prometheus job label of the node_exporter serving host metrics")
	)
	flag.Parse()

	dsPrefixes := strings.Split(*datasetF, ",")
	for _, p := range dsPrefixes {
		if !strings.HasSuffix(p, "/") {
			log.Fatalf("-zfs-dataset entries must end with /: %q", p)
		}
	}
	quotedPrefixes := make([]string, len(dsPrefixes))
	for i, p := range dsPrefixes {
		quotedPrefixes[i] = regexp.QuoteMeta(p)
	}

	if *step == 0 {
		*step = max(*window/2000, time.Minute)
	}

	p := &prom{
		base: strings.TrimRight(*promURL, "/"),
		hc:   &http.Client{Timeout: 30 * time.Second},
	}
	end := time.Now().UTC()
	start := end.Add(-*window)

	sel := selectors{
		sunlight:      fmt.Sprintf(`job=%q`, *logName),
		skylight:      fmt.Sprintf(`log=~%q`, *logName+".*"),
		skylightJob:   fmt.Sprintf(`job=%q`, *skylightJob),
		dataset:       fmt.Sprintf(`dataset=~%q`, "(?:"+strings.Join(quotedPrefixes, "|")+")"+regexp.QuoteMeta(*logName)+`[0-9].*`),
		process:       fmt.Sprintf(`job=~%q`, *logName+"|"+*skylightJob),
		networkDevice: fmt.Sprintf(`device=~%q`, *netDevice),
		node:          fmt.Sprintf(`job=%q`, *nodeJob),
		dsPrefixes:    dsPrefixes,
		processLabels: map[string]string{
			*logName:     "sunlight (write path)",
			*skylightJob: "skylight (read path)",
		},
	}

	page := buildPage(p, *title, start, end, *step, sel)

	if *outPath == "-" {
		if err := pageTemplate.Execute(os.Stdout, page); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := writeAtomic(*outPath, page); err != nil {
		log.Fatal(err)
	}
}

func writeAtomic(path string, page *pageData) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp.")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := pageTemplate.Execute(f, page); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0644); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// Prometheus client.

type prom struct {
	base string
	hc   *http.Client
}

type promResp struct {
	Status    string   `json:"status"`
	Data      promData `json:"data"`
	ErrorType string   `json:"errorType,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type promData struct {
	ResultType string    `json:"resultType"`
	Result     []promRes `json:"result"`
}

type promRes struct {
	Metric map[string]string `json:"metric"`
	Value  *promPoint        `json:"value,omitempty"`
	Values []promPoint       `json:"values,omitempty"`
}

type promPoint struct {
	T time.Time
	V float64
}

func (s *promPoint) UnmarshalJSON(b []byte) error {
	var a [2]json.RawMessage
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	var ts float64
	if err := json.Unmarshal(a[0], &ts); err != nil {
		return fmt.Errorf("timestamp: %w", err)
	}
	var vs string
	if err := json.Unmarshal(a[1], &vs); err != nil {
		return fmt.Errorf("value: %w", err)
	}
	v, err := strconv.ParseFloat(vs, 64)
	if err != nil {
		v = math.NaN()
	}
	frac := ts - math.Floor(ts)
	s.T = time.Unix(int64(ts), int64(frac*1e9)).UTC()
	s.V = v
	return nil
}

type series struct {
	Labels  map[string]string
	Samples []sample
}

type sample struct {
	T time.Time
	V float64
}

func (p *prom) queryInstant(expr string, t time.Time) ([]series, error) {
	v := url.Values{"query": {expr}, "time": {strconv.FormatInt(t.Unix(), 10)}}
	return p.get("/api/v1/query?" + v.Encode())
}

func (p *prom) queryRange(expr string, start, end time.Time, step time.Duration) ([]series, error) {
	v := url.Values{
		"query": {expr},
		"start": {strconv.FormatInt(start.Unix(), 10)},
		"end":   {strconv.FormatInt(end.Unix(), 10)},
		"step":  {strconv.FormatFloat(step.Seconds(), 'f', -1, 64)},
	}
	return p.get("/api/v1/query_range?" + v.Encode())
}

func (p *prom) get(q string) ([]series, error) {
	resp, err := p.hc.Get(p.base + q)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var r promResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	if r.Status != "success" {
		return nil, fmt.Errorf("%s: %s", r.ErrorType, r.Error)
	}
	out := make([]series, len(r.Data.Result))
	for i, e := range r.Data.Result {
		s := series{Labels: e.Metric}
		if e.Value != nil {
			s.Samples = []sample{{T: e.Value.T, V: e.Value.V}}
		} else {
			s.Samples = make([]sample, len(e.Values))
			for j, pp := range e.Values {
				s.Samples[j] = sample(pp)
			}
		}
		out[i] = s
	}
	return out, nil
}

// Page model.

type pageData struct {
	Title    string
	Updated  time.Time
	Window   time.Duration
	Logs     *logsTable
	Sections []section
}

type section struct {
	Title  string
	Blocks []block
}

// block is one panel of a section. Exactly one field is set.
type block struct {
	Chart   *chartPanel
	Clients *clientsTable
}

func (s *section) chart(title string, c chartPanel) {
	c.Title = title
	s.Blocks = append(s.Blocks, block{Chart: &c})
}

type chartPanel struct {
	Title  string
	SVG    template.HTML
	Legend []legendItem
	Error  string
}

type legendItem struct {
	Label string
	Color string
}

type unitKind int

const (
	unitCount unitKind = iota
	unitBytes
	unitRate
	unitSeconds
	unitCPU
	unitMbps
)

type logsTable struct {
	Rows  []logTableRow
	Total logTableRow
	Error string
}

type logTableRow struct {
	Log         string
	NotAfter    string
	Entries     string
	Growth24h   string
	OnDisk      string
	Logical     string
	Compression string
	IsTotal     bool
}

type clientsTable struct {
	Rows  []clientRow
	Total clientRow
	Error string
}

type clientRow struct {
	Family    string // display name
	Rule      string // how skylight assigns the family
	Clients   string
	Requests  string
	Egress    string
	PollEvery string
	Mix       []string // checkpoint, partial, data, tile, names, other
	Warnings  string
	IsTotal   bool
}

type chartOpts struct {
	Unit     unitKind
	Stack    bool
	LogScale bool              // logarithmic Y axis with power-of-ten ticks
	Order    []string          // explicit series order (bottom-up for stacks); unlisted labels sort last
	LabelMap map[string]string // rewrite series labels for the legend
}

type namedQuery struct {
	name string
	expr string
}

var palette = []string{
	"#0369a1", "#16a34a", "#dc2626", "#f59e0b",
	"#7c3aed", "#0891b2", "#ca8a04", "#64748b",
	"#db2777", "#65a30d", "#a16207", "#ea580c",
}

type selectors struct {
	sunlight      string   // e.g. `job="tuscolo"`
	skylight      string   // e.g. `log=~"tuscolo.*"`
	skylightJob   string   // e.g. `job="skylight"` (for metrics without a log label)
	dataset       string   // e.g. `dataset=~"(?:tank/logs/|tank/caches/)tuscolo.*"`
	process       string   // e.g. `job=~"tuscolo|skylight"`
	networkDevice string   // e.g. `device=~"enp.*"`
	node          string   // e.g. `job="node"` (node_exporter, including the ZFS textfile collector)
	dsPrefixes    []string // e.g. ["tank/logs/", "tank/caches/"] (for stripping dataset labels)
	processLabels map[string]string
}

func buildPage(p *prom, title string, start, end time.Time, step time.Duration, sel selectors) *pageData {
	page := &pageData{Title: title, Updated: end, Window: end.Sub(start)}
	page.Logs = buildTable(p, end, sel)

	sunlight := &section{Title: "Sunlight"}

	sunlight.chart("Submissions/s (per log)",
		rangeChart(p, start, end, step,
			fmt.Sprintf(`log:sunlight_addchain_requests:rate5m{%s}`, sel.sunlight),
			[]string{"log"}, chartOpts{Unit: unitRate}))

	sunlight.chart("Submissions/s (by priority)",
		rangeChart(p, start, end, step,
			fmt.Sprintf(`low_priority:sunlight_addchain_requests:rate5m{%s}`, sel.sunlight),
			[]string{"low_priority"}, chartOpts{Unit: unitRate, Stack: true,
				Order:    []string{"normal", "low"},
				LabelMap: map[string]string{"true": "low", "false": "normal"}}))

	outcome := func(name, matchers string) namedQuery {
		return namedQuery{name, fmt.Sprintf(`sum(source_error:sunlight_addchain_requests:rate5m{%s,%s})`, sel.sunlight, matchers)}
	}
	sunlight.chart("Submissions/s (per outcome)",
		multiRangeChart(p, start, end, step, []namedQuery{
			outcome("sequenced", `error="",source="sequencer"`),
			outcome("duplicate", `error="",source=~"cache|pool"`),
			outcome("rate limited", `source=~"ratelimit|evicted|duplimit"`),
			outcome("invalid", fmt.Sprintf(`error=~%q`, invalidErrors)),
			outcome("failed", fmt.Sprintf(`error!="",error!~%q,source!~"ratelimit|evicted|duplimit"`, invalidErrors)),
		}, chartOpts{Unit: unitRate}))

	// Only shards receiving a meaningful number of submissions count towards
	// the worst shard: the wait quantiles of a near-idle shard are computed
	// over a handful of samples, so they jitter without saying anything about
	// the log's health.
	active := fmt.Sprintf(`(log:sunlight_addchain_requests:rate5m{%s} > %g)`, sel.sunlight, activeShardRate)
	sunlight.chart("Submit latency (p50, p99, worst active shard, log scale)",
		rangeChart(p, start, end, step,
			fmt.Sprintf(`max by (quantile) (sunlight_addchain_wait_seconds{%s,quantile=~"0.5|0.99"} and on (job, log) %s)`, sel.sunlight, active),
			[]string{"quantile"}, chartOpts{Unit: unitSeconds, LogScale: true}))

	skylight := &section{Title: "Skylight"}

	skylight.chart("Requests/s served (per kind)",
		rangeChart(p, start, end, step,
			fmt.Sprintf(`sum by (kind) (rate(skylight_http_requests_total{%s}[5m]))`, sel.skylight),
			[]string{"kind"}, chartOpts{Unit: unitRate}))

	skylight.chart("Requests/s served (by client)",
		multiRangeChart(p, start, end, step, []namedQuery{
			{"identified", fmt.Sprintf(`sum(rate(skylight_http_requests_total{%s,client!="anonymous"}[5m]))`, sel.skylight)},
			{"anonymous", fmt.Sprintf(`sum(rate(skylight_http_requests_total{%s,client="anonymous"}[5m]))`, sel.skylight)},
		}, chartOpts{Unit: unitRate, Stack: true}))

	skylight.Blocks = append(skylight.Blocks, block{Clients: buildClientsTable(p, end, sel)})

	system := &section{Title: "System"}

	system.chart("Bandwidth",
		multiRangeChart(p, start, end, step, []namedQuery{
			{"out", fmt.Sprintf(`sum(rate(node_network_transmit_bytes_total{%s,%s}[5m]))`, sel.node, sel.networkDevice)},
			{"in", fmt.Sprintf(`sum(rate(node_network_receive_bytes_total{%s,%s}[5m]))`, sel.node, sel.networkDevice)},
		}, chartOpts{Unit: unitMbps}))

	system.chart("CPU",
		rangeChart(p, start, end, step,
			fmt.Sprintf(`sum by (job) (rate(process_cpu_seconds_total{%s}[5m]))`, sel.process),
			[]string{"job"}, chartOpts{Unit: unitCPU, LabelMap: sel.processLabels}))

	system.chart("Resident memory",
		rangeChart(p, start, end, step,
			fmt.Sprintf(`sum by (job) (process_resident_memory_bytes{%s})`, sel.process),
			[]string{"job"}, chartOpts{Unit: unitBytes, LabelMap: sel.processLabels}))

	page.Sections = []section{*sunlight, *skylight, *system}
	return page
}

// activeShardRate is the minimum submissions per second for a shard to count
// as active in the latency chart. Shards outside the current notAfter window
// see a few submissions per minute, active ones tens to hundreds per second.
const activeShardRate = 1.0

// invalidErrors matches the error categories of add-chain requests rejected
// because of their content, as opposed to failures on the log's side. The
// categories are the prefixes of the fmtErrorf format strings in
// internal/ctlog/http.go.
const invalidErrors = `invalid .*|empty chain|failed to parse request|request body too large|missing precertificate.*|pre-certificate submitted to add-chain|final certificate submitted to add-pre-chain`

func buildTable(p *prom, end time.Time, sel selectors) *logsTable {
	type rowData struct {
		entries, growth, onDisk, logical float64
		notAfterStart, notAfterEnd       float64
		hasEntries, hasDisk              bool
	}
	rows := map[string]*rowData{}
	get := func(log string) *rowData {
		r, ok := rows[log]
		if !ok {
			r = &rowData{}
			rows[log] = r
		}
		return r
	}

	scrape := func(expr string, f func(labels map[string]string, v float64)) {
		p.scrape(end, expr, f)
	}
	scrape(fmt.Sprintf(`sunlight_tree_size_leaves_total{%s}`, sel.sunlight), func(l map[string]string, v float64) {
		if name := l["log"]; name != "" {
			get(name).entries = v
			get(name).hasEntries = true
		}
	})
	scrape(fmt.Sprintf(`sunlight_tree_size_leaves_total{%s} - sunlight_tree_size_leaves_total{%s} offset 24h`, sel.sunlight, sel.sunlight), func(l map[string]string, v float64) {
		if name := l["log"]; name != "" {
			get(name).growth = v
		}
	})
	scrape(fmt.Sprintf(`sunlight_config_notafter_start_timestamp_seconds{%s}`, sel.sunlight), func(l map[string]string, v float64) {
		if name := l["log"]; name != "" {
			get(name).notAfterStart = v
		}
	})
	scrape(fmt.Sprintf(`sunlight_config_notafter_end_timestamp_seconds{%s}`, sel.sunlight), func(l map[string]string, v float64) {
		if name := l["log"]; name != "" {
			get(name).notAfterEnd = v
		}
	})
	// A shard's usage is spread across multiple parent datasets (tiles and
	// dedup cache), summed into a single row.
	scrape(fmt.Sprintf(`zfs_dataset_referenced_bytes{%s,%s}`, sel.node, sel.dataset), func(l map[string]string, v float64) {
		name := shardFromDataset(l["dataset"], sel.dsPrefixes)
		if name == "" {
			return
		}
		get(name).onDisk += v
		get(name).hasDisk = true
	})
	scrape(fmt.Sprintf(`zfs_dataset_logicalreferenced_bytes{%s,%s}`, sel.node, sel.dataset), func(l map[string]string, v float64) {
		name := shardFromDataset(l["dataset"], sel.dsPrefixes)
		if name == "" {
			return
		}
		get(name).logical += v
	})

	names := make([]string, 0, len(rows))
	for n := range rows {
		names = append(names, n)
	}
	sort.Strings(names)

	tbl := &logsTable{}
	var tot rowData
	for _, name := range names {
		r := rows[name]
		if !r.hasEntries {
			continue
		}
		tbl.Rows = append(tbl.Rows, logTableRow{
			Log:         name,
			NotAfter:    fmtNotAfter(r.notAfterStart, r.notAfterEnd),
			Entries:     fmtEntries(r.entries, r.hasEntries),
			Growth24h:   fmtGrowth(r.growth, r.hasEntries),
			OnDisk:      fmtDisk(r.onDisk, r.hasDisk),
			Logical:     fmtDisk(r.logical, r.hasDisk),
			Compression: fmtCompression(r.logical, r.onDisk, r.hasDisk),
		})
		tot.entries += r.entries
		tot.growth += r.growth
		tot.onDisk += r.onDisk
		tot.logical += r.logical
		tot.hasEntries = true
		tot.hasDisk = tot.hasDisk || r.hasDisk
	}
	tbl.Total = logTableRow{
		Log:         "total",
		Entries:     fmtEntries(tot.entries, tot.hasEntries),
		Growth24h:   fmtGrowth(tot.growth, tot.hasEntries),
		OnDisk:      fmtDisk(tot.onDisk, tot.hasDisk),
		Logical:     fmtDisk(tot.logical, tot.hasDisk),
		Compression: fmtCompression(tot.logical, tot.onDisk, tot.hasDisk),
		IsTotal:     true,
	}
	return tbl
}

// scrape runs an instant query at time t and calls f for each result.
func (p *prom) scrape(t time.Time, expr string, f func(labels map[string]string, v float64)) {
	s, err := p.queryInstant(expr, t)
	if err != nil {
		log.Printf("query %q: %v", expr, err)
		return
	}
	for _, sr := range s {
		if len(sr.Samples) == 0 || math.IsNaN(sr.Samples[0].V) {
			continue
		}
		f(sr.Labels, sr.Samples[0].V)
	}
}

// rowData holds the five-minute rates and gauges of one client family.
type rowData struct {
	clients, requests, bytes, limited float64
	checkpoint, partial, data         float64
	tile, names                       float64
	logs                              float64 // logs the family fetched checkpoints from
	partialPairs, dataPairs           float64 // distinct (client, path) pairs
	partialWindow, dataWindow         float64 // requests over the span of the pairs
}

// buildClientsTable summarizes the read path traffic of the last five minutes
// by client family. All inputs are five-minute rates or gauges over a
// five-minute window, so the derived columns compare like with like.
func buildClientsTable(p *prom, end time.Time, sel selectors) *clientsTable {
	rows := map[string]*rowData{}
	get := func(family string) *rowData {
		r, ok := rows[family]
		if !ok {
			r = &rowData{}
			rows[family] = r
		}
		return r
	}
	byFamily := func(expr string, f func(r *rowData, l map[string]string, v float64)) {
		p.scrape(end, expr, func(l map[string]string, v float64) {
			if family := l["family"]; family != "" {
				f(get(family), l, v)
			}
		})
	}

	byFamily(fmt.Sprintf(`sum by (family) (rate(skylight_http_requests_total{%s}[5m]))`, sel.skylight),
		func(r *rowData, l map[string]string, v float64) { r.requests = v })
	byFamily(fmt.Sprintf(`sum by (family) (rate(skylight_http_response_size_bytes_sum{%s}[5m]))`, sel.skylight),
		func(r *rowData, l map[string]string, v float64) { r.bytes = v })
	byFamily(fmt.Sprintf(`sum by (family) (rate(skylight_http_requests_total{%s,code="429"}[5m]))`, sel.skylight),
		func(r *rowData, l map[string]string, v float64) { r.limited = v })
	byFamily(fmt.Sprintf(`sum by (family, kind) (rate(skylight_http_requests_total{%s,kind=~"checkpoint|partial|data|tile|names"}[5m]))`, sel.skylight),
		func(r *rowData, l map[string]string, v float64) {
			switch l["kind"] {
			case "checkpoint":
				r.checkpoint = v
			case "partial":
				r.partial = v
			case "data":
				r.data = v
			case "tile":
				r.tile = v
			case "names":
				r.names = v
			}
		})
	byFamily(fmt.Sprintf(`count by (family) (sum by (family, log) (rate(skylight_http_requests_total{%s,kind="checkpoint"}[5m])) > 0)`, sel.skylight),
		func(r *rowData, l map[string]string, v float64) { r.logs = v })
	byFamily(fmt.Sprintf(`skylight_distinct_clients{%s}`, sel.skylightJob),
		func(r *rowData, l map[string]string, v float64) { r.clients = v })
	byFamily(fmt.Sprintf(`sum by (family, kind) (skylight_client_paths_distinct{%s,kind=~"partial|data"})`, sel.skylight),
		func(r *rowData, l map[string]string, v float64) {
			switch l["kind"] {
			case "partial":
				r.partialPairs = v
			case "data":
				r.dataPairs = v
			}
		})
	byFamily(fmt.Sprintf(`sum by (family, kind) (skylight_client_paths_requests{%s,kind=~"partial|data"})`, sel.skylight),
		func(r *rowData, l map[string]string, v float64) {
			switch l["kind"] {
			case "partial":
				r.partialWindow = v
			case "data":
				r.dataWindow = v
			}
		})

	families := make([]string, 0, len(rows))
	var tot rowData
	for f, r := range rows {
		// Families that made less than a request per hundred seconds would
		// all show as 0.00/s.
		if r.requests < 0.01 {
			continue
		}
		families = append(families, f)
		tot.requests += r.requests
		tot.bytes += r.bytes
		tot.limited += r.limited
		tot.checkpoint += r.checkpoint
		tot.partial += r.partial
		tot.data += r.data
		tot.tile += r.tile
		tot.names += r.names
		tot.clients += r.clients
		tot.partialPairs += r.partialPairs
		tot.dataPairs += r.dataPairs
		tot.partialWindow += r.partialWindow
		tot.dataWindow += r.dataWindow
	}
	sort.Slice(families, func(i, j int) bool {
		a, b := rows[families[i]], rows[families[j]]
		if a.bytes != b.bytes {
			return a.bytes > b.bytes
		}
		return families[i] < families[j]
	})

	row := func(family string, r *rowData) clientRow {
		return clientRow{
			Family:    familyName(family),
			Rule:      familyRule(family),
			Clients:   fmtClients(r.clients),
			Requests:  fmtRate(r.requests),
			Egress:    fmtEgress(r.bytes),
			PollEvery: fmtPollEvery(family, r.clients, r.logs, r.checkpoint),
			Mix:       fmtMix([]float64{r.checkpoint, r.partial, r.data, r.tile, r.names}, r.requests),
			Warnings:  fmtWarnings(r),
		}
	}
	tbl := &clientsTable{}
	for _, f := range families {
		tbl.Rows = append(tbl.Rows, row(f, rows[f]))
	}
	if len(tbl.Rows) == 0 {
		tbl.Error = "no data"
		return tbl
	}
	tbl.Total = row("total", &tot)
	tbl.Total.IsTotal = true
	return tbl
}

func fmtClients(v float64) string {
	if v == 0 {
		return "—"
	}
	return fmtInt(v)
}

func fmtRate(v float64) string {
	return fmtShort(v) + "/s"
}

func fmtEgress(bytes float64) string {
	return fmt.Sprintf("%.1f Mbps", bytes*8/1e6)
}

// fmtPollEvery returns the interval between checkpoint fetches by a single
// client for a single log, from the fleet's aggregate checkpoint rate. It's
// only meaningful for families made of a single program.
func fmtPollEvery(family string, clients, logs, checkpoint float64) string {
	if families[family].Mixed || clients == 0 || logs == 0 || checkpoint < 0.1 {
		return "—"
	}
	s := clients * logs / checkpoint
	if s < 10 {
		return fmt.Sprintf("%.1fs", s)
	}
	return fmt.Sprintf("%.0fs", s)
}

// fmtMix returns the percentage of total made up by each of the kinds, and by
// everything else.
func fmtMix(kinds []float64, total float64) []string {
	parts := make([]string, 0, len(kinds)+1)
	if total < 0.1 {
		for range len(kinds) + 1 {
			parts = append(parts, "—")
		}
		return parts
	}
	other := total
	for _, k := range kinds {
		other -= k
		parts = append(parts, fmt.Sprintf("%.0f", 100*k/total))
	}
	return append(parts, fmt.Sprintf("%.0f", 100*max(0, other)/total))
}

// families maps the family label values minted by skylight to display names
// and to a description of the rule skylight uses to assign them. Unlisted
// values are shown as they are. Mixed families lump together unrelated
// programs, so per-client behavior can't be inferred from their aggregates.
var families = map[string]struct {
	Name, Rule string
	Mixed      bool
}{
	"certstream-go":        {"Certstream Server Go", `User-Agent starts with "Certstream Server", version ≥ 1.10.0`, false},
	"certstream-go-legacy": {"Certstream Server Go (< 1.10.0)", `User-Agent starts with "Certstream Server", version < 1.10.0`, false},
	"certstream-rust":      {"certstream-server-rust", `User-Agent starts with "certstream-server-rust/"`, false},
	"certspotter":          {"Cert Spotter", `User-Agent starts with "certspotter/"`, false},
	"gungnir":              {"gungnir", `User-Agent starts with "gungnir +https://github.com/g0ldencybersec/gungnir"`, false},
	"gungnir-rix4uni":      {"gungnir (rix4uni fork)", `User-Agent starts with "gungnir +https://github.com/rix4uni/gungnir"`, false},
	"linkdata-certstream":  {"linkdata/certstream", `User-Agent starts with "certstream (+https://github.com/linkdata/certstream)"`, false},
	"crlite":               {"Mozilla CRLite", `User-Agent starts with "ct-fetch; +https://github.com/mozilla/crlite"`, false},
	"crtsh":                {"crt.sh", `User-Agent starts with "github.com/crtsh/"`, false},
	"google-ct-bot":        {"Google CT bot", `User-Agent starts with "Google-CT-bot"`, false},
	"sunlight":             {"filippo.io/sunlight clients", `User-Agent contains " sunlight/v" and matches no other family`, false},
	"go-http-client-1.1":   {"Go net/http default (HTTP/1.1)", `User-Agent starts with "Go-http-client/1.1"`, true},
	"go-http-client-2.0":   {"Go net/http default (HTTP/2)", `User-Agent starts with "Go-http-client/2.0"`, true},
	"python-httpx":         {"Python httpx default", `User-Agent starts with "python-httpx/"`, true},
	"python-requests":      {"Python requests default", `User-Agent starts with "python-requests/"`, true},
	"python":               {"Python default", `User-Agent starts with "Python/"`, true},
	"curl":                 {"curl default", `User-Agent starts with "curl/"`, true},
	"restsharp":            {"RestSharp default", `User-Agent starts with "RestSharp/"`, true},
	"req":                  {"req default", `User-Agent starts with "req/"`, true},
	"node":                 {"Node.js default", `User-Agent starts with "node"`, true},
	"undici":               {"undici default", `User-Agent starts with "undici"`, true},
	"axios":                {"axios default", `User-Agent starts with "axios/"`, true},
	"node-fetch":           {"node-fetch default", `User-Agent starts with "node-fetch"`, true},
	"ruby":                 {"Ruby default", `User-Agent starts with "Ruby"`, true},
	"browser":              {"Browser", `User-Agent starts with "Mozilla/5.0"`, true},
	"empty":                {"No User-Agent", `No User-Agent header`, true},
	"hetrixtools":          {"HetrixTools", `User-Agent starts with "HetrixTools Uptime Monitoring Bot"`, false},
	"prometheus":           {"Prometheus", `User-Agent starts with "Prometheus/"`, false},
	"other":                {"Other", `No other family matched`, true},
	"total":                {"total", `All families listed above`, true},
}

func familyName(label string) string {
	if f, ok := families[label]; ok {
		return f.Name
	}
	return label
}

func familyRule(label string) string {
	if f, ok := families[label]; ok {
		return f.Rule
	}
	return label
}

func fmtWarnings(r *rowData) string {
	var w []string
	if d := dupRatio(r.partialWindow, r.partialPairs); d >= 2 {
		w = append(w, fmt.Sprintf("partial dup %.1f×", d))
	}
	if d := dupRatio(r.dataWindow, r.dataPairs); d >= 2 {
		w = append(w, fmt.Sprintf("data dup %.1f×", d))
	}
	if r.limited > 0 && r.requests > 0 {
		if share := 100 * r.limited / r.requests; share < 1 {
			w = append(w, "limited <1%")
		} else {
			w = append(w, fmt.Sprintf("limited %.0f%%", share))
		}
	}
	return strings.Join(w, ", ")
}

// dupRatio returns how many times each client requested each distinct path,
// from the requests and the distinct (client, path) pairs over the same span,
// or 0 if there were too few requests to tell.
func dupRatio(requests, pairs float64) float64 {
	if requests < 30 || pairs < 1 {
		return 0
	}
	return requests / pairs
}

func shardFromDataset(ds string, prefixes []string) string {
	for _, p := range prefixes {
		if name := strings.TrimPrefix(ds, p); name != ds && name != "" {
			return name
		}
	}
	return ""
}

func fmtNotAfter(start, end float64) string {
	if start == 0 || end == 0 {
		return "—"
	}
	s := time.Unix(int64(start), 0).UTC().Format("2006-01")
	e := time.Unix(int64(end), 0).UTC().Format("2006-01")
	return s + " — " + e
}

func fmtEntries(v float64, ok bool) string {
	if !ok {
		return "—"
	}
	return fmtInt(v)
}

func fmtGrowth(v float64, ok bool) string {
	if !ok {
		return "—"
	}
	return "+" + fmtInt(v)
}

func fmtDisk(v float64, ok bool) string {
	if !ok {
		return "—"
	}
	return fmtBytes(v)
}

func fmtCompression(logical, compressed float64, ok bool) string {
	if !ok || compressed == 0 {
		return "—"
	}
	return fmt.Sprintf("%.2f×", logical/compressed)
}

func rangeChart(p *prom, start, end time.Time, step time.Duration, expr string, labels []string, o chartOpts) chartPanel {
	s, err := p.queryRange(expr, start, end, step)
	if err != nil {
		return chartPanel{Error: err.Error()}
	}
	cs := make([]chartSeries, 0, len(s))
	for _, sr := range s {
		lbl := pickLabel(sr.Labels, labels)
		if v, ok := o.LabelMap[lbl]; ok {
			lbl = v
		}
		cs = append(cs, chartSeries{
			Label:   lbl,
			Samples: sr.Samples,
		})
	}
	if len(o.Order) > 0 {
		rank := func(s chartSeries) int {
			if i := slices.Index(o.Order, s.Label); i >= 0 {
				return i
			}
			return len(o.Order)
		}
		sort.SliceStable(cs, func(i, j int) bool { return rank(cs[i]) < rank(cs[j]) })
	} else if o.Stack {
		// Largest series at the bottom of the stack.
		sort.SliceStable(cs, func(i, j int) bool { return seriesTotal(cs[i]) > seriesTotal(cs[j]) })
	} else {
		sort.SliceStable(cs, func(i, j int) bool { return cs[i].Label < cs[j].Label })
	}
	for i := range cs {
		cs[i].Color = palette[i%len(palette)]
	}
	return renderChart(cs, start, end, o)
}

func multiRangeChart(p *prom, start, end time.Time, step time.Duration, queries []namedQuery, o chartOpts) chartPanel {
	var cs []chartSeries
	for i, q := range queries {
		s, err := p.queryRange(q.expr, start, end, step)
		if err != nil {
			return chartPanel{Error: fmt.Sprintf("%s: %v", q.name, err)}
		}
		if len(s) == 0 {
			continue
		}
		cs = append(cs, chartSeries{
			Label:   q.name,
			Color:   palette[i%len(palette)],
			Samples: s[0].Samples,
		})
	}
	return renderChart(cs, start, end, o)
}

func pickLabel(lbls map[string]string, preferred []string) string {
	for _, k := range preferred {
		if v, ok := lbls[k]; ok && v != "" {
			if k == "instance" {
				if i := strings.IndexByte(v, ':'); i > 0 {
					v = v[:i]
				}
			}
			return v
		}
	}
	keys := make([]string, 0, len(lbls))
	for k := range lbls {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v := lbls[k]; v != "" {
			return v
		}
	}
	return "—"
}

// SVG chart rendering.

type chartSeries struct {
	Label   string
	Color   string
	Samples []sample
}

const (
	chartW = 900
	chartH = 220
	padL   = 60
	padR   = 16
	padT   = 10
	padB   = 22
)

func renderChart(cs []chartSeries, start, end time.Time, o chartOpts) chartPanel {
	if len(cs) == 0 {
		return chartPanel{Error: "no data"}
	}
	var yOf func(v float64) float64
	var yTicks []float64
	if o.LogScale {
		lmin, lmax, ok := logYAxis(cs)
		if !ok {
			return chartPanel{Error: "no data"}
		}
		logMin, logMax := math.Log10(lmin), math.Log10(lmax)
		yOf = func(v float64) float64 {
			// Clamp non-positive and off-scale-low values to the bottom edge.
			if v < lmin {
				v = lmin
			}
			return yPx(math.Log10(v), logMin, logMax)
		}
		for d := logMin; d <= logMax+1e-6; d++ {
			yTicks = append(yTicks, math.Pow(10, d))
		}
	} else {
		vmin, vmax, ok := seriesRange(cs)
		if !ok {
			return chartPanel{Error: "no data"}
		}
		if o.Stack {
			vmin = 0
			vmax = stackMax(cs)
		}
		if vmin > 0 {
			vmin = 0
		}
		if vmax <= vmin {
			vmax = vmin + 1
		}
		niceMin, niceMax, tick := niceYAxis(vmin, vmax)
		yOf = func(v float64) float64 { return yPx(v, niceMin, niceMax) }
		for y := niceMin; y <= niceMax+tick*1e-6; y += tick {
			yTicks = append(yTicks, y)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet">`, chartW, chartH)

	fmt.Fprintf(&b, `<g font-size="10" fill="#999" font-family="-apple-system,system-ui,sans-serif">`)
	for _, y := range yTicks {
		py := yOf(y)
		fmt.Fprintf(&b, `<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="#eee"/>`, padL, py, chartW-padR, py)
		fmt.Fprintf(&b, `<text x="%d" y="%.1f" text-anchor="end">%s</text>`,
			padL-4, py+3, html.EscapeString(fmtAxis(y, o.Unit)))
	}
	for _, t := range xTicks(start, end) {
		px := xPx(t, start, end)
		fmt.Fprintf(&b, `<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="#eee"/>`, px, padT, px, chartH-padB)
		fmt.Fprintf(&b, `<text x="%.1f" y="%d" text-anchor="middle">%s</text>`,
			px, chartH-padB+12, html.EscapeString(fmtXTick(t, end.Sub(start))))
	}
	fmt.Fprintf(&b, `</g>`)

	if o.Stack {
		renderStack(&b, cs, start, end, yOf)
	} else {
		for _, s := range cs {
			renderLine(&b, s, start, end, yOf)
		}
	}
	fmt.Fprintf(&b, `</svg>`)

	var legend []legendItem
	if len(cs) > 1 {
		legend = make([]legendItem, len(cs))
		for i, s := range cs {
			legend[i] = legendItem{Label: s.Label, Color: s.Color}
		}
	}
	return chartPanel{SVG: template.HTML(b.String()), Legend: legend}
}

func seriesRange(cs []chartSeries) (min, max float64, ok bool) {
	for _, s := range cs {
		for _, p := range s.Samples {
			if math.IsNaN(p.V) {
				continue
			}
			if !ok || p.V < min {
				min = p.V
			}
			if !ok || p.V > max {
				max = p.V
			}
			ok = true
		}
	}
	return
}

// logYAxis returns power-of-ten axis bounds covering the positive values in
// cs, spanning at most six decades below the maximum.
func logYAxis(cs []chartSeries) (min, max float64, ok bool) {
	for _, s := range cs {
		for _, p := range s.Samples {
			if math.IsNaN(p.V) || p.V <= 0 {
				continue
			}
			if !ok || p.V < min {
				min = p.V
			}
			if !ok || p.V > max {
				max = p.V
			}
			ok = true
		}
	}
	if !ok {
		return 0, 0, false
	}
	lo := math.Floor(math.Log10(min))
	hi := math.Ceil(math.Log10(max))
	if hi == lo {
		hi++
	}
	if lo < hi-6 {
		lo = hi - 6
	}
	return math.Pow(10, lo), math.Pow(10, hi), true
}

func seriesTotal(s chartSeries) float64 {
	var t float64
	for _, p := range s.Samples {
		if !math.IsNaN(p.V) {
			t += p.V
		}
	}
	return t
}

func stackMax(cs []chartSeries) float64 {
	sums := map[int64]float64{}
	for _, s := range cs {
		for _, p := range s.Samples {
			if math.IsNaN(p.V) {
				continue
			}
			sums[p.T.Unix()] += p.V
		}
	}
	var m float64
	for _, v := range sums {
		if v > m {
			m = v
		}
	}
	return m
}

func xPx(t, start, end time.Time) float64 {
	dur := end.Sub(start).Seconds()
	if dur <= 0 {
		return padL
	}
	return float64(padL) + t.Sub(start).Seconds()/dur*float64(chartW-padL-padR)
}

func yPx(v, ymin, ymax float64) float64 {
	span := ymax - ymin
	if span == 0 {
		return float64(chartH - padB)
	}
	return float64(padT) + (ymax-v)/span*float64(chartH-padT-padB)
}

func renderLine(b *strings.Builder, s chartSeries, start, end time.Time, yOf func(float64) float64) {
	var pts []string
	flush := func() {
		if len(pts) >= 2 {
			fmt.Fprintf(b, `<polyline fill="none" stroke="%s" stroke-width="1.3" stroke-linejoin="round" points="%s"/>`,
				s.Color, strings.Join(pts, " "))
		} else if len(pts) == 1 {
			parts := strings.Split(pts[0], ",")
			fmt.Fprintf(b, `<circle cx="%s" cy="%s" r="1.5" fill="%s"/>`, parts[0], parts[1], s.Color)
		}
		pts = nil
	}
	for _, p := range s.Samples {
		if math.IsNaN(p.V) {
			flush()
			continue
		}
		pts = append(pts, fmt.Sprintf("%.1f,%.1f", xPx(p.T, start, end), yOf(p.V)))
	}
	flush()
}

func renderStack(b *strings.Builder, cs []chartSeries, start, end time.Time, yOf func(float64) float64) {
	tsSet := map[int64]struct{}{}
	for _, s := range cs {
		for _, p := range s.Samples {
			tsSet[p.T.Unix()] = struct{}{}
		}
	}
	ts := make([]int64, 0, len(tsSet))
	for t := range tsSet {
		ts = append(ts, t)
	}
	slices.Sort(ts)

	running := make([]float64, len(ts))
	for _, s := range cs {
		vals := map[int64]float64{}
		for _, p := range s.Samples {
			vals[p.T.Unix()] = p.V
		}
		top := make([]float64, len(ts))
		for j, t := range ts {
			v, ok := vals[t]
			if !ok || math.IsNaN(v) {
				v = 0
			}
			top[j] = running[j] + v
		}
		var pts []string
		for j, t := range ts {
			pts = append(pts, fmt.Sprintf("%.1f,%.1f",
				xPx(time.Unix(t, 0), start, end), yOf(top[j])))
		}
		for j := len(ts) - 1; j >= 0; j-- {
			pts = append(pts, fmt.Sprintf("%.1f,%.1f",
				xPx(time.Unix(ts[j], 0), start, end), yOf(running[j])))
		}
		fmt.Fprintf(b, `<polygon fill="%s" fill-opacity="0.55" stroke="%s" stroke-width="0.8" points="%s"/>`,
			s.Color, s.Color, strings.Join(pts, " "))
		for j := range ts {
			running[j] = top[j]
		}
	}
}

func niceYAxis(vmin, vmax float64) (float64, float64, float64) {
	span := vmax - vmin
	if span <= 0 {
		return vmin, vmin + 1, 1
	}
	raw := span / 4
	mag := math.Pow(10, math.Floor(math.Log10(raw)))
	norm := raw / mag
	var step float64
	switch {
	case norm <= 1:
		step = mag
	case norm <= 2:
		step = 2 * mag
	case norm <= 5:
		step = 5 * mag
	default:
		step = 10 * mag
	}
	return math.Floor(vmin/step) * step, math.Ceil(vmax/step) * step, step
}

func xTicks(start, end time.Time) []time.Time {
	dur := end.Sub(start)
	var interval time.Duration
	switch {
	case dur <= time.Hour:
		interval = 10 * time.Minute
	case dur <= 6*time.Hour:
		interval = time.Hour
	case dur <= 24*time.Hour:
		interval = 4 * time.Hour
	case dur <= 3*24*time.Hour:
		interval = 12 * time.Hour
	case dur <= 14*24*time.Hour:
		interval = 24 * time.Hour
	default:
		interval = 7 * 24 * time.Hour
	}
	t := start.Truncate(interval)
	if !t.After(start) {
		t = t.Add(interval)
	}
	var out []time.Time
	for t.Before(end) {
		out = append(out, t)
		t = t.Add(interval)
	}
	return out
}

func fmtXTick(t time.Time, dur time.Duration) string {
	if dur <= 24*time.Hour {
		return t.Format("15:04")
	}
	if dur <= 14*24*time.Hour {
		return t.Format("Mon 15:04")
	}
	return t.Format("Jan 02")
}

// Value formatting.

func fmtInt(v float64) string {
	s := strconv.FormatFloat(math.Round(v), 'f', 0, 64)
	return insertSep(s)
}

func insertSep(s string) string {
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	if neg {
		s = "-" + s
	}
	return s
}

func fmtBytes(v float64) string {
	const unit = 1024.0
	if math.Abs(v) < unit {
		return fmt.Sprintf("%.0f B", v)
	}
	div, exp := unit, 0
	for n := math.Abs(v) / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", v/div, "KMGTPE"[exp])
}

func fmtBytesShort(v float64) string {
	const unit = 1024.0
	if math.Abs(v) < unit {
		return fmt.Sprintf("%.0f", v)
	}
	div, exp := unit, 0
	for n := math.Abs(v) / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", v/div, "KMGTPE"[exp])
}

func fmtShort(v float64) string {
	av := math.Abs(v)
	switch {
	case av < 1:
		return strconv.FormatFloat(v, 'f', 2, 64)
	case av < 1000:
		if v == math.Trunc(v) {
			return strconv.FormatFloat(v, 'f', 0, 64)
		}
		return strconv.FormatFloat(v, 'f', 1, 64)
	case av < 1e6:
		return fmt.Sprintf("%.1fk", v/1e3)
	case av < 1e9:
		return fmt.Sprintf("%.2fM", v/1e6)
	case av < 1e12:
		return fmt.Sprintf("%.2fG", v/1e9)
	default:
		return fmt.Sprintf("%.2fT", v/1e12)
	}
}

func fmtSeconds(v float64) string {
	av := math.Abs(v)
	switch {
	case av < 1e-6:
		return fmt.Sprintf("%.0fns", v*1e9)
	case av < 1e-3:
		return fmt.Sprintf("%.0fµs", v*1e6)
	case av < 1:
		return fmt.Sprintf("%.0fms", v*1e3)
	default:
		return fmt.Sprintf("%.2fs", v)
	}
}

func fmtAxis(v float64, u unitKind) string {
	if v == 0 {
		return "0"
	}
	switch u {
	case unitBytes:
		return fmtBytesShort(v)
	case unitRate:
		return fmtShort(v) + "/s"
	case unitSeconds:
		return fmtSeconds(v)
	case unitCPU:
		return fmt.Sprintf("%.2f", v)
	case unitMbps:
		return fmt.Sprintf("%.0f Mbps", v/125000)
	default:
		return fmtShort(v)
	}
}

// HTML template.

const pageTmpl = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
html, body { margin: 0; }
body { font: 14px/1.4 -apple-system, "SF Pro Text", "Segoe UI", system-ui, sans-serif; color: #222; background: #fafafa; }
main { max-width: 960px; margin: 24px auto; padding: 0 16px; }
h1 { font-size: 22px; font-weight: 600; margin: 0 0 2px; }
h2 { font-size: 17px; font-weight: 600; margin: 28px 0 10px; }
.updated { color: #888; font-size: 12px; margin-bottom: 20px; font-variant-numeric: tabular-nums; }
.table-wrap { background: white; border: 1px solid #e5e5e5; border-radius: 6px; padding: 10px 14px; margin-bottom: 14px; overflow-x: auto; }
table.logs { border-collapse: collapse; width: 100%; font-variant-numeric: tabular-nums; }
table.logs th, table.logs td { padding: 6px 10px; text-align: right; white-space: nowrap; }
table.logs th:first-child, table.logs td:first-child { text-align: left; }
table.logs th { font-size: 11px; font-weight: 600; color: #666; text-transform: uppercase; letter-spacing: 0.03em; border-bottom: 1px solid #e5e5e5; }
table.logs tr.total td { border-top: 1px solid #e5e5e5; font-weight: 600; }
table.logs td.log { font-family: ui-monospace, Menlo, monospace; }
table.logs th[title] { text-decoration: underline dotted; cursor: help; }
.scroll { max-height: 480px; overflow-y: auto; }
table.clients thead th { position: sticky; top: 0; background: white; border-bottom: none; box-shadow: inset 0 -1px #e5e5e5; }
table.clients th.mix, table.clients td.mix { width: 2.2em; padding-left: 0; padding-right: 0; text-align: center; }
table.clients th.mix.first, table.clients td.mix.first { padding-left: 10px; }
table.clients th.mix.last, table.clients td.mix.last { padding-right: 10px; }
table.clients th.warn, table.clients td.warn { text-align: left; }
table.clients td.warn { color: #b91c1c; }
.table-wrap h3 { font-size: 12px; font-weight: 600; margin: 0 0 6px; color: #555; letter-spacing: 0.02em; text-transform: uppercase; }
.chart { background: white; border: 1px solid #e5e5e5; border-radius: 6px; padding: 10px 14px; margin-bottom: 14px; }
.chart h3 { font-size: 12px; font-weight: 600; margin: 0 0 6px; color: #555; letter-spacing: 0.02em; text-transform: uppercase; }
.chart svg { display: block; width: 100%; height: auto; }
.legend { font-size: 11px; color: #555; margin-top: 6px; display: flex; flex-wrap: wrap; gap: 10px; }
.legend span { display: inline-flex; align-items: center; gap: 5px; }
.legend i { display: inline-block; width: 10px; height: 10px; border-radius: 2px; }
.error { color: #b91c1c; font-size: 12px; padding: 20px 0; font-family: ui-monospace, Menlo, monospace; }
footer { color: #aaa; font-size: 11px; margin: 24px 0; text-align: center; }
footer a { color: inherit; }
</style>
</head>
<body>
<main>
<h1>{{.Title}}</h1>
<div class="updated">Updated {{.Updated.Format "2006-01-02 15:04:05 MST"}} · last {{fmtDur .Window}}</div>
{{template "logs" .Logs}}
{{range .Sections}}<h2>{{.Title}}</h2>
{{range .Blocks}}{{if .Clients}}{{template "clients" .Clients}}{{else}}{{template "chart" .Chart}}{{end}}
{{end}}{{end}}<footer><a href="https://github.com/FiloSottile/sunlight/tree/main/cmd/heliograph-dashboard">heliograph-dashboard</a></footer>
</main>
</body>
</html>
{{define "chart"}}<div class="chart">
<h3>{{.Title}}</h3>
{{if .Error}}<div class="error">{{.Error}}</div>{{else}}{{.SVG}}{{end}}
{{if .Legend}}<div class="legend">{{range .Legend}}<span><i style="background:{{.Color}}"></i>{{.Label}}</span>{{end}}</div>{{end}}
</div>{{end}}
{{define "logs"}}<div class="table-wrap">
{{if .Error}}<div class="error">{{.Error}}</div>{{else}}<table class="logs">
<thead><tr><th>Log</th><th>NotAfter</th><th>Entries</th><th>/24h</th><th>On disk</th><th>Logical</th><th>Compression</th></tr></thead>
<tbody>
{{range .Rows}}<tr><td class="log">{{.Log}}</td><td>{{.NotAfter}}</td><td>{{.Entries}}</td><td>{{.Growth24h}}</td><td>{{.OnDisk}}</td><td>{{.Logical}}</td><td>{{.Compression}}</td></tr>
{{end}}<tr class="total"><td class="log">{{.Total.Log}}</td><td></td><td>{{.Total.Entries}}</td><td>{{.Total.Growth24h}}</td><td>{{.Total.OnDisk}}</td><td>{{.Total.Logical}}</td><td>{{.Total.Compression}}</td></tr>
</tbody></table>{{end}}
</div>{{end}}
{{define "clients"}}<div class="table-wrap">
<h3>Clients (last 5 minutes)</h3>
{{if .Error}}<div class="error">{{.Error}}</div>{{else}}<div class="scroll"><table class="logs clients">
<thead><tr>
<th title="Client software, from the User-Agent. 'default' families sent a bare HTTP library User-Agent. Anything unrecognized is Other. Hover a name for the matching rule.">Family</th>
<th title="Distinct client IP addresses (IPv6 by /64) across all logs on this host. Estimated with HyperLogLog, ±2%. — means none were seen.">Clients</th>
<th title="Requests per second, all kinds. Families below 0.01/s are not listed.">Req/s</th>
<th title="Response bytes per second, in megabits.">Egress</th>
<th title="Seconds between checkpoint fetches by one client for one log: clients × logs polled ÷ checkpoint requests per second. Lower is more aggressive polling. — for families that lump together unrelated programs, and when there are fewer than 0.1 checkpoint requests per second.">Poll</th>
<th class="mix first" title="Checkpoint requests, % of all requests. Tailing clients are mostly checkpoints and partials; backfilling ones are mostly data tiles. — means fewer than 0.1 requests per second.">C</th>
<th class="mix" title="Partial data tile requests, % of all requests.">P</th>
<th class="mix" title="Full data tile requests, % of all requests.">D</th>
<th class="mix" title="Hash tile requests, % of all requests.">H</th>
<th class="mix" title="Names tile requests, % of all requests.">N</th>
<th class="mix last" title="Other requests (issuers, metadata, logs.json, health), % of all requests.">O</th>
<th class="warn" title="partial dup / data dup: requests per client per distinct partial or full data tile path over the window, shown when 2× or more; well-behaved clients are near 1×. limited: share of requests rejected with 429; only anonymous clients (no contact in the User-Agent) are rate limited this way.">Warnings</th>
</tr></thead>
<tbody>
{{range .Rows}}<tr><td title="{{.Rule}}">{{.Family}}</td><td>{{.Clients}}</td><td>{{.Requests}}</td><td>{{.Egress}}</td><td>{{.PollEvery}}</td>{{template "mix" .Mix}}<td class="warn">{{.Warnings}}</td></tr>
{{end}}<tr class="total"><td title="{{.Total.Rule}}">{{.Total.Family}}</td><td>{{.Total.Clients}}</td><td>{{.Total.Requests}}</td><td>{{.Total.Egress}}</td><td>{{.Total.PollEvery}}</td>{{template "mix" .Total.Mix}}<td class="warn">{{.Total.Warnings}}</td></tr>
</tbody></table></div>{{end}}
</div>{{end}}
{{define "mix"}}{{range $i, $v := .}}<td class="mix{{if eq $i 0}} first{{end}}{{if eq $i 5}} last{{end}}">{{$v}}</td>{{end}}{{end}}
`

var pageTemplate = template.Must(template.New("page").Funcs(template.FuncMap{
	"fmtDur": func(d time.Duration) string {
		switch {
		case d >= 24*time.Hour && d%(24*time.Hour) == 0:
			return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
		case d >= time.Hour && d%time.Hour == 0:
			return fmt.Sprintf("%dh", int(d/time.Hour))
		default:
			return d.String()
		}
	},
}).Parse(pageTmpl))
