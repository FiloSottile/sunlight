// Command heliograph-dashboard generates a static HTML dashboard summarising a
// Sunlight CT log's cost and activity from Prometheus metrics.
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
		datasetF    = flag.String("zfs-dataset", "tank/logs/", "ZFS parent dataset (must end with /)")
		netDevice   = flag.String("network-device", "enp.*", "regex for physical NIC device labels")
	)
	flag.Parse()

	if !strings.HasSuffix(*datasetF, "/") {
		log.Fatalf("-zfs-dataset must end with /: %q", *datasetF)
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
		dataset:       fmt.Sprintf(`dataset=~%q`, regexp.QuoteMeta(*datasetF+*logName)+`[0-9].*`),
		process:       fmt.Sprintf(`job=~%q`, *logName+"|"+*skylightJob),
		networkDevice: fmt.Sprintf(`device=~%q`, *netDevice),
		dsPrefix:      *datasetF,
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
				s.Samples[j] = sample{T: pp.T, V: pp.V}
			}
		}
		out[i] = s
	}
	return out, nil
}

// Page model.

type pageData struct {
	Title   string
	Updated time.Time
	Window  time.Duration
	Table   *logsTable
	Charts  []chartPanel
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

type chartOpts struct {
	Unit     unitKind
	Stack    bool
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
	sunlight      string // e.g. `job="tuscolo"`
	skylight      string // e.g. `log=~"tuscolo.*"`
	dataset       string // e.g. `dataset=~"tank/logs/tuscolo.*"`
	process       string // e.g. `job=~"tuscolo|skylight"`
	networkDevice string // e.g. `device=~"enp.*"`
	dsPrefix      string // e.g. "tank/logs/" (for stripping dataset labels)
}

func buildPage(p *prom, title string, start, end time.Time, step time.Duration, sel selectors) *pageData {
	page := &pageData{Title: title, Updated: end, Window: end.Sub(start)}

	page.Table = buildTable(p, end, sel)

	add := func(title string, c chartPanel) {
		c.Title = title
		page.Charts = append(page.Charts, c)
	}

	add("Submissions/s (per log)",
		rangeChart(p, start, end, step,
			fmt.Sprintf(`sum by (log) (rate(sunlight_addchain_requests_total{%s,error=""}[5m]))`, sel.sunlight),
			[]string{"log"}, chartOpts{Unit: unitRate}))

	add("Submissions/s (by priority)",
		rangeChart(p, start, end, step,
			fmt.Sprintf(`sum by (low_priority) (rate(sunlight_addchain_requests_total{%s,error=""}[5m]))`, sel.sunlight),
			[]string{"low_priority"}, chartOpts{Unit: unitRate, Stack: true,
				LabelMap: map[string]string{"true": "low", "false": "normal"}}))

	add("Submit latency (p50, p99, worst shard)",
		rangeChart(p, start, end, step,
			fmt.Sprintf(`max by (quantile) (sunlight_addchain_wait_seconds{%s,quantile=~"0.5|0.99"})`, sel.sunlight),
			[]string{"quantile"}, chartOpts{Unit: unitSeconds}))

	add("Requests/s served (by kind)",
		rangeChart(p, start, end, step,
			fmt.Sprintf(`sum by (kind) (rate(skylight_http_requests_total{%s}[5m]))`, sel.skylight),
			[]string{"kind"}, chartOpts{Unit: unitRate, Stack: true}))

	add("Requests/s served (by client)",
		rangeChart(p, start, end, step,
			fmt.Sprintf(`sum by (client) (rate(skylight_http_requests_total{%s}[5m]))`, sel.skylight),
			[]string{"client"}, chartOpts{Unit: unitRate, Stack: true}))

	add("Bandwidth (system-wide)",
		multiRangeChart(p, start, end, step, []namedQuery{
			{"out", fmt.Sprintf(`sum(rate(node_network_transmit_bytes_total{%s}[5m]))`, sel.networkDevice)},
			{"in", fmt.Sprintf(`-sum(rate(node_network_receive_bytes_total{%s}[5m]))`, sel.networkDevice)},
		}, chartOpts{Unit: unitMbps}))

	add("CPU",
		rangeChart(p, start, end, step,
			fmt.Sprintf(`sum by (job) (rate(process_cpu_seconds_total{%s}[5m]))`, sel.process),
			[]string{"job"}, chartOpts{Unit: unitCPU}))

	add("Resident memory",
		rangeChart(p, start, end, step,
			fmt.Sprintf(`sum by (job) (process_resident_memory_bytes{%s})`, sel.process),
			[]string{"job"}, chartOpts{Unit: unitBytes}))

	return page
}

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
		s, err := p.queryInstant(expr, end)
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
	scrape(fmt.Sprintf(`zfs_dataset_referenced_bytes{%s}`, sel.dataset), func(l map[string]string, v float64) {
		ds := l["dataset"]
		name := strings.TrimPrefix(ds, sel.dsPrefix)
		if name == "" || name == ds {
			return
		}
		get(name).onDisk = v
		get(name).hasDisk = true
	})
	scrape(fmt.Sprintf(`zfs_dataset_logicalreferenced_bytes{%s}`, sel.dataset), func(l map[string]string, v float64) {
		ds := l["dataset"]
		name := strings.TrimPrefix(ds, sel.dsPrefix)
		if name == "" || name == ds {
			return
		}
		get(name).logical = v
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
	if o.Stack {
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

	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet">`, chartW, chartH)

	fmt.Fprintf(&b, `<g font-size="10" fill="#999" font-family="-apple-system,system-ui,sans-serif">`)
	for y := niceMin; y <= niceMax+tick*1e-6; y += tick {
		py := yPx(y, niceMin, niceMax)
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
		renderStack(&b, cs, start, end, niceMin, niceMax)
	} else {
		for _, s := range cs {
			renderLine(&b, s, start, end, niceMin, niceMax)
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

func renderLine(b *strings.Builder, s chartSeries, start, end time.Time, ymin, ymax float64) {
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
		pts = append(pts, fmt.Sprintf("%.1f,%.1f", xPx(p.T, start, end), yPx(p.V, ymin, ymax)))
	}
	flush()
}

func renderStack(b *strings.Builder, cs []chartSeries, start, end time.Time, ymin, ymax float64) {
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
				xPx(time.Unix(t, 0), start, end), yPx(top[j], ymin, ymax)))
		}
		for j := len(ts) - 1; j >= 0; j-- {
			pts = append(pts, fmt.Sprintf("%.1f,%.1f",
				xPx(time.Unix(ts[j], 0), start, end), yPx(running[j], ymin, ymax)))
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
.updated { color: #888; font-size: 12px; margin-bottom: 20px; font-variant-numeric: tabular-nums; }
.table-wrap { background: white; border: 1px solid #e5e5e5; border-radius: 6px; padding: 10px 14px; margin-bottom: 14px; overflow-x: auto; }
table.logs { border-collapse: collapse; width: 100%; font-variant-numeric: tabular-nums; }
table.logs th, table.logs td { padding: 6px 10px; text-align: right; white-space: nowrap; }
table.logs th:first-child, table.logs td:first-child { text-align: left; }
table.logs th { font-size: 11px; font-weight: 600; color: #666; text-transform: uppercase; letter-spacing: 0.03em; border-bottom: 1px solid #e5e5e5; }
table.logs tr.total td { border-top: 1px solid #e5e5e5; font-weight: 600; }
table.logs td.log { font-family: ui-monospace, Menlo, monospace; }
.chart { background: white; border: 1px solid #e5e5e5; border-radius: 6px; padding: 10px 14px; margin-bottom: 14px; }
.chart h2 { font-size: 12px; font-weight: 600; margin: 0 0 6px; color: #555; letter-spacing: 0.02em; text-transform: uppercase; }
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
{{with .Table}}<div class="table-wrap">
{{if .Error}}<div class="error">{{.Error}}</div>{{else}}<table class="logs">
<thead><tr><th>Log</th><th>NotAfter</th><th>Entries</th><th>/24h</th><th>On disk</th><th>Logical</th><th>Compression</th></tr></thead>
<tbody>
{{range .Rows}}<tr><td class="log">{{.Log}}</td><td>{{.NotAfter}}</td><td>{{.Entries}}</td><td>{{.Growth24h}}</td><td>{{.OnDisk}}</td><td>{{.Logical}}</td><td>{{.Compression}}</td></tr>
{{end}}<tr class="total"><td class="log">{{.Total.Log}}</td><td></td><td>{{.Total.Entries}}</td><td>{{.Total.Growth24h}}</td><td>{{.Total.OnDisk}}</td><td>{{.Total.Logical}}</td><td>{{.Total.Compression}}</td></tr>
</tbody></table>{{end}}
</div>{{end}}
{{range .Charts}}<div class="chart">
<h2>{{.Title}}</h2>
{{if .Error}}<div class="error">{{.Error}}</div>{{else}}{{.SVG}}{{end}}
{{if .Legend}}<div class="legend">{{range .Legend}}<span><i style="background:{{.Color}}"></i>{{.Label}}</span>{{end}}</div>{{end}}
</div>
{{end}}<footer><a href="https://github.com/FiloSottile/sunlight/tree/main/cmd/heliograph-dashboard">heliograph-dashboard</a></footer>
</main>
</body>
</html>`

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
