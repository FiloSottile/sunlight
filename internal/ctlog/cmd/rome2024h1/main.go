package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"time"

	"filippo.io/litetlog/internal/ctlog"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	createFlag := flag.Bool("create", false, "create the log")
	debugFlag := flag.Bool("debug", false, "verbose logging")
	flag.Parse()
	if *debugFlag {
		h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
		slog.SetDefault(slog.New(h))
	}

	log.SetFlags(log.Flags() | log.Lshortfile)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	b, err := ctlog.NewS3Backend(ctx, "us-east-2", "rome2024h1", slog.Default())
	if err != nil {
		log.Fatal(err)
	}
	r := x509util.NewPEMCertPool()
	if err := r.AppendCertsFromPEMFile("roots.pem"); err != nil {
		log.Fatal(err)
	}
	keyPEM, err := os.ReadFile("key.pem")
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		log.Fatal("failed to parse key PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	c := &ctlog.Config{
		Name:          "rome.ct.filippo.io/2024h1",
		Key:           k.(crypto.Signer),
		Backend:       b,
		Log:           slog.Default(),
		Roots:         r,
		NotAfterStart: time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfterLimit: time.Date(2024, time.July, 1, 0, 0, 0, 0, time.UTC),
	}

	if *createFlag {
		if err := ctlog.CreateLog(ctx, c); err != nil {
			log.Fatal(err)
		}
	}

	l, err := ctlog.LoadLog(ctx, c)
	if err != nil {
		log.Fatal(err)
	}

	metrics := prometheus.NewRegistry()
	registry := prometheus.WrapRegistererWithPrefix("sunlight_", metrics)
	registry.MustRegister(collectors.NewGoCollector())
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	prometheus.WrapRegistererWith(prometheus.Labels{"log": "rome2024h1"},
		registry).MustRegister(l.Metrics()...)

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.Handle("/2024h1/", http.StripPrefix("/2024h1", l.Handler()))
	mux.Handle("/metrics", promhttp.HandlerFor(metrics, promhttp.HandlerOpts{
		ErrorLog: slog.NewLogLogger(c.Log.Handler(), slog.LevelWarn),
	}))

	m := &autocert.Manager{
		Cache:      autocert.DirCache("rome-autocert"),
		Prompt:     autocert.AcceptTOS,
		Email:      "rome-autocert@filippo.io",
		HostPolicy: autocert.HostWhitelist("rome.ct.filippo.io"),
	}
	s := &http.Server{
		Addr:         ":https",
		TLSConfig:    m.TLSConfig(),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	go func() {
		log.Println("ListenAndServeTLS:", s.ListenAndServeTLS("", ""))
		stop()
	}()
	log.Println("RunSequencer:", l.RunSequencer(ctx, 1*time.Second))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		log.Println("Shutdown:", err)
	}
}
