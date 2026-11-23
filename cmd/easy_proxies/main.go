package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"easy_proxies/internal/app"
	"easy_proxies/internal/config"
	"easy_proxies/internal/monitor"

	"gopkg.in/natefinch/lumberjack.v2"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "config.yaml", "path to config file")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var cfg *config.Config
	for attempt := 1; attempt <= 3; attempt++ {
		var err error
		cfg, err = config.LoadContext(ctx, configPath)
		if err == nil {
			break
		}
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			log.Println("Received shutdown signal during startup, exiting cleanly")
			return
		}
		if attempt < 3 && strings.Contains(err.Error(), "config.nodes cannot be empty") {
			log.Printf("⚠️  Attempt %d/3: %v (retrying in %ds...)", attempt, err, attempt*10)
			select {
			case <-ctx.Done():
				log.Println("Received shutdown signal while waiting to retry config load, exiting cleanly")
				return
			case <-time.After(time.Duration(attempt*10) * time.Second):
				continue
			}
		}
		log.Fatalf("load config: %v", err)
	}

	// Setup logging based on config
	setupLogging(cfg)

	if err := app.Run(ctx, cfg); err != nil {
		if ctx.Err() != nil && errors.Is(err, context.Canceled) {
			return
		}
		fmt.Fprintf(os.Stderr, "proxy pool exited with error: %v\n", err)
		os.Exit(1)
	}
}

func setupLogging(cfg *config.Config) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// Always include the in-memory ring buffer for dashboard console
	writers := []io.Writer{os.Stdout, monitor.LogWriter()}

	if cfg.Log.Output == "file" {
		// Ensure log directory exists
		logDir := filepath.Dir(cfg.Log.File)
		if err := os.MkdirAll(logDir, 0o755); err != nil {
			log.Printf("\u26a0\ufe0f Failed to create log dir %s: %v, falling back to stdout", logDir, err)
		} else {
			lj := &lumberjack.Logger{
				Filename:   cfg.Log.File,
				MaxSize:    cfg.Log.MaxSize, // MB
				MaxBackups: cfg.Log.MaxBackups,
				MaxAge:     cfg.Log.MaxAge, // days
				Compress:   cfg.Log.Compress,
			}
			writers = append(writers, lj)
			log.Printf("\u2705 Log rotation enabled: file=%s, maxSize=%dMB, maxBackups=%d, maxAge=%dd",
				cfg.Log.File, cfg.Log.MaxSize, cfg.Log.MaxBackups, cfg.Log.MaxAge)
		}
	}

	log.SetOutput(io.MultiWriter(writers...))
}
