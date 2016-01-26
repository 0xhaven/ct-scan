package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"

	"github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/client"
	"github.com/google/certificate-transparency/go/scanner"
)

var (
	logURL                       string
	csvFile                      string
	verbose                      bool
	earliestString, latestString string
	format                       = "2006-01-02"
)

func init() {
	flag.StringVar(&logURL, "log-url", "https://ct.googleapis.com/pilot", "CT Log to scan")
	flag.StringVar(&csvFile, "csv-file", "ev-certs.csv", "File to log EV certs to")
	flag.BoolVar(&verbose, "v", false, "Whether to print scanning data")
	flag.StringVar(&earliestString, "earliest", "2015-01-01", "Earliest NotBefore time (parsed as 2006-01-02)")
	flag.StringVar(&latestString, "latest", "2016-01-01", "Earliest NotBefore time (parsed as 2006-01-02)")
}

type csvLogger struct {
	*csv.Writer
	count int
}

func newLogger(filename string) (*csvLogger, error) {
	w, err := os.Create(filename)
	if err != nil {
		return nil, err
	}

	return &csvLogger{Writer: csv.NewWriter(w)}, nil
}

func (l *csvLogger) Write(record []string) error {
	l.count++
	return l.Writer.Write(record)
}

func main() {
	flag.Parse()
	u, err := url.Parse(logURL)
	if err != nil {
		log.Fatal(err)
	}

	if u.Scheme == "" {
		u.Scheme = "https"
	}
	c := client.New(u.String())
	opts := scanner.ScannerOptions{
		Matcher:       NewMatchEV(earliestString, latestString),
		BatchSize:     1000,
		NumWorkers:    100,
		ParallelFetch: 10,
		Quiet:         !verbose,
	}

	s := scanner.NewScanner(c, opts)

	l, err := newLogger(csvFile)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Scanning %s for EV certs...\n", u.String())
	err = s.Scan(func(le *ct.LogEntry) {
		err := l.Write(append([]string{le.X509Cert.Issuer.CommonName, le.X509Cert.NotBefore.Format(format), le.X509Cert.Subject.CommonName}, le.X509Cert.DNSNames...))
		if err != nil {
			log.Println(err)
		}
	}, func(le *ct.LogEntry) {})
	if err != nil {
		log.Fatal(err)
	}

	l.Flush()
	fmt.Printf("Found %d EV Certs\n", l.count)
}
