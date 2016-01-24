package main

import (
	"flag"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/asn1"
	"github.com/google/certificate-transparency/go/client"
	"github.com/google/certificate-transparency/go/scanner"
	"github.com/google/certificate-transparency/go/x509"
)

var (
	logURL                       string
	verbose                      bool
	earliestString, latestString string
)

func init() {
	flag.StringVar(&logURL, "log-url", "ct.ws.symantec.com", "CT Log to scan")
	flag.BoolVar(&verbose, "v", false, "Whether to print scanning data")
	flag.StringVar(&earliestString, "earliest", "2015-01-01", "Earliest NotBefore time (parsed as 2006-01-02)")
	flag.StringVar(&latestString, "latest", "2016-01-01", "Earliest NotBefore time (parsed as 2006-01-02)")
}

var evOIDs = []asn1.ObjectIdentifier{
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34697, 2, 1},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34697, 2, 2},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34697, 2, 1},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34697, 2, 3},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34697, 2, 4},
	asn1.ObjectIdentifier{1, 2, 40, 0, 17, 1, 22},
	asn1.ObjectIdentifier{2, 16, 578, 1, 26, 1, 3, 3},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 17326, 10, 14, 2, 1, 2},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 17326, 10, 8, 12, 1, 2},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 6449, 1, 2, 1, 5, 1},
	asn1.ObjectIdentifier{2, 16, 840, 1, 114412, 2, 1},
	asn1.ObjectIdentifier{2, 16, 528, 1, 1001, 1, 1, 1, 12, 6, 1, 1, 1},
	asn1.ObjectIdentifier{2, 16, 840, 1, 114028, 10, 1, 2},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 14370, 1, 6},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 4146, 1, 1},
	asn1.ObjectIdentifier{2, 16, 840, 1, 114413, 1, 7, 23, 3},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 14777, 6, 1, 1},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 14777, 6, 1, 2},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 22234, 2, 5, 2, 3, 1},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 782, 1, 2, 1, 8, 1},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 8024, 0, 2, 100, 1, 2},
	asn1.ObjectIdentifier{1, 2, 392, 200091, 100, 721, 1},
	asn1.ObjectIdentifier{2, 16, 840, 1, 114414, 1, 7, 23, 3},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 23223, 2},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 23223, 1, 1, 1},
	asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1},
	asn1.ObjectIdentifier{2, 16, 756, 1, 89, 1, 2, 1, 1},
	asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 7, 48, 1},
	asn1.ObjectIdentifier{2, 16, 840, 1, 114404, 1, 1, 2, 4, 1},
	asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 7, 23, 6},
	asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 6334, 1, 100, 1},
}

type matchEVCert struct {
	earliest, latest time.Time
}

func (m matchEVCert) CertificateMatches(c *x509.Certificate) bool {
	if c.NotBefore.Before(m.earliest) || c.NotBefore.After(m.latest) {
		return false
	}

	for _, oid := range c.PolicyIdentifiers {
		for _, evOID := range evOIDs {
			if oid.Equal(evOID) {
				return true
			}
		}
	}
	return false
}

func (m matchEVCert) PrecertificateMatches(p *ct.Precertificate) bool {
	return false
}

func main() {
	flag.Parse()
	earliest, err := time.Parse("2006-01-02", earliestString)
	if err != nil {
		log.Fatal(err)
	}
	latest, err := time.Parse("2006-01-02", latestString)
	if err != nil {
		log.Fatal(err)
	}

	u, err := url.Parse(logURL)
	if err != nil {
		log.Fatal(err)
	}

	if u.Scheme == "" {
		u.Scheme = "https"
	}
	c := client.New(u.String())
	opts := scanner.ScannerOptions{
		Matcher:       matchEVCert{earliest, latest},
		BatchSize:     1000,
		NumWorkers:    100,
		ParallelFetch: 100,
		Quiet:         !verbose,
	}
	log.Printf("Scanning %s for EV certs issued between %s and %s...\n", u.String(), earliest, latest)

	s := scanner.NewScanner(c, opts)
	var count int
	err = s.Scan(func(le *ct.LogEntry) {
		count++
		fmt.Printf("%d: %s\n", count, le.X509Cert.Subject.CommonName)
	}, func(le *ct.LogEntry) {})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d EV Certs\n", count)
}
