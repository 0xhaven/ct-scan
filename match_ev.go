package main

import (
	"time"

	"github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/asn1"
	"github.com/google/certificate-transparency/go/x509"
)

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

var zero time.Time

// MatchEV is a CT scanner.Matcher that matches EV cert issuance.
type MatchEV struct {
	earliest, latest time.Time
}

// NewMatchEV returns a new MatchEV matcher.
func NewMatchEV(earliestString, latestString string) *MatchEV {
	earliest, _ := time.Parse(format, earliestString)
	latest, _ := time.Parse(format, latestString)
	return &MatchEV{earliest, latest}
}

// CertificateMatches matches all EV certificates with NotBefore between a earliest and latest date.
func (m *MatchEV) CertificateMatches(c *x509.Certificate) bool {
	if m.earliest != zero && c.NotBefore.Before(m.earliest) || m.latest != zero && c.NotBefore.After(m.latest) {
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

// PrecertificateMatches matches no CT Precertificate entries.
func (m *MatchEV) PrecertificateMatches(p *ct.Precertificate) bool {
	return false
}
