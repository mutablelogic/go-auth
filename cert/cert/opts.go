// Copyright 2026 David Thorpe
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	// Packages
	schema "github.com/mutablelogic/go-auth/cert/schema"
	types "github.com/mutablelogic/go-server/pkg/types"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// Opt is a function which applies options
type Opt func(*Cert) error

////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func apply(opts ...Opt) (*Cert, error) {
	// Create new options
	cert := new(Cert)

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	cert.x509.KeyUsage = x509.KeyUsageDigitalSignature

	// Set other defaults
	cert.x509.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	cert.x509.BasicConstraintsValid = true

	// Apply options
	for _, fn := range opts {
		if err := fn(cert); err != nil {
			return nil, err
		}
	}

	// Return success
	return cert, nil
}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Set certificate name
func withName(name string) Opt {
	return func(o *Cert) error {
		if name != "" {
			o.Name = name
		}
		return nil
	}
}

// Set common name
func WithCommonName(name string) Opt {
	return func(o *Cert) error {
		if name = strings.TrimSpace(name); name != "" {
			o.x509.Subject.CommonName = name
		}
		return nil
	}
}

// Set organization
func WithOrganization(org, unit string) Opt {
	return func(o *Cert) error {
		if org = strings.TrimSpace(org); org != "" {
			o.x509.Subject.Organization = []string{org}
		}
		if unit = strings.TrimSpace(unit); unit != "" {
			o.x509.Subject.OrganizationalUnit = []string{unit}
		}
		return nil
	}
}

// Set country
func WithCountry(country, state, city string) Opt {
	return func(o *Cert) error {
		if country = strings.TrimSpace(country); country != "" {
			o.x509.Subject.Country = []string{country}
		}
		if state = strings.TrimSpace(state); state != "" {
			o.x509.Subject.Province = []string{state}
		}
		if city = strings.TrimSpace(city); city != "" {
			o.x509.Subject.Locality = []string{city}
		}
		return nil
	}
}

// Set address
func WithAddress(address, postcode string) Opt {
	return func(o *Cert) error {
		if address = strings.TrimSpace(address); address != "" {
			o.x509.Subject.StreetAddress = []string{address}
		}
		if postcode = strings.TrimSpace(postcode); postcode != "" {
			o.x509.Subject.PostalCode = []string{postcode}
		}
		return nil
	}
}

// Set subject attributes, excluding the common name.
func WithSubject(subject schema.SubjectMeta) Opt {
	return func(o *Cert) error {
		org := strings.TrimSpace(types.Value(subject.Org))
		unit := strings.TrimSpace(types.Value(subject.Unit))
		country := strings.TrimSpace(types.Value(subject.Country))
		state := strings.TrimSpace(types.Value(subject.State))
		city := strings.TrimSpace(types.Value(subject.City))
		address := strings.TrimSpace(types.Value(subject.StreetAddress))
		postcode := strings.TrimSpace(types.Value(subject.PostalCode))

		if org == "" && unit == "" && country == "" && state == "" && city == "" && address == "" && postcode == "" {
			return fmt.Errorf("subject is required")
		}

		if err := WithOrganization(org, unit)(o); err != nil {
			return err
		}
		if err := WithCountry(country, state, city)(o); err != nil {
			return err
		}
		return WithAddress(address, postcode)(o)
	}
}

// Set certificate expiry
func WithExpiry(expires time.Duration) Opt {
	return func(o *Cert) error {
		o.x509.NotBefore = time.Now().Truncate(time.Second).UTC()
		o.x509.NotAfter = o.x509.NotBefore.Add(expires).Truncate(time.Second).UTC()
		return nil
	}
}

// Set random serial number
func WithRandomSerial() Opt {
	return func(o *Cert) error {
		// Generate a random serial number
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		if serialNumber, err := rand.Int(rand.Reader, serialNumberLimit); err != nil {
			return err
		} else {
			o.x509.SerialNumber = serialNumber
		}

		// Return success
		return nil
	}
}

// Set serial number
func WithSerial(serial *big.Int) Opt {
	return func(o *Cert) error {
		if serial == nil {
			return WithRandomSerial()(o)
		} else {
			o.x509.SerialNumber = serial
		}
		return nil
	}
}

// Create either an ECDSA or RSA key
func WithKeyType(t string) Opt {
	return func(o *Cert) error {
		t = strings.ToUpper(strings.TrimSpace(t))
		switch {
		case t == "RSA":
			return WithRSAKey(0)(o)
		case strings.HasPrefix(t, "RSA"):
			if bits, err := strconv.ParseUint(strings.TrimPrefix(t, "RSA"), 10, 32); err != nil {
				return err
			} else {
				return WithRSAKey(int(bits))(o)
			}
		default:
			return WithEllipticKey(t)(o)
		}
	}
}

// Create with a default key type
func WithDefaultKeyType() Opt {
	return func(o *Cert) error {
		return WithRSAKey(0)(o)
	}
}

// Create an ECDSA key with one of the following curves: P224, P256, P384, P521
func WithEllipticKey(t string) Opt {
	return func(o *Cert) error {
		// Generate a private key
		if key, err := ecdsaKey(t); err != nil {
			return err
		} else {
			o.priv = key
		}

		// Return success
		return nil
	}
}

// Create an RSA key with the specified number of bits
func WithRSAKey(bits int) Opt {
	return func(o *Cert) error {
		// Set bits if not specified
		if bits <= 0 {
			bits = defaultBits
		}
		// Generate a private key
		if key, err := rsa.GenerateKey(rand.Reader, bits); err != nil {
			return err
		} else {
			o.priv = key
		}

		// RSA subject keys should have the KeyEncipherment KeyUsage bits set
		o.x509.KeyUsage |= x509.KeyUsageKeyEncipherment

		// Return success
		return nil
	}
}

// Set subject alternative names for the certificate.
func WithSAN(san ...string) Opt {
	return func(o *Cert) error {
		if err := ValidateSAN(san...); err != nil {
			return err
		}
		for _, value := range san {
			value = strings.TrimSpace(value)
			if ip := net.ParseIP(value); ip != nil {
				o.x509.IPAddresses = append(o.x509.IPAddresses, ip)
			} else {
				o.x509.DNSNames = append(o.x509.DNSNames, value)
			}
		}

		// Return success
		return nil
	}
}

// ValidateSAN validates SAN inputs accepted by WithSAN.
// Valid inputs are IP addresses, DNS names, and wildcard DNS names.
// CIDR ranges are rejected because they belong to CA constraints rather than
// leaf certificate SAN entries.
func ValidateSAN(san ...string) error {
	for _, value := range san {
		if _, err := validateSAN(value); err != nil {
			return err
		}
	}
	return nil
}

// Set as a CA certificate
func WithCA() Opt {
	return func(o *Cert) error {
		o.x509.IsCA = true
		o.x509.KeyUsage |= x509.KeyUsageCertSign
		return nil
	}
}

// Mark as the unique root certificate. A root certificate is always a CA and
// must be self-signed when created.
func WithRoot() Opt {
	return func(o *Cert) error {
		o.root = true
		return WithCA()(o)
	}
}

// Set the signer for the certificate
func WithSigner(signer *Cert) Opt {
	return func(o *Cert) error {
		if signer == nil {
			return fmt.Errorf("missing signer")
		} else if !signer.IsCA() {
			return fmt.Errorf("signer is not a CA certificate")
		}
		o.Signer = signer
		return nil
	}
}

////////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func ecdsaKey(t string) (*ecdsa.PrivateKey, error) {
	switch strings.ToUpper(t) {
	case "P224":
		return ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, fmt.Errorf("unrecognized key type: %q", t)
	}
}

var dnsLabelPattern = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

func validateSAN(san string) (string, error) {
	san = strings.TrimSpace(san)
	if san == "" {
		return "", fmt.Errorf("san entry is required")
	}
	if strings.Contains(san, "/") {
		if _, _, err := net.ParseCIDR(san); err == nil {
			return "", fmt.Errorf("san entry %q is a CIDR range and is not supported for certificates", san)
		}
	}
	if ip := net.ParseIP(san); ip != nil {
		return san, nil
	}
	if strings.HasSuffix(san, ".") {
		return "", fmt.Errorf("san entry %q is invalid", san)
	}
	labels := strings.Split(san, ".")
	for i, label := range labels {
		if label == "" {
			return "", fmt.Errorf("san entry %q is invalid", san)
		}
		if label == "*" {
			if i != 0 || len(labels) < 2 {
				return "", fmt.Errorf("san entry %q is invalid", san)
			}
			continue
		}
		if len(label) > 63 || !dnsLabelPattern.MatchString(label) || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("san entry %q is invalid", san)
		}
	}
	return san, nil
}
