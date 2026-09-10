package probe

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"
)

// These OIDs identify the ML-DSA public-key and signature algorithms. Keeping
// the OID checks here lets QuantumHello report them on toolchains that do not
// yet expose dedicated x509 key types.
var (
	mlDSAPublicKeyOIDs = map[string]string{
		"2.16.840.1.101.3.4.4.1": "ML-DSA-44",
		"2.16.840.1.101.3.4.4.2": "ML-DSA-65",
		"2.16.840.1.101.3.4.4.3": "ML-DSA-87",
	}
	mlDSASignatureOIDs = map[string]string{
		"2.16.840.1.101.3.4.3.17": "ML-DSA-44",
		"2.16.840.1.101.3.4.3.18": "ML-DSA-65",
		"2.16.840.1.101.3.4.3.19": "ML-DSA-87",
	}
)

func ObserveCertificate(cert *x509.Certificate, position int, role string) CertificateObservation {
	obs := CertificateObservation{
		Position: position, Role: role, Subject: cert.Subject.String(), Issuer: cert.Issuer.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(), NotBefore: cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter: cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"), DNSNames: append([]string(nil), cert.DNSNames...),
	}
	obs.PublicKeyAlgorithm, obs.PublicKeyDetails, obs.PublicKeyPostQuantum = publicKeyDescription(cert)
	obs.SignaturePostQuantum = isMLDSASignature(cert)
	return obs
}

func ObservePresentedChain(certs []*x509.Certificate) []CertificateObservation {
	return observeChain(certs, "presented")
}

func ObserveVerifiedChain(certs []*x509.Certificate) []CertificateObservation {
	return observeChain(certs, "verified")
}

func observeChain(certs []*x509.Certificate, role string) []CertificateObservation {
	result := make([]CertificateObservation, 0, len(certs))
	for i, cert := range certs {
		certRole := role
		if i == 0 {
			certRole = "leaf"
		} else if i == len(certs)-1 {
			certRole = "root_or_last"
		}
		result = append(result, ObserveCertificate(cert, i, certRole))
	}
	return result
}

func publicKeyDescription(cert *x509.Certificate) (string, string, bool) {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", fmt.Sprintf("%d-bit", key.N.BitLen()), false
	case *ecdsa.PublicKey:
		return "ECDSA", key.Curve.Params().Name, false
	case ed25519.PublicKey:
		return "Ed25519", "", false
	}
	var info struct {
		Algorithm struct{ Algorithm asn1.ObjectIdentifier }
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &info); err == nil {
		if name, ok := mlDSAPublicKeyOIDs[info.Algorithm.Algorithm.String()]; ok {
			return name, name, true
		}
	}
	return cert.PublicKeyAlgorithm.String(), "", false
}

func isMLDSASignature(cert *x509.Certificate) bool {
	name := strings.ToUpper(cert.SignatureAlgorithm.String())
	if strings.Contains(name, "ML-DSA") || strings.Contains(name, "MLDSA") {
		return true
	}
	var info struct {
		Version   int `asn1:"optional,explicit,tag:0,default:0"`
		Serial    asn1.RawValue
		Signature struct{ Algorithm asn1.ObjectIdentifier }
	}
	if _, err := asn1.Unmarshal(cert.RawTBSCertificate, &info); err == nil {
		_, ok := mlDSASignatureOIDs[info.Signature.Algorithm.String()]
		return ok
	}
	return false
}
