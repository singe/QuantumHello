package probe

import (
	"bytes"
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
		// Current ML-DSA certificates use the signature algorithm OIDs for
		// SubjectPublicKeyInfo as well; retain the draft key OIDs for interop.
		"2.16.840.1.101.3.4.3.17": "ML-DSA-44",
		"2.16.840.1.101.3.4.3.18": "ML-DSA-65",
		"2.16.840.1.101.3.4.3.19": "ML-DSA-87",
		"2.16.840.1.101.3.4.4.1":  "ML-DSA-44",
		"2.16.840.1.101.3.4.4.2":  "ML-DSA-65",
		"2.16.840.1.101.3.4.4.3":  "ML-DSA-87",
	}
	mlDSASignatureOIDs = map[string]string{
		"2.16.840.1.101.3.4.3.17": "ML-DSA-44",
		"2.16.840.1.101.3.4.3.18": "ML-DSA-65",
		"2.16.840.1.101.3.4.3.19": "ML-DSA-87",
	}
	slhDSAPublicKeyOIDs = map[string]string{
		"2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128s",
		"2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-128f",
		"2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192s",
		"2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-192f",
		"2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256s",
		"2.16.840.1.101.3.4.3.26": "SLH-DSA-SHA2-256f",
	}
	slhDSASignatureOIDs = slhDSAPublicKeyOIDs
)

func ObserveCertificate(cert *x509.Certificate, position int, role string) CertificateObservation {
	obs := CertificateObservation{
		Position: position, Role: role, Subject: cert.Subject.String(), Issuer: cert.Issuer.String(),
		SignatureAlgorithm: certificateSignatureName(cert), NotBefore: cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
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
		Algorithm asn1.RawValue
		Key       asn1.RawValue
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &info); err == nil {
		var algorithm struct{ Algorithm asn1.ObjectIdentifier }
		if _, err := asn1.Unmarshal(info.Algorithm.FullBytes, &algorithm); err != nil {
			return cert.PublicKeyAlgorithm.String(), "", false
		}
		if name, ok := mlDSAPublicKeyOIDs[algorithm.Algorithm.String()]; ok {
			return name, name, true
		}
		if name, ok := slhDSAPublicKeyOIDs[algorithm.Algorithm.String()]; ok {
			return name, name, true
		}
	}
	// Some providers emit a valid SubjectPublicKeyInfo encoding that Go's
	// generic ASN.1 struct cannot fully decode. Scan the DER for the known
	// algorithm identifier before falling back to an opaque key name.
	for _, item := range allPQPublicKeyOIDs() {
		oid, name := item.oid, item.name
		encoded, _ := asn1.Marshal(oid)
		if bytes.Contains(cert.RawSubjectPublicKeyInfo, encoded) {
			return name, name, true
		}
	}
	if oid := subjectPublicKeyOID(cert); oid != "" {
		return "unknown:" + oid, "OID " + oid, false
	}
	// Go may recognize the family but not expose the parameter set. The
	// certificate signature still provides the parameter-set name for ML-DSA.
	keyName := strings.ToUpper(cert.PublicKeyAlgorithm.String())
	if strings.Contains(keyName, "ML-DSA") || strings.Contains(keyName, "MLDSA") {
		sigName := strings.ToUpper(cert.SignatureAlgorithm.String())
		if strings.Contains(sigName, "ML-DSA-44") {
			return "ML-DSA-44", "ML-DSA-44", true
		}
		if strings.Contains(sigName, "ML-DSA-65") {
			return "ML-DSA-65", "ML-DSA-65", true
		}
		if strings.Contains(sigName, "ML-DSA-87") {
			return "ML-DSA-87", "ML-DSA-87", true
		}
		return "ML-DSA", "ML-DSA", true
	}
	return cert.PublicKeyAlgorithm.String(), "", false
}

func allPQPublicKeyOIDs() []struct {
	oid  asn1.ObjectIdentifier
	name string
} {
	result := make([]struct {
		oid  asn1.ObjectIdentifier
		name string
	}, 0, len(mlDSAPublicKeyOIDs)+len(slhDSAPublicKeyOIDs))
	for value, name := range mlDSAPublicKeyOIDs {
		result = append(result, struct {
			oid  asn1.ObjectIdentifier
			name string
		}{parseOID(value), name})
	}
	for value, name := range slhDSAPublicKeyOIDs {
		result = append(result, struct {
			oid  asn1.ObjectIdentifier
			name string
		}{parseOID(value), name})
	}
	return result
}

func parseOID(value string) asn1.ObjectIdentifier {
	parts := strings.Split(value, ".")
	result := make(asn1.ObjectIdentifier, len(parts))
	for i, part := range parts {
		var n int
		fmt.Sscan(part, &n)
		result[i] = n
	}
	return result
}

func subjectPublicKeyOID(cert *x509.Certificate) string {
	var info struct {
		Algorithm asn1.RawValue
		Key       asn1.RawValue
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &info); err != nil {
		return ""
	}
	var algorithm struct{ Algorithm asn1.ObjectIdentifier }
	if _, err := asn1.Unmarshal(info.Algorithm.FullBytes, &algorithm); err != nil {
		return ""
	}
	return algorithm.Algorithm.String()
}

func isMLDSASignature(cert *x509.Certificate) bool {
	name := strings.ToUpper(certificateSignatureName(cert))
	if strings.Contains(name, "ML-DSA") || strings.Contains(name, "MLDSA") {
		return true
	}
	var info struct {
		Version   int `asn1:"optional,explicit,tag:0,default:0"`
		Serial    asn1.RawValue
		Signature struct{ Algorithm asn1.ObjectIdentifier }
	}
	if _, err := asn1.Unmarshal(cert.RawTBSCertificate, &info); err == nil {
		_, mlDSA := mlDSASignatureOIDs[info.Signature.Algorithm.String()]
		_, slhDSA := slhDSASignatureOIDs[info.Signature.Algorithm.String()]
		return mlDSA || slhDSA
	}
	return false
}

func certificateSignatureName(cert *x509.Certificate) string {
	name := cert.SignatureAlgorithm.String()
	if name != "" && name != "0" && name != "UnknownSignatureAlgorithm" {
		return name
	}
	var info struct {
		Version   int `asn1:"optional,explicit,tag:0,default:0"`
		Serial    asn1.RawValue
		Signature struct{ Algorithm asn1.ObjectIdentifier }
	}
	if _, err := asn1.Unmarshal(cert.RawTBSCertificate, &info); err == nil {
		oid := info.Signature.Algorithm.String()
		if value, ok := mlDSASignatureOIDs[oid]; ok {
			return value
		}
		if value, ok := slhDSASignatureOIDs[oid]; ok {
			return value
		}
		if oid != "" {
			return "unknown:" + oid
		}
	}
	return name
}
