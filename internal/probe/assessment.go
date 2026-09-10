package probe

// Assess derives the semantic readiness result from the facts currently
// collected by the checker. It intentionally leaves the legacy Status and
// Summary fields untouched so existing API consumers remain compatible.
func Assess(result *Result) {
	result.SchemaVersion = "2"
	result.Assessment = Assessment{}

	if isAssessmentFailure(result.Status) {
		result.Grade = GradeFailed
		result.Assessment.Grade = result.Grade
		result.Assessment.Headline = "QuantumHello could not assess this endpoint"
		result.Assessment.Explanation = result.Summary
		unknown := dimension("unknown", "Unknown", "Not enough evidence was collected.")
		result.Assessment.KeyEstablishment = unknown
		result.Assessment.Authentication = unknown
		result.Assessment.CertificateChain = unknown
		result.Assessment.Deployment = unknown
		result.Assessment.TLSBaseline = dimension("unknown", "Unknown", result.Summary)
		return
	}

	kexState := "post_quantum_unsupported"
	kexLabel := "Not post-quantum"
	kexSummary := "No standardized ML-KEM hybrid was negotiated."
	if isPQHybridCurveName(result.ControlProbe.NegotiatedCurve) {
		kexState = "post_quantum_preferred"
		kexLabel = "Post-quantum"
		kexSummary = "Normal TLS selected " + result.ControlProbe.NegotiatedCurve + "."
	} else if isPQHybridCurveName(result.PQProbe.NegotiatedCurve) {
		kexState = "post_quantum_supported"
		kexLabel = "Available, not preferred"
		kexSummary = "The server can negotiate post-quantum key establishment, but normal TLS selected a classical group."
	}
	result.Assessment.KeyEstablishment = dimension(kexState, kexLabel, kexSummary)
	result.Assessment.HNDLProtected = kexState == "post_quantum_preferred" || kexState == "post_quantum_supported"

	result.Assessment.Authentication = assessAuthentication(result.ControlProbe)
	result.Assessment.CertificateChain = assessCertificateChain(result.ControlProbe)
	switch result.Network.Consistency {
	case "consistent", "single_family":
		result.Assessment.Deployment = dimension(result.Network.Consistency, "Consistent", "Tested address-family paths produced equivalent readiness results.")
	case "inconsistent":
		result.Assessment.Deployment = dimension("inconsistent", "Inconsistent", "Tested IPv4 and IPv6 paths produced different readiness results.")
	case "partial":
		result.Assessment.Deployment = dimension("partial", "Partial coverage", "One tested address-family path could not complete a TLS assessment.")
	default:
		result.Assessment.Deployment = dimension("unknown", "Not assessed", "Address-family consistency is not yet assessed.")
	}

	tlsHealthy := result.ControlProbe.Success && result.ControlProbe.CertificateValid && result.Status != StatusCertError
	if result.TLS12Probe.Success && !result.ControlProbe.Success {
		result.Assessment.TLSBaseline = dimension("tls12", "TLS 1.2 only", "The endpoint completed TLS 1.2, not TLS 1.3.")
	} else if tlsHealthy {
		result.Assessment.TLSBaseline = dimension("healthy", "Healthy", "TLS 1.3 and certificate validation succeeded.")
	} else if result.Status == StatusCertError || !result.ControlProbe.CertificateValid {
		result.Assessment.TLSBaseline = dimension("certificate_invalid", "Certificate invalid", "The TLS handshake completed, but certificate validation failed.")
	} else {
		result.Assessment.TLSBaseline = dimension("unhealthy", "Unhealthy", result.Summary)
	}

	result.Grade = calculateGrade(*result, kexState, tlsHealthy)
	result.Assessment.Grade = result.Grade
	result.Assessment.Headline, result.Assessment.Explanation = gradeCopy(result.Grade, result, kexState)
}

func assessAuthentication(probe TLSProbeResult) DimensionAssessment {
	chain := probe.VerifiedChain
	if len(chain) == 0 {
		chain = probe.PresentedChain
	}
	if len(chain) == 0 {
		return dimension("unknown", "Not assessed", "The server authentication key is not yet collected by this probe.")
	}
	leaf := chain[0]
	if leaf.PublicKeyPostQuantum {
		return dimension("post_quantum", "Post-quantum", "The server authentication key is "+leaf.PublicKeyAlgorithm+".")
	}
	details := leaf.PublicKeyAlgorithm
	if leaf.PublicKeyDetails != "" {
		details += " " + leaf.PublicKeyDetails
	}
	return dimension("classical", "Classical", "The server authentication key is "+details+".")
}

func assessCertificateChain(probe TLSProbeResult) DimensionAssessment {
	if len(probe.VerifiedChain) == 0 {
		if len(probe.PresentedChain) == 0 {
			return dimension("unknown", "Not assessed", "Certificate-chain algorithms are not yet collected by this probe.")
		}
		return dimension("presented_only", "Presented only", "The presented certificate chain could not be verified.")
	}
	for _, cert := range probe.VerifiedChain {
		if !cert.SignaturePostQuantum {
			return dimension("classical", "Classical", "The verified chain contains classical certificate signatures.")
		}
	}
	return dimension("post_quantum", "Post-quantum", "The verified chain uses post-quantum certificate signatures.")
}

func calculateGrade(result Result, kexState string, tlsHealthy bool) Grade {
	if result.Status == StatusCertError || !tlsHealthy || result.TLS12Probe.Success {
		return GradeBad
	}
	switch kexState {
	case "post_quantum_preferred":
		if result.Network.Consistency == "inconsistent" {
			return GradeFair
		}
		if result.Assessment.Authentication.State == "post_quantum" && result.Assessment.CertificateChain.State == "post_quantum" {
			return GradeExcellent
		}
		return GradeGood
	case "post_quantum_supported":
		return GradeFair
	default:
		return GradeBad
	}
}

func gradeCopy(grade Grade, result *Result, kexState string) (string, string) {
	switch grade {
	case GradeExcellent:
		return "Post-quantum key establishment and authentication were observed", "The endpoint selected " + result.ControlProbe.NegotiatedCurve + " and its verified authentication chain uses post-quantum algorithms."
	case GradeGood:
		return "Post-quantum encryption is in normal use", "The endpoint selected " + result.ControlProbe.NegotiatedCurve + " in a normal TLS 1.3 handshake. Authentication remains classical."
	case GradeFair:
		if kexState == "post_quantum_supported" {
			return "Post-quantum encryption is available, but not consistently used", result.Assessment.KeyEstablishment.Summary
		}
		return "Post-quantum deployment needs attention", result.Summary
	case GradeBad:
		return "This endpoint is not currently protected by the tested post-quantum TLS baseline", result.Summary
	default:
		return "QuantumHello could not assess this endpoint", result.Summary
	}
}

func dimension(state, label, summary string) DimensionAssessment {
	return DimensionAssessment{State: state, Label: label, Summary: summary}
}

func isAssessmentFailure(status Status) bool {
	switch status {
	case StatusInvalidInput, StatusBlockedTarget, StatusDNSError, StatusTimeout, StatusConnectionErr, StatusUnknown:
		return true
	default:
		return false
	}
}
