package probe

import "crypto/tls"

var defaultCurveOrder = []tls.CurveID{
	tls.X25519MLKEM768,
	tls.SecP256r1MLKEM768,
	tls.SecP384r1MLKEM1024,
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
	tls.CurveP521,
}

var pqCurveOrder = []tls.CurveID{
	tls.X25519MLKEM768,
	tls.SecP256r1MLKEM768,
	tls.SecP384r1MLKEM1024,
}

func defaultCurvePreferences() []tls.CurveID {
	return append([]tls.CurveID(nil), defaultCurveOrder...)
}

func pqCurvePreferences() []tls.CurveID {
	return append([]tls.CurveID(nil), pqCurveOrder...)
}

func isPQHybridCurveName(name string) bool {
	switch name {
	case tls.X25519MLKEM768.String(), tls.SecP256r1MLKEM768.String(), tls.SecP384r1MLKEM1024.String():
		return true
	default:
		return false
	}
}

func supportsPQHybridPair(control, pq TLSProbeResult) bool {
	return isPQHybridCurveName(control.NegotiatedCurve) && isPQHybridCurveName(pq.NegotiatedCurve)
}
