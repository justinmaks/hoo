package decode

// Protocol represents an application-level protocol classification.
type Protocol string

const (
	ProtoHTTPS Protocol = "HTTPS"
	ProtoHTTP  Protocol = "HTTP"
	ProtoDNS   Protocol = "DNS"
	ProtoSSH   Protocol = "SSH"
	ProtoOther Protocol = "Other"
)

// ClassifyProtocol determines the application protocol from transport and ports.
func ClassifyProtocol(transport string, srcPort, dstPort uint16) Protocol {
	if matchPort(srcPort, dstPort, 443) {
		return ProtoHTTPS
	}
	if matchPort(srcPort, dstPort, 80) {
		return ProtoHTTP
	}
	if matchPort(srcPort, dstPort, 53) {
		return ProtoDNS
	}
	if matchPort(srcPort, dstPort, 22) {
		return ProtoSSH
	}
	return ProtoOther
}

func matchPort(src, dst, target uint16) bool {
	return src == target || dst == target
}

// AllProtocols returns the list of known protocols for display ordering.
func AllProtocols() []Protocol {
	return []Protocol{ProtoHTTPS, ProtoHTTP, ProtoDNS, ProtoSSH, ProtoOther}
}
