package probe

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

// TelemetryAnomalyDetector analyzes raw kernel probe events and flags anomalous attack patterns.
type TelemetryAnomalyDetector struct {
	SensitivePorts map[int]string
	MonitoredPaths []string
	SuspiciousComms map[string]bool
}

// NewAnomalyDetector creates an anomaly detector with bare-metal security baselines.
func NewAnomalyDetector() *TelemetryAnomalyDetector {
	return &TelemetryAnomalyDetector{
		SensitivePorts: map[int]string{
			2379:  "etcd-client",
			2380:  "etcd-peer",
			10250: "kubelet-api",
			6789:  "ceph-mon",
			6443:  "k8s-apiserver",
		},
		MonitoredPaths: []string{
			"/nix/store",
			"/etc/kubernetes",
			"/var/lib/kubelet/pki",
			"/proc/kcore",
		},
		SuspiciousComms: map[string]bool{
			"nc":      true,
			"ncat":    true,
			"netcat":  true,
			"socat":   true,
			"bash":    true,
			"sh":      true,
			"python":  true,
			"python3": true,
			"perl":    true,
			"ruby":    true,
		},
	}
}

// EvaluateEvent performs multi-vector inspection on a telemetry event and updates risk telemetry.
func (d *TelemetryAnomalyDetector) EvaluateEvent(event *TelemetryEvent, feed *intel.Feed) {
	if event == nil {
		return
	}

	tags := make(map[string]bool)
	for _, t := range event.ThreatTags {
		tags[t] = true
	}

	var maxScore float64 = event.RiskScore
	var highestSeverity string = event.Severity

	// Vector 1: Interactive shell spawning with external socket connection (Reverse Shell Radar)
	if event.ProbeType == ProbeTypeSocket && event.EventType == "SOCKET_CONNECT" {
		if d.SuspiciousComms[strings.ToLower(event.Comm)] {
			if isExternalIP(event.DestAddr) {
				tags["REVERSE_SHELL_ATTEMPT"] = true
				tags["ANOMALOUS_OUTBOUND_SOCKET"] = true
				if maxScore < 9.2 {
					maxScore = 9.2
					highestSeverity = string(intel.SeverityCritical)
				}
				event.Message = fmt.Sprintf("Suspicious interactive shell '%s' initiated outbound socket to external address %s", event.Comm, event.DestAddr)
			}
		}

		// Vector 2: Sensitive port probing
		port := extractPort(event.DestAddr)
		if svc, found := d.SensitivePorts[port]; found {
			// Authorized system daemons: kube-proxy, apiserver, flannel, calico, cilium
			comm := strings.ToLower(event.Comm)
			if !isAuthorizedInfrastructureComm(comm) {
				tags["SENSITIVE_PORT_PROBE"] = true
				tags[fmt.Sprintf("TARGET_%s", strings.ToUpper(svc))] = true
				if maxScore < 8.5 {
					maxScore = 8.5
					highestSeverity = string(intel.SeverityHigh)
				}
				event.Message = fmt.Sprintf("Unauthorized process '%s' probed sensitive infrastructure port %d (%s)", event.Comm, port, svc)
			}
		}
	}

	// Vector 3: Immutable Store & Critical Path Tampering
	if event.ProbeType == ProbeTypeStorage || event.ProbeType == ProbeTypeSyscall {
		for _, p := range d.MonitoredPaths {
			if strings.Contains(event.Message, p) || strings.Contains(event.Syscall, "openat") || strings.Contains(event.EventType, "STORE_TAMPER") {
				tags["IMMUTABLE_STORE_TAMPERING"] = true
				if maxScore < 8.8 {
					maxScore = 8.8
					highestSeverity = string(intel.SeverityHigh)
				}
				break
			}
		}
	}

	// Vector 4: Container Escape Primitives (ptrace / bpf syscalls from pod namespace)
	if event.Namespace != "" && (event.Syscall == "ptrace" || event.Syscall == "bpf") {
		tags["CONTAINER_ESCAPE_PRIMITIVE"] = true
		tags["PRIVILEGED_SYSCALL_VIOLATION"] = true
		if maxScore < 9.6 {
			maxScore = 9.6
			highestSeverity = string(intel.SeverityCritical)
		}
		event.Message = fmt.Sprintf("Pod '%s/%s' executed privileged syscall '%s' attempting container boundary escape", event.Namespace, event.PodName, event.Syscall)
	}

	// Vector 5: Threat Feed Correlation
	if feed != nil {
		for _, item := range feed.Items {
			if strings.Contains(strings.ToLower(event.Message), strings.ToLower(item.Component)) ||
				strings.Contains(strings.ToLower(event.Comm), strings.ToLower(item.Component)) {
				tags[item.ID] = true
				if item.CVSSScore > maxScore {
					maxScore = item.CVSSScore
					highestSeverity = string(item.Severity)
				}
			}
		}
	}

	var tagList []string
	for t := range tags {
		tagList = append(tagList, t)
	}

	event.ThreatTags = tagList
	event.RiskScore = maxScore
	if highestSeverity != "" {
		event.Severity = highestSeverity
	}
}

func isExternalIP(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return false
	}
	return true
}

func extractPort(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	p, _ := strconv.Atoi(portStr)
	return p
}

func isAuthorizedInfrastructureComm(comm string) bool {
	switch comm {
	case "kubelet", "kube-proxy", "kube-apiserver", "cilium-agent", "calico-node", "etcd", "flanneld":
		return true
	default:
		return false
	}
}
