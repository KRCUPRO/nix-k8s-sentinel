package wireguard

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/KRCUPRO/nix-k8s-sentinel/pkg/intel"
)

var (
	reIfaceBlock     = regexp.MustCompile(`networking\.wireguard\.interfaces\.([a-zA-Z0-9_-]+)\s*=\s*\{`)
	reListenPort     = regexp.MustCompile(`listenPort\s*=\s*([0-9]+);`)
	rePrivateKey     = regexp.MustCompile(`privateKey\s*=\s*"([^"]+)";`)
	rePrivateKeyFile = regexp.MustCompile(`privateKeyFile\s*=\s*"([^"]+)";`)
	reMTU            = regexp.MustCompile(`mtu\s*=\s*([0-9]+);`)
	rePublicKey      = regexp.MustCompile(`publicKey\s*=\s*"([^"]+)";`)
	rePSK            = regexp.MustCompile(`presharedKey\s*=\s*"([^"]+)";`)
	rePSKFile        = regexp.MustCompile(`presharedKeyFile\s*=\s*"([^"]+)";`)
	reEndpoint       = regexp.MustCompile(`endpoint\s*=\s*"([^"]+)";`)
	reKeepalive      = regexp.MustCompile(`persistentKeepalive\s*=\s*([0-9]+);`)
	reAllowedIPs     = regexp.MustCompile(`allowedIPs\s*=\s*\[([^\]]+)\];`)
	reIPList         = regexp.MustCompile(`ips\s*=\s*\[([^\]]+)\];`)
)

// WireGuardScanner inspects declarative NixOS and Kubernetes WireGuard configuration declarations.
type WireGuardScanner struct {
	feed *intel.Feed
	keyEngine *KeyRotationEngine
}

// NewWireGuardScanner creates a scanner configured with threat intelligence feeds.
func NewWireGuardScanner(feed *intel.Feed) *WireGuardScanner {
	return &WireGuardScanner{
		feed:      feed,
		keyEngine: NewKeyRotationEngine(),
	}
}

// ScanFile audits a single declarative configuration file.
func (s *WireGuardScanner) ScanFile(filePath string) ([]InterfaceDeclaration, []WireGuardViolation, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat file %s: %w", filePath, err)
	}

	if fi.Size() > MaxManifestBytes {
		return nil, nil, fmt.Errorf("file %s exceeds maximum size ceiling (%d bytes)", filePath, MaxManifestBytes)
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	return s.ScanContent(string(content), filePath)
}

// ScanDirectory walks a directory tree and audits all Nix and YAML/JSON declarations.
func (s *WireGuardScanner) ScanDirectory(dirPath string) ([]InterfaceDeclaration, []WireGuardViolation, error) {
	var allInterfaces []InterfaceDeclaration
	var allViolations []WireGuardViolation

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".nix" || ext == ".yaml" || ext == ".yml" || ext == ".json" {
			ifaces, viols, scanErr := s.ScanFile(path)
			if scanErr == nil {
				allInterfaces = append(allInterfaces, ifaces...)
				allViolations = append(allViolations, viols...)
			}
		}
		return nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("failed to scan directory %s: %w", dirPath, err)
	}

	return allInterfaces, allViolations, nil
}

// ScanContent parses configuration lines and identifies WireGuard declarations and vulnerabilities.
func (s *WireGuardScanner) ScanContent(content string, filePath string) ([]InterfaceDeclaration, []WireGuardViolation, error) {
	var interfaces []InterfaceDeclaration
	var violations []WireGuardViolation

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0

	var currentIface *InterfaceDeclaration
	var currentPeer *PeerDeclaration
	inPeersBlock := false

	flushPeer := func() {
		if currentPeer != nil && currentIface != nil {
			currentIface.Peers = append(currentIface.Peers, *currentPeer)
			currentPeer = nil
		}
	}

	flushIface := func() {
		flushPeer()
		if currentIface != nil {
			interfaces = append(interfaces, *currentIface)
			currentIface = nil
			inPeersBlock = false
		}
	}

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// 1. Detect new interface block
		if m := reIfaceBlock.FindStringSubmatch(line); len(m) > 1 {
			flushIface()
			currentIface = &InterfaceDeclaration{
				Name:      m[1],
				FilePath:  filePath,
				StartLine: lineNum,
			}
			continue
		}

		if currentIface == nil {
			continue
		}

		// 2. Interface properties
		if m := reIPList.FindStringSubmatch(line); len(m) > 1 {
			rawIPs := strings.Fields(m[1])
			for _, rip := range rawIPs {
				cleanIP := strings.Trim(rip, `",`)
				if cleanIP != "" {
					currentIface.IPs = append(currentIface.IPs, cleanIP)
				}
			}
		}

		if m := reListenPort.FindStringSubmatch(line); len(m) > 1 {
			if port, err := strconv.Atoi(m[1]); err == nil {
				currentIface.ListenPort = port
			}
		}

		// Rule WG-MESH-001: Plaintext Private Key
		if m := rePrivateKey.FindStringSubmatch(line); len(m) > 1 {
			currentIface.PrivateKey = m[1]
			rule := WireGuardRuleRegistry[RuleWGPlaintextPrivateKey]
			violations = append(violations, WireGuardViolation{
				RuleID:        rule.ID,
				Title:         rule.Title,
				InterfaceName: currentIface.Name,
				Severity:      rule.Severity,
				CVSSScore:     rule.CVSSScore,
				Description:   fmt.Sprintf("Interface '%s' embeds plaintext private key in Nix configuration at line %d.", currentIface.Name, lineNum),
				Remediation:   rule.Remediation,
				MatchedCVE:    rule.MatchedCVE,
				FilePath:      filePath,
				StartLine:     lineNum,
			})
		}

		if m := rePrivateKeyFile.FindStringSubmatch(line); len(m) > 1 {
			currentIface.PrivateKeyFile = m[1]
		}

		// Rule WG-MESH-011: Suboptimal MTU
		if m := reMTU.FindStringSubmatch(line); len(m) > 1 {
			if mtu, err := strconv.Atoi(m[1]); err == nil {
				currentIface.MTU = mtu
				if mtu > OptimalWireGuardMTU {
					rule := WireGuardRuleRegistry[RuleWGSuboptimalMTU]
					violations = append(violations, WireGuardViolation{
						RuleID:        rule.ID,
						Title:         rule.Title,
						InterfaceName: currentIface.Name,
						Severity:      rule.Severity,
						CVSSScore:     rule.CVSSScore,
						Description:   fmt.Sprintf("Interface '%s' specifies MTU %d (> %d), risking packet fragmentation on standard Ethernet overlays.", currentIface.Name, mtu, OptimalWireGuardMTU),
						Remediation:   rule.Remediation,
						FilePath:      filePath,
						StartLine:     lineNum,
					})
				}
			}
		}

		// 3. Detect peers list
		if strings.Contains(line, "peers = [") {
			inPeersBlock = true
			continue
		}

		if inPeersBlock {
			if strings.Contains(trimmed, "{") {
				flushPeer()
				currentPeer = &PeerDeclaration{
					StartLine: lineNum,
				}
			}

			if currentPeer != nil {
				if m := rePublicKey.FindStringSubmatch(line); len(m) > 1 {
					currentPeer.PublicKey = m[1]
					if valid, err := s.keyEngine.ValidateKeyFormat(m[1]); !valid {
						rule := WireGuardRuleRegistry[RuleWGInvalidKeyFormat]
						violations = append(violations, WireGuardViolation{
							RuleID:        rule.ID,
							Title:         rule.Title,
							InterfaceName: currentIface.Name,
							PeerPublicKey: s.keyEngine.MaskKey(m[1]),
							Severity:      rule.Severity,
							CVSSScore:     rule.CVSSScore,
							Description:   fmt.Sprintf("Peer public key '%s' has invalid format or degenerate key pattern: %v", s.keyEngine.MaskKey(m[1]), err),
							Remediation:   rule.Remediation,
							FilePath:      filePath,
							StartLine:     lineNum,
						})
					}
				}

				// Rule WG-MESH-003: Plaintext PSK
				if m := rePSK.FindStringSubmatch(line); len(m) > 1 {
					currentPeer.PresharedKey = m[1]
					rule := WireGuardRuleRegistry[RuleWGPlaintextPSK]
					violations = append(violations, WireGuardViolation{
						RuleID:        rule.ID,
						Title:         rule.Title,
						InterfaceName: currentIface.Name,
						PeerPublicKey: s.keyEngine.MaskKey(currentPeer.PublicKey),
						Severity:      rule.Severity,
						CVSSScore:     rule.CVSSScore,
						Description:   fmt.Sprintf("Peer on interface '%s' hardcodes plaintext pre-shared key (presharedKey) at line %d.", currentIface.Name, lineNum),
						Remediation:   rule.Remediation,
						FilePath:      filePath,
						StartLine:     lineNum,
					})
				}

				if m := rePSKFile.FindStringSubmatch(line); len(m) > 1 {
					currentPeer.PresharedKeyFile = m[1]
				}

				if m := reEndpoint.FindStringSubmatch(line); len(m) > 1 {
					currentPeer.Endpoint = m[1]
				}

				if m := reKeepalive.FindStringSubmatch(line); len(m) > 1 {
					if ka, err := strconv.Atoi(m[1]); err == nil {
						currentPeer.PersistentKeepalive = ka
					}
				}

				if m := reAllowedIPs.FindStringSubmatch(line); len(m) > 1 {
					rawIPs := strings.Fields(m[1])
					for _, rip := range rawIPs {
						cleanIP := strings.Trim(rip, `",`)
						if cleanIP != "" {
							currentPeer.AllowedIPs = append(currentPeer.AllowedIPs, cleanIP)
							// Rule WG-MESH-004: Overly Permissive 0.0.0.0/0
							if cleanIP == "0.0.0.0/0" || cleanIP == "::/0" {
								rule := WireGuardRuleRegistry[RuleWGPermissiveAllowedIPs]
								violations = append(violations, WireGuardViolation{
									RuleID:        rule.ID,
									Title:         rule.Title,
									InterfaceName: currentIface.Name,
									PeerPublicKey: s.keyEngine.MaskKey(currentPeer.PublicKey),
									Endpoint:      currentPeer.Endpoint,
									Severity:      rule.Severity,
									CVSSScore:     rule.CVSSScore,
									Description:   fmt.Sprintf("Peer on interface '%s' specifies permissive '%s' in allowedIPs, routing all node traffic through overlay.", currentIface.Name, cleanIP),
									Remediation:   rule.Remediation,
									FilePath:      filePath,
									StartLine:     lineNum,
								})
							}
						}
					}
				}
			}

			if trimmed == "}" || trimmed == "}," {
				flushPeer()
			}

			if trimmed == "];" {
				flushPeer()
				inPeersBlock = false
			}
		}

		if strings.HasPrefix(trimmed, "};") && !inPeersBlock {
			flushIface()
		}
	}

	flushIface()

	// 4. Interface-level post-parsing validation: PSK verification & AllowedIPs overlap checks
	for _, iface := range interfaces {
		peerIPMap := make(map[string]string) // IP -> PeerPublicKey

		for _, peer := range iface.Peers {
			// Rule WG-MESH-002: Missing PSK
			if peer.PresharedKey == "" && peer.PresharedKeyFile == "" {
				rule := WireGuardRuleRegistry[RuleWGMpyMissingPSK]
				violations = append(violations, WireGuardViolation{
					RuleID:        rule.ID,
					Title:         rule.Title,
					InterfaceName: iface.Name,
					PeerPublicKey: s.keyEngine.MaskKey(peer.PublicKey),
					Endpoint:      peer.Endpoint,
					Severity:      rule.Severity,
					CVSSScore:     rule.CVSSScore,
					Description:   fmt.Sprintf("Peer %s on interface '%s' lacks pre-shared key (PSK) for post-quantum defense-in-depth.", s.keyEngine.MaskKey(peer.PublicKey), iface.Name),
					Remediation:   rule.Remediation,
					FilePath:      filePath,
					StartLine:     peer.StartLine,
				})
			}

			// Rule WG-MESH-005: AllowedIPs Overlap & Subnet Collision
			for _, cidr := range peer.AllowedIPs {
				if existingPeer, exists := peerIPMap[cidr]; exists && existingPeer != peer.PublicKey {
					rule := WireGuardRuleRegistry[RuleWGAllowedIPsOverlap]
					violations = append(violations, WireGuardViolation{
						RuleID:        rule.ID,
						Title:         rule.Title,
						InterfaceName: iface.Name,
						PeerPublicKey: s.keyEngine.MaskKey(peer.PublicKey),
						Severity:      rule.Severity,
						CVSSScore:     rule.CVSSScore,
						Description:   fmt.Sprintf("AllowedIPs collision on interface '%s': CIDR '%s' is claimed by both %s and %s.", iface.Name, cidr, s.keyEngine.MaskKey(existingPeer), s.keyEngine.MaskKey(peer.PublicKey)),
						Remediation:   rule.Remediation,
						MatchedCVE:    rule.MatchedCVE,
						FilePath:      filePath,
						StartLine:     peer.StartLine,
					})
				} else {
					peerIPMap[cidr] = peer.PublicKey
				}
			}
		}
	}

	return interfaces, violations, nil
}

// IsSubnetOverlap evaluates if two CIDR network blocks overlap.
func IsSubnetOverlap(cidr1, cidr2 string) bool {
	_, net1, err1 := net.ParseCIDR(cidr1)
	_, net2, err2 := net.ParseCIDR(cidr2)
	if err1 != nil || err2 != nil {
		return false
	}
	return net1.Contains(net2.IP) || net2.Contains(net1.IP)
}
