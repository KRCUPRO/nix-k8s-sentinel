package bgp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseCiliumBGPPeeringPolicy parses Cilium BGP peering policy manifests from YAML stream.
func ParseCiliumBGPPeeringPolicy(data []byte, filename string) ([]CiliumBGPPeeringPolicyConfig, error) {
	if int64(len(data)) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest payload exceeds maximum limit of %d bytes", MaxManifestBytes)
	}

	var policies []CiliumBGPPeeringPolicyConfig
	docs := bytes.Split(data, []byte("\n---"))

	for docIdx, doc := range docs {
		trimmed := bytes.TrimSpace(doc)
		if len(trimmed) == 0 {
			continue
		}

		scanner := bufio.NewScanner(bytes.NewReader(trimmed))
		lineCount := 0

		var currentPolicy CiliumBGPPeeringPolicyConfig
		var currentRouter *VirtualRouterConfig
		var currentNeighbor *CiliumBGPPeerConfig

		inVirtualRouters := false
		inNeighbors := false
		inFamilies := false
		inPrefixFilters := false
		isBGPKind := false

		currentPolicy.SourceFile = filename
		currentPolicy.StartLine = 1 + docIdx*20

		for scanner.Scan() {
			lineCount++
			if lineCount > MaxAllowedScanLines {
				return nil, fmt.Errorf("manifest exceeds scan ceiling of %d lines", MaxAllowedScanLines)
			}

			line := scanner.Text()
			clean := strings.TrimSpace(line)

			if strings.HasPrefix(clean, "#") || clean == "" {
				continue
			}

			if strings.HasPrefix(clean, "kind:") {
				val := strings.TrimSpace(strings.TrimPrefix(clean, "kind:"))
				val = strings.Trim(val, `"'`)
				if val == "CiliumBGPPeeringPolicy" || val == "CiliumBGPClusterConfig" || val == "CiliumBGPNodeConfig" {
					isBGPKind = true
				}
				continue
			}

			if strings.HasPrefix(clean, "name:") && !inNeighbors && !inVirtualRouters && currentPolicy.PolicyName == "" {
				val := strings.TrimSpace(strings.TrimPrefix(clean, "name:"))
				currentPolicy.PolicyName = strings.Trim(val, `"'`)
				continue
			}

			if strings.HasPrefix(clean, "virtualRouters:") {
				inVirtualRouters = true
				continue
			}

			if inVirtualRouters {
				if strings.HasPrefix(clean, "- localASN:") || strings.HasPrefix(clean, "localASN:") {
					if currentRouter != nil {
						if currentNeighbor != nil {
							currentRouter.Neighbors = append(currentRouter.Neighbors, *currentNeighbor)
							currentNeighbor = nil
						}
						currentPolicy.VirtualRouters = append(currentPolicy.VirtualRouters, *currentRouter)
					}
					currentRouter = &VirtualRouterConfig{}
					inNeighbors = false
					inFamilies = false
					inPrefixFilters = false

					parts := strings.Split(clean, "localASN:")
					if len(parts) == 2 {
						asn, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
						currentRouter.LocalASN = asn
					}
					continue
				}

				if strings.HasPrefix(clean, "exportPodCIDR:") && currentRouter != nil {
					val := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(clean, "exportPodCIDR:")))
					currentRouter.ExportPodCIDR = val == "true"
					continue
				}

				if strings.HasPrefix(clean, "exportServiceCIDR:") && currentRouter != nil {
					val := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(clean, "exportServiceCIDR:")))
					currentRouter.ExportServiceCIDR = val == "true"
					continue
				}

				if strings.HasPrefix(clean, "prefixFilters:") || strings.HasPrefix(clean, "prefixList:") {
					inPrefixFilters = true
					inFamilies = false
					continue
				}

				if inPrefixFilters && strings.HasPrefix(clean, "-") {
					prefix := strings.TrimSpace(strings.TrimPrefix(clean, "-"))
					prefix = strings.Trim(prefix, `"'`)
					if currentRouter != nil && prefix != "" {
						currentRouter.PrefixFilters = append(currentRouter.PrefixFilters, prefix)
					}
					continue
				}

				if strings.HasPrefix(clean, "neighbors:") {
					inNeighbors = true
					inPrefixFilters = false
					continue
				}

				if inNeighbors {
					if strings.HasPrefix(clean, "- peerAddress:") || strings.HasPrefix(clean, "peerAddress:") {
						if currentNeighbor != nil && currentRouter != nil {
							currentRouter.Neighbors = append(currentRouter.Neighbors, *currentNeighbor)
						}
						currentNeighbor = &CiliumBGPPeerConfig{}
						inFamilies = false

						parts := strings.Split(clean, "peerAddress:")
						if len(parts) == 2 {
							currentNeighbor.PeerAddress = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
						}
						continue
					}

					if strings.HasPrefix(clean, "peerASN:") && currentNeighbor != nil {
						val := strings.TrimSpace(strings.TrimPrefix(clean, "peerASN:"))
						asn, _ := strconv.Atoi(val)
						currentNeighbor.PeerASN = asn
						continue
					}

					if strings.HasPrefix(clean, "authSecretRef:") || strings.HasPrefix(clean, "password:") {
						if currentNeighbor != nil {
							parts := strings.Split(clean, ":")
							if len(parts) >= 2 {
								secret := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
								currentNeighbor.AuthSecret = secret
								if secret != "" {
									currentNeighbor.HasMD5 = true
								}
							}
						}
						continue
					}

					if strings.HasPrefix(clean, "tcpAO:") || strings.HasPrefix(clean, "tcpAo:") {
						if currentNeighbor != nil {
							val := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(clean, "tcpAO:")))
							if val == "true" || strings.Contains(clean, "key") {
								currentNeighbor.HasTCPAO = true
							}
						}
						continue
					}

					if strings.HasPrefix(clean, "eBGP рассказать:") || strings.HasPrefix(clean, "eBGP:") || strings.HasPrefix(clean, "multihopTTL:") || strings.HasPrefix(clean, "ttl:") {
						if currentNeighbor != nil {
							parts := strings.Split(clean, ":")
							if len(parts) >= 2 {
								ttl, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
								currentNeighbor.MultihopTTL = ttl
							}
						}
						continue
					}

					if strings.HasPrefix(clean, "gracefulRestart:") {
						if currentNeighbor != nil {
							val := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(clean, "gracefulRestart:")))
							if val == "true" || strings.Contains(val, "enabled") {
								currentNeighbor.GracefulRestart = true
							}
						}
						continue
					}

					if strings.HasPrefix(clean, "restartTimeSeconds:") || strings.HasPrefix(clean, "restartTime:") {
						if currentNeighbor != nil {
							parts := strings.Split(clean, ":")
							if len(parts) >= 2 {
								sec, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
								currentNeighbor.GracefulRestartTime = sec
								if sec > 0 {
									currentNeighbor.GracefulRestart = true
								}
							}
						}
						continue
					}

					if strings.HasPrefix(clean, "holdTimeSeconds:") || strings.HasPrefix(clean, "holdTime:") {
						if currentNeighbor != nil {
							parts := strings.Split(clean, ":")
							if len(parts) >= 2 {
								sec, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
								currentNeighbor.HoldTime = sec
							}
						}
						continue
					}

					if strings.HasPrefix(clean, "keepAliveTimeSeconds:") || strings.HasPrefix(clean, "keepAliveTime:") || strings.HasPrefix(clean, "keepalive:") {
						if currentNeighbor != nil {
							parts := strings.Split(clean, ":")
							if len(parts) >= 2 {
								sec, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
								currentNeighbor.KeepAlive = sec
							}
						}
						continue
					}

					if strings.HasPrefix(clean, "families:") {
						inFamilies = true
						continue
					}

					if inFamilies && strings.HasPrefix(clean, "-") {
						family := strings.TrimSpace(strings.TrimPrefix(clean, "-"))
						family = strings.Trim(family, `"'`)
						if currentNeighbor != nil && family != "" {
							currentNeighbor.Families = append(currentNeighbor.Families, family)
						}
						continue
					}

					if strings.HasPrefix(clean, "community:") || strings.HasPrefix(clean, "communities:") {
						if currentNeighbor != nil {
							parts := strings.Split(clean, ":")
							if len(parts) >= 2 {
								comm := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
								if comm != "" {
									currentNeighbor.CommunityTags = append(currentNeighbor.CommunityTags, comm)
								}
							}
						}
						continue
					}
				}
			}
		}

		if currentNeighbor != nil && currentRouter != nil {
			currentRouter.Neighbors = append(currentRouter.Neighbors, *currentNeighbor)
		}
		if currentRouter != nil {
			currentPolicy.VirtualRouters = append(currentPolicy.VirtualRouters, *currentRouter)
		}

		if isBGPKind || currentPolicy.PolicyName != "" || len(currentPolicy.VirtualRouters) > 0 {
			if currentPolicy.PolicyName == "" {
				currentPolicy.PolicyName = fmt.Sprintf("cilium-bgp-policy-%d", len(policies)+1)
			}
			policies = append(policies, currentPolicy)
		}
	}

	return policies, nil
}

// ParseCiliumLoadBalancerIPPool parses CiliumLoadBalancerIPPool CRD manifests.
func ParseCiliumLoadBalancerIPPool(data []byte, filename string) ([]CiliumLoadBalancerIPPoolConfig, error) {
	if int64(len(data)) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest payload exceeds limit of %d bytes", MaxManifestBytes)
	}

	var pools []CiliumLoadBalancerIPPoolConfig
	docs := bytes.Split(data, []byte("\n---"))

	for docIdx, doc := range docs {
		trimmed := bytes.TrimSpace(doc)
		if len(trimmed) == 0 {
			continue
		}

		scanner := bufio.NewScanner(bytes.NewReader(trimmed))
		lineCount := 0
		var currentPool CiliumLoadBalancerIPPoolConfig
		currentPool.SourceFile = filename
		currentPool.StartLine = 1 + docIdx*20

		isIPPoolKind := false
		inCIDRs := false

		for scanner.Scan() {
			lineCount++
			if lineCount > MaxAllowedScanLines {
				return nil, fmt.Errorf("manifest exceeds line ceiling of %d lines", MaxAllowedScanLines)
			}

			clean := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(clean, "#") || clean == "" {
				continue
			}

			if strings.HasPrefix(clean, "kind:") {
				val := strings.Trim(strings.TrimSpace(strings.TrimPrefix(clean, "kind:")), `"'`)
				if val == "CiliumLoadBalancerIPPool" {
					isIPPoolKind = true
				}
				continue
			}

			if strings.HasPrefix(clean, "name:") && currentPool.PoolName == "" {
				currentPool.PoolName = strings.Trim(strings.TrimSpace(strings.TrimPrefix(clean, "name:")), `"'`)
				continue
			}

			if strings.HasPrefix(clean, "disabled:") {
				val := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(clean, "disabled:")))
				currentPool.Disabled = val == "true"
				continue
			}

			if strings.HasPrefix(clean, "cidrs:") || strings.HasPrefix(clean, "blocks:") {
				inCIDRs = true
				continue
			}

			if inCIDRs {
				if strings.HasPrefix(clean, "- cidr:") {
					cidrStr := strings.Trim(strings.TrimSpace(strings.TrimPrefix(clean, "- cidr:")), `"'`)
					if cidrStr != "" {
						currentPool.CIDRs = append(currentPool.CIDRs, cidrStr)
					}
					continue
				}
				if strings.HasPrefix(clean, "cidr:") {
					cidrStr := strings.Trim(strings.TrimSpace(strings.TrimPrefix(clean, "cidr:")), `"'`)
					if cidrStr != "" {
						currentPool.CIDRs = append(currentPool.CIDRs, cidrStr)
					}
					continue
				}
				if strings.HasPrefix(clean, "-") {
					cidrStr := strings.Trim(strings.TrimSpace(strings.TrimPrefix(clean, "-")), `"'`)
					if cidrStr != "" {
						currentPool.CIDRs = append(currentPool.CIDRs, cidrStr)
					}
					continue
				}
				if !strings.HasPrefix(clean, "-") && !strings.HasPrefix(clean, "cidr") {
					inCIDRs = false
				}
			}
		}

		if isIPPoolKind || len(currentPool.CIDRs) > 0 {
			if currentPool.PoolName == "" {
				currentPool.PoolName = fmt.Sprintf("cilium-ippool-%d", len(pools)+1)
			}
			pools = append(pools, currentPool)
		}
	}

	return pools, nil
}

// ParseNixOSBGPModule parses NixOS FRR and network configurations.
func ParseNixOSBGPModule(data []byte, filename string) (*NixOSBGPConfig, error) {
	if int64(len(data)) > MaxManifestBytes {
		return nil, fmt.Errorf("NixOS manifest exceeds limit of %d bytes", MaxManifestBytes)
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineCount := 0

	cfg := &NixOSBGPConfig{
		HostName:     "nixos-bgp-node",
		SourceFile:   filename,
		StartLine:    1,
		IPv6AcceptRA: -1, // -1 means unset
	}

	for scanner.Scan() {
		lineCount++
		if lineCount > MaxAllowedScanLines {
			return nil, fmt.Errorf("NixOS config exceeds line ceiling of %d lines", MaxAllowedScanLines)
		}

		clean := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(clean, "#") || clean == "" {
			continue
		}

		if strings.Contains(clean, "services.frr.bgp.enable") && strings.Contains(clean, "true") {
			cfg.FRREnabled = true
		}

		if strings.Contains(clean, "services.frr.bgp.localASN") {
			parts := strings.Split(clean, "=")
			if len(parts) >= 2 {
				val := strings.Trim(strings.TrimSpace(strings.TrimSuffix(parts[1], ";")), `"'`)
				asn, _ := strconv.Atoi(val)
				cfg.LocalASN = asn
			}
		}

		if strings.Contains(clean, "networking.firewall.allowedTCPPorts") && strings.Contains(clean, "179") {
			cfg.TCP179Allowed = true
		}

		if strings.Contains(clean, "networking.firewall.extraCommands") && strings.Contains(clean, "179") {
			cfg.FirewallRestricted = true
		}

		if strings.Contains(clean, "accept_ra") {
			parts := strings.Split(clean, "=")
			if len(parts) >= 2 {
				val := strings.Trim(strings.TrimSpace(strings.TrimSuffix(parts[1], ";")), `"'`)
				ra, err := strconv.Atoi(val)
				if err == nil {
					cfg.IPv6AcceptRA = ra
				}
			}
		}

		if strings.Contains(clean, "neighbor") && strings.Contains(clean, "password") {
			cfg.BGPNeighbors = append(cfg.BGPNeighbors, CiliumBGPPeerConfig{
				HasMD5: true,
			})
		}
	}

	return cfg, nil
}

// ParseBGPTelemetryJSON parses runtime BGP session and IPAM telemetry report from JSON.
func ParseBGPTelemetryJSON(data []byte) (*BGPTelemetryReport, error) {
	if int64(len(data)) > MaxTelemetryBytes {
		return nil, fmt.Errorf("telemetry payload exceeds maximum limit of %d bytes", MaxTelemetryBytes)
	}

	var report BGPTelemetryReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal BGP telemetry JSON: %w", err)
	}

	if report.Timestamp.IsZero() {
		report.Timestamp = time.Now().UTC()
	}

	if len(report.Peers) > MaxTelemetryEvents {
		report.Peers = report.Peers[:MaxTelemetryEvents]
	}

	return &report, nil
}
