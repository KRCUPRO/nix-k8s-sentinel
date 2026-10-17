package replication

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	reYamlDocSep = regexp.MustCompile(`(?m)^---\s*$`)
)

// ParsedDRManifests holds collections of discovered DR and snapshot resources.
type ParsedDRManifests struct {
	SnapshotClasses   []VolumeSnapshotClassConfig
	SnapshotSchedules []SnapshotSchedulePolicy
	ReplicationClasses []VolumeReplicationClassConfig
	VolumeReplications []VolumeReplicationConfig
	MirrorDaemons     []CephMirrorDaemonConfig
	ArbiterConfigs    []CephArbiterConfig
}

// ParseManifestFile reads and parses a Kubernetes YAML or JSON manifest file.
func ParseManifestFile(filePath string) (*ParsedDRManifests, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat manifest file: %w", err)
	}
	if info.Size() > MaxManifestBytes {
		return nil, fmt.Errorf("manifest file exceeds maximum size ceiling (%d > %d)", info.Size(), MaxManifestBytes)
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}

	return ParseManifestBytes(content, filePath)
}

// ParseManifestBytes parses raw YAML/JSON documents into structured DR objects.
func ParseManifestBytes(data []byte, sourceFile string) (*ParsedDRManifests, error) {
	if len(data) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest data exceeds size limit (%d bytes)", MaxManifestBytes)
	}

	result := &ParsedDRManifests{}
	docs := splitDocuments(data)

	lineOffset := 1
	for _, doc := range docs {
		trimmed := bytes.TrimSpace(doc)
		if len(trimmed) > 0 {
			parseSingleDocument(trimmed, sourceFile, lineOffset, result)
		}
		lineOffset += bytes.Count(doc, []byte("\n"))
	}

	return result, nil
}

func splitDocuments(data []byte) [][]byte {
	indices := reYamlDocSep.FindAllIndex(data, -1)
	if len(indices) == 0 {
		return [][]byte{data}
	}

	var docs [][]byte
	start := 0
	for _, idx := range indices {
		if idx[0] > start {
			docs = append(docs, data[start:idx[0]])
		}
		start = idx[1]
	}
	if start < len(data) {
		docs = append(docs, data[start:])
	}
	return docs
}

func parseSingleDocument(doc []byte, sourceFile string, startLine int, res *ParsedDRManifests) {
	scanner := bufio.NewScanner(bytes.NewReader(doc))
	var kind, name, namespace, driver, delPolicy, prov, sched, repState, repClass, pvcName string
	var mirroringMode ReplicationMode
	var retentionCount, replicas int
	var pruneEnabled, encryptedTransport, antiAffinity, arbiterEnabled bool
	var arbiterZone, failureDomain string

	params := make(map[string]string)
	inParams := false
	inArbiter := false
	inAntiAffinity := false

	lineNum := startLine - 1
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.HasPrefix(trimmed, "kind:") {
			kind = strings.TrimSpace(strings.TrimPrefix(trimmed, "kind:"))
			kind = strings.Trim(kind, `"'`)
		} else if strings.HasPrefix(trimmed, "name:") && name == "" {
			name = strings.TrimSpace(strings.TrimPrefix(trimmed, "name:"))
			name = strings.Trim(name, `"'`)
		} else if strings.HasPrefix(trimmed, "namespace:") && namespace == "" {
			namespace = strings.TrimSpace(strings.TrimPrefix(trimmed, "namespace:"))
			namespace = strings.Trim(namespace, `"'`)
		} else if strings.HasPrefix(trimmed, "driver:") {
			driver = strings.TrimSpace(strings.TrimPrefix(trimmed, "driver:"))
			driver = strings.Trim(driver, `"'`)
		} else if strings.HasPrefix(trimmed, "deletionPolicy:") {
			delPolicy = strings.TrimSpace(strings.TrimPrefix(trimmed, "deletionPolicy:"))
			delPolicy = strings.Trim(delPolicy, `"'`)
		} else if strings.HasPrefix(trimmed, "provisioner:") {
			prov = strings.TrimSpace(strings.TrimPrefix(trimmed, "provisioner:"))
			prov = strings.Trim(prov, `"'`)
		} else if strings.HasPrefix(trimmed, "mirroringMode:") {
			m := strings.TrimSpace(strings.TrimPrefix(trimmed, "mirroringMode:"))
			mirroringMode = ReplicationMode(strings.Trim(m, `"'`))
		} else if strings.HasPrefix(trimmed, "schedulingInterval:") {
			sched = strings.TrimSpace(strings.TrimPrefix(trimmed, "schedulingInterval:"))
			sched = strings.Trim(sched, `"'`)
		} else if strings.HasPrefix(trimmed, "schedule:") {
			sched = strings.TrimSpace(strings.TrimPrefix(trimmed, "schedule:"))
			sched = strings.Trim(sched, `"'`)
		} else if strings.HasPrefix(trimmed, "retentionCount:") || strings.HasPrefix(trimmed, "retention:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				val, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
				retentionCount = val
			}
		} else if strings.HasPrefix(trimmed, "pruneOld:") || strings.HasPrefix(trimmed, "prune:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 && strings.Contains(strings.ToLower(parts[1]), "true") {
				pruneEnabled = true
			}
		} else if strings.HasPrefix(trimmed, "volumeReplicationClass:") || strings.HasPrefix(trimmed, "volumeReplicationClassName:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				repClass = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			}
		} else if strings.HasPrefix(trimmed, "replicationState:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				repState = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			}
		} else if strings.HasPrefix(trimmed, "claimName:") || strings.HasPrefix(trimmed, "pvcName:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				pvcName = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			}
		} else if strings.HasPrefix(trimmed, "replicas:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				r, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
				replicas = r
			}
		} else if strings.HasPrefix(trimmed, "podAntiAffinity:") || strings.Contains(trimmed, "antiAffinity") {
			inAntiAffinity = true
			antiAffinity = true
		} else if strings.HasPrefix(trimmed, "arbiter:") {
			inArbiter = true
		} else if inArbiter && strings.HasPrefix(trimmed, "enabled:") {
			if strings.Contains(strings.ToLower(trimmed), "true") {
				arbiterEnabled = true
			}
		} else if inArbiter && strings.HasPrefix(trimmed, "arbiterZone:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				arbiterZone = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			}
		} else if inArbiter && strings.HasPrefix(trimmed, "failureDomain:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				failureDomain = strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			}
		} else if strings.HasPrefix(trimmed, "parameters:") {
			inParams = true
		} else if inParams {
			if strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t") {
				parts := strings.SplitN(trimmed, ":", 2)
				if len(parts) == 2 {
					k := strings.TrimSpace(parts[0])
					v := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
					params[k] = v
					if strings.Contains(k, "encrypted") || strings.Contains(k, "ms_mode") || strings.Contains(k, "tls") {
						if v == "true" || v == "secure" {
							encryptedTransport = true
						}
					}
				}
			} else {
				inParams = false
			}
		}
	}
	_ = inAntiAffinity

	switch kind {
	case "VolumeSnapshotClass":
		res.SnapshotClasses = append(res.SnapshotClasses, VolumeSnapshotClassConfig{
			Name:           name,
			Driver:         driver,
			DeletionPolicy: DeletionPolicy(delPolicy),
			Parameters:     params,
			File:           sourceFile,
			Line:           startLine,
		})
	case "CephFilesystemSubVolumeGroup", "VolumeSnapshotSchedule":
		res.SnapshotSchedules = append(res.SnapshotSchedules, SnapshotSchedulePolicy{
			Name:            name,
			Schedule:        sched,
			RetentionCount:  retentionCount,
			PruneOldEnabled: pruneEnabled,
			File:            sourceFile,
			Line:            startLine,
		})
	case "VolumeReplicationClass":
		res.ReplicationClasses = append(res.ReplicationClasses, VolumeReplicationClassConfig{
			Name:               name,
			Provisioner:        prov,
			MirroringMode:      mirroringMode,
			SchedulingInterval: sched,
			EncryptedTransport: encryptedTransport,
			Parameters:         params,
			File:               sourceFile,
			Line:               startLine,
		})
	case "VolumeReplication":
		res.VolumeReplications = append(res.VolumeReplications, VolumeReplicationConfig{
			Name:                   name,
			Namespace:              namespace,
			VolumeReplicationClass: repClass,
			PVCName:                pvcName,
			ReplicationState:       ReplicationState(repState),
			File:                   sourceFile,
			Line:                   startLine,
		})
	case "CephFilesystemMirror", "CephRBDMirror":
		res.MirrorDaemons = append(res.MirrorDaemons, CephMirrorDaemonConfig{
			Name:         name,
			Kind:         kind,
			Replicas:     replicas,
			AntiAffinity: antiAffinity,
			File:         sourceFile,
			Line:         startLine,
		})
	case "CephCluster":
		res.ArbiterConfigs = append(res.ArbiterConfigs, CephArbiterConfig{
			ClusterName:    name,
			ArbiterZone:    arbiterZone,
			ArbiterEnabled: arbiterEnabled,
			FailureDomain:  failureDomain,
			File:           sourceFile,
			Line:           startLine,
		})
	}
}

// ParseCrossRegionDRTelemetry parses live JSON disaster recovery telemetry.
func ParseCrossRegionDRTelemetry(data []byte) (*CrossRegionDRTelemetry, error) {
	if len(data) > MaxTelemetryBytes {
		return nil, fmt.Errorf("DR telemetry exceeds maximum size ceiling (%d > %d bytes)", len(data), MaxTelemetryBytes)
	}

	var telemetry CrossRegionDRTelemetry
	if err := json.Unmarshal(data, &telemetry); err != nil {
		return nil, fmt.Errorf("failed to parse DR telemetry JSON: %w", err)
	}

	return &telemetry, nil
}
