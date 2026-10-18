package impermanence

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	reHostName         = regexp.MustCompile(`(?i)(?:networking\.hostName|hostName)\s*=\s*"([^"]+)"`)
	reRootFsType       = regexp.MustCompile(`(?i)fileSystems\."\/"\.fsType\s*=\s*"([^"]+)"`)
	rePersistenceRoot  = regexp.MustCompile(`(?i)environment\.persistence\."([^"]+)"`)
	reHideMounts       = regexp.MustCompile(`(?i)hideMounts\s*=\s*(true|false)`)
	reZfsRollback      = regexp.MustCompile(`(?i)zfs\s+rollback\s+-r\s+([^\s]+)`)
	reBtrfsSubvol      = regexp.MustCompile(`(?i)btrfs\s+subvolume\s+(?:snapshot|delete)`)
	reRandomEncryption = regexp.MustCompile(`(?i)randomEncryption(?:\.enable)?\s*=\s*true`)
	reLuksEncrypted    = regexp.MustCompile(`(?i)(?:boot\.initrd\.luks|luks\.devices|/dev/mapper/enc)`)
	reK8sKind          = regexp.MustCompile(`(?i)^kind:\s*([A-Za-z0-9]+)`)
	reK8sName          = regexp.MustCompile(`(?i)^\s*name:\s*([A-Za-z0-9._-]+)`)
	reK8sNamespace     = regexp.MustCompile(`(?i)^\s*namespace:\s*([A-Za-z0-9._-]+)`)
	reHostPath         = regexp.MustCompile(`(?i)^\s*path:\s*([^\s#]+)`)
	reMountPath        = regexp.MustCompile(`(?i)^\s*mountPath:\s*([^\s#]+)`)
	reReadOnly         = regexp.MustCompile(`(?i)^\s*readOnly:\s*(true|false)`)
)

// ParseNixOSImpermanence parses a NixOS configuration file or snippet for impermanence settings.
func ParseNixOSImpermanence(content string, filePath string) (*ImpermanenceHostConfig, error) {
	if int64(len(content)) > MaxManifestBytes {
		return nil, fmt.Errorf("configuration payload exceeds maximum allowed size (%d bytes)", MaxManifestBytes)
	}

	host := &ImpermanenceHostConfig{
		HostName:          filepath.Base(filePath),
		FilePath:          filePath,
		StartLine:         1,
		Mode:              ModeUnknown,
		KernelParams:      make([]string, 0),
		PersistentEntries: make([]PersistentEntry, 0),
		SwapDevices:       make([]SwapDeviceConfig, 0),
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0
	inDirectories := false
	inFiles := false
	inKernelParams := false
	inSwapDevices := false
	inPostDeviceCommands := false
	inRootFileSystem := false
	currentSwap := SwapDeviceConfig{}

	for scanner.Scan() {
		lineNum++
		if lineNum > MaxAllowedScanLines {
			break
		}
		rawLine := scanner.Text()
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if m := reHostName.FindStringSubmatch(trimmed); len(m) > 1 {
			host.HostName = m[1]
		}
		if strings.Contains(trimmed, `fileSystems."/"`) {
			inRootFileSystem = true
			if m := reRootFsType.FindStringSubmatch(trimmed); len(m) > 1 {
				host.RootFsType = strings.ToLower(m[1])
			}
		}
		if inRootFileSystem {
			if strings.Contains(trimmed, "fsType =") {
				parts := strings.Split(trimmed, "=")
				if len(parts) > 1 {
					host.RootFsType = strings.ToLower(strings.Trim(strings.TrimSpace(parts[1]), "\";"))
				}
			}
			if strings.Contains(trimmed, "};") || (strings.Contains(trimmed, "}") && !strings.Contains(trimmed, "{")) {
				inRootFileSystem = false
			}
		}
		if m := rePersistenceRoot.FindStringSubmatch(trimmed); len(m) > 1 {
			if host.PersistenceRoot == "" {
				host.PersistenceRoot = m[1]
			}
		}
		if reLuksEncrypted.MatchString(trimmed) {
			host.StorageEncrypted = true
		}

		// Detect wipe commands in postDeviceCommands or systemd-initrd
		if strings.Contains(trimmed, "boot.initrd.postDeviceCommands") || strings.Contains(trimmed, "systemd.initrd") {
			inPostDeviceCommands = true
		}
		if inPostDeviceCommands {
			if m := reZfsRollback.FindStringSubmatch(trimmed); len(m) > 1 {
				host.WipeOnReboot = true
				host.WipeHookCommand = "zfs rollback -r " + m[1]
			} else if reBtrfsSubvol.MatchString(trimmed) {
				host.WipeOnReboot = true
				host.WipeHookCommand = "btrfs subvolume reset"
			}
			if strings.Contains(trimmed, "''") && strings.Count(trimmed, "''")%2 != 0 {
				inPostDeviceCommands = false
			}
		}

		// Swap devices block
		if strings.Contains(trimmed, "swapDevices") && strings.Contains(trimmed, "[") {
			inSwapDevices = true
			continue
		}
		if inSwapDevices {
			if strings.Contains(trimmed, "device =") {
				parts := strings.Split(trimmed, "=")
				if len(parts) > 1 {
					currentSwap.Device = strings.Trim(strings.TrimSpace(parts[1]), "\";")
				}
			}
			if reRandomEncryption.MatchString(trimmed) {
				currentSwap.RandomEncryption = true
			}
			if strings.Contains(trimmed, "}") {
				if currentSwap.Device != "" {
					host.SwapDevices = append(host.SwapDevices, currentSwap)
					if !currentSwap.RandomEncryption {
						host.HasUnencryptedSwap = true
					}
					currentSwap = SwapDeviceConfig{}
				}
			}
			if strings.Contains(trimmed, "];") {
				inSwapDevices = false
			}
		}

		// Kernel parameters
		if strings.Contains(trimmed, "boot.kernelParams") && strings.Contains(trimmed, "[") {
			inKernelParams = true
			continue
		}
		if inKernelParams {
			cleanParam := strings.Trim(trimmed, "\";[]")
			if cleanParam != "" {
				host.KernelParams = append(host.KernelParams, cleanParam)
				if strings.Contains(cleanParam, "page_poison=1") ||
					strings.Contains(cleanParam, "init_on_free=1") ||
					strings.Contains(cleanParam, "init_on_alloc=1") {
					host.KernelMemoryWiping = true
				}
			}
			if strings.Contains(trimmed, "];") {
				inKernelParams = false
			}
		}

		// Persistence block entries
		if strings.Contains(trimmed, "directories = [") {
			inDirectories = true
			continue
		}
		if inDirectories {
			if strings.Contains(trimmed, "];") {
				inDirectories = false
			} else {
				entry := parsePersistentEntry(trimmed, false, lineNum, filePath)
				if entry != nil {
					host.PersistentEntries = append(host.PersistentEntries, *entry)
					checkSpecialPaths(host, entry.Path, false)
				}
			}
		}

		if strings.Contains(trimmed, "files = [") {
			inFiles = true
			continue
		}
		if inFiles {
			if strings.Contains(trimmed, "];") {
				inFiles = false
			} else {
				entry := parsePersistentEntry(trimmed, true, lineNum, filePath)
				if entry != nil {
					host.PersistentEntries = append(host.PersistentEntries, *entry)
					checkSpecialPaths(host, entry.Path, true)
				}
			}
		}
	}

	// Classify persistence mode
	switch host.RootFsType {
	case "tmpfs":
		host.Mode = ModeTmpfsRoot
		host.WipeOnReboot = true
	case "zfs":
		if host.WipeOnReboot {
			host.Mode = ModeZfsRollback
		} else {
			host.Mode = ModeMutableDisk
		}
	case "btrfs":
		if host.WipeOnReboot {
			host.Mode = ModeBtrfsSnapshot
		} else {
			host.Mode = ModeMutableDisk
		}
	case "ext4", "xfs", "bcachefs":
		host.Mode = ModeMutableDisk
	default:
		if host.PersistenceRoot != "" && !host.WipeOnReboot {
			host.Mode = ModeMutableDisk
		}
	}

	// Flag containerd on tmpfs if root is tmpfs and containerd is not persisted
	if host.Mode == ModeTmpfsRoot && !host.ContainerdPersisted {
		host.ContainerdOnTmpfs = true
	}

	return host, nil
}

func checkSpecialPaths(host *ImpermanenceHostConfig, path string, isFile bool) {
	clean := filepath.ToSlash(filepath.Clean(path))
	if isFile && clean == "/etc/machine-id" {
		host.MachineIDPersisted = true
	}
	if !isFile {
		if strings.HasPrefix(clean, "/var/lib/kubelet") {
			host.KubeletPKIPersisted = true
		}
		if strings.HasPrefix(clean, "/var/lib/containerd") || strings.HasPrefix(clean, "/var/lib/docker") {
			host.ContainerdPersisted = true
		}
	}
}

func parsePersistentEntry(line string, isFile bool, lineNum int, filePath string) *PersistentEntry {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || trimmed == "]" || trimmed == "];" {
		return nil
	}

	entry := &PersistentEntry{
		MountType:  MountBind,
		IsFile:     isFile,
		FilePath:   filePath,
		LineNumber: lineNum,
	}

	// Check if simple string path: "/var/log"
	if strings.HasPrefix(trimmed, "\"") {
		clean := strings.Trim(trimmed, "\",;")
		entry.Path = clean
		return entry
	}

	// Attrset entry: { directory = "/var/lib/kubelet"; mode = "0700"; }
	if strings.HasPrefix(trimmed, "{") {
		trimmedClean := strings.Trim(trimmed, "{}; ")
		fields := strings.Split(trimmedClean, ";")
		for _, f := range fields {
			f = strings.TrimSpace(strings.Trim(f, "{} "))
			if strings.HasPrefix(f, "directory =") || strings.HasPrefix(f, "file =") {
				parts := strings.Split(f, "=")
				if len(parts) > 1 {
					entry.Path = strings.Trim(strings.TrimSpace(parts[1]), "\"{}; ")
				}
			} else if strings.HasPrefix(f, "mode =") {
				parts := strings.Split(f, "=")
				if len(parts) > 1 {
					entry.Mode = strings.Trim(strings.TrimSpace(parts[1]), "\"{}; ")
				}
			} else if strings.HasPrefix(f, "user =") {
				parts := strings.Split(f, "=")
				if len(parts) > 1 {
					entry.User = strings.Trim(strings.TrimSpace(parts[1]), "\"{}; ")
				}
			} else if strings.HasPrefix(f, "group =") {
				parts := strings.Split(f, "=")
				if len(parts) > 1 {
					entry.Group = strings.Trim(strings.TrimSpace(parts[1]), "\"{}; ")
				}
			} else if strings.HasPrefix(f, "how =") {
				if strings.Contains(f, "symlink") {
					entry.MountType = MountSymlink
				}
			}
		}
		if entry.Path != "" {
			return entry
		}
	}

	return nil
}

// ParseK8sStorageMounts extracts hostPath volume mounts from Kubernetes manifests.
func ParseK8sStorageMounts(content string, filePath string) ([]ClusterMountReference, error) {
	if int64(len(content)) > MaxManifestBytes {
		return nil, fmt.Errorf("Kubernetes manifest payload exceeds maximum allowed size (%d bytes)", MaxManifestBytes)
	}

	var references []ClusterMountReference
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0

	var currentKind, currentName, currentNamespace string
	var inHostPath, inVolumeMounts bool
	var lastHostPath string

	for scanner.Scan() {
		lineNum++
		if lineNum > MaxAllowedScanLines {
			break
		}
		rawLine := scanner.Text()
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if m := reK8sKind.FindStringSubmatch(trimmed); len(m) > 1 {
			currentKind = m[1]
		}
		if m := reK8sName.FindStringSubmatch(trimmed); len(m) > 1 && currentName == "" {
			currentName = m[1]
		}
		if m := reK8sNamespace.FindStringSubmatch(trimmed); len(m) > 1 {
			currentNamespace = m[1]
		}

		if strings.Contains(trimmed, "---") {
			currentKind = ""
			currentName = ""
			currentNamespace = ""
			inHostPath = false
			inVolumeMounts = false
			lastHostPath = ""
			continue
		}

		if strings.Contains(trimmed, "hostPath:") {
			inHostPath = true
			continue
		}
		if inHostPath {
			if m := reHostPath.FindStringSubmatch(trimmed); len(m) > 1 {
				lastHostPath = m[1]
				references = append(references, ClusterMountReference{
					ResourceKind: currentKind,
					ResourceName: currentName,
					Namespace:    currentNamespace,
					HostPath:     lastHostPath,
					FilePath:     filePath,
					LineNumber:   lineNum,
				})
				inHostPath = false
			}
		}

		if strings.Contains(trimmed, "volumeMounts:") {
			inVolumeMounts = true
			continue
		}
		if inVolumeMounts {
			if strings.HasPrefix(trimmed, "-") && strings.Contains(trimmed, "mountPath:") {
				if m := reMountPath.FindStringSubmatch(trimmed); len(m) > 1 {
					mountRef := ClusterMountReference{
						ResourceKind: currentKind,
						ResourceName: currentName,
						Namespace:    currentNamespace,
						MountPath:    m[1],
						FilePath:     filePath,
						LineNumber:   lineNum,
					}
					references = append(references, mountRef)
				}
			}
		}
	}

	return references, nil
}

// ParseImpermanenceTelemetryJSON parses runtime ephemeral storage telemetry.
func ParseImpermanenceTelemetryJSON(data []byte) (*ImpermanenceTelemetry, error) {
	if int64(len(data)) > MaxTelemetryBytes {
		return nil, fmt.Errorf("telemetry payload exceeds maximum allowed size (%d bytes)", MaxTelemetryBytes)
	}

	var telemetry ImpermanenceTelemetry
	if err := json.Unmarshal(data, &telemetry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal impermanence telemetry JSON: %w", err)
	}

	if telemetry.Timestamp.IsZero() {
		telemetry.Timestamp = time.Now()
	}

	return &telemetry, nil
}

// ReadFileWithLimit reads a file while enforcing the provided byte limit.
func ReadFileWithLimit(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("file size (%d bytes) exceeds maximum limit (%d bytes)", info.Size(), limit)
	}
	return os.ReadFile(path)
}
