package hsm

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	rePKCS11URI     = regexp.MustCompile(`pkcs11:[^\s"'\n]+`)
	rePinValue      = regexp.MustCompile(`(?i)(?:pin-value|pin)\s*=\s*([^;,\s"']+)`)
	reTimeoutSec    = regexp.MustCompile(`^(\d+)(?:s|sec)?$`)
	reNixP11Enable  = regexp.MustCompile(`services\.p11-kit\.enable\s*=\s*(true|false)`)
	reNixNitroEnable = regexp.MustCompile(`hardware\.nitro-enclaves\.enable\s*=\s*(true|false)`)
)

// ParseK8sEncryptionConfig parses a Kubernetes EncryptionConfiguration from an io.Reader.
func ParseK8sEncryptionConfig(r io.Reader, filePath string) (*KMSEncryptionConfig, error) {
	limitedReader := io.LimitReader(r, MaxManifestBytes+1)
	scanner := bufio.NewScanner(limitedReader)

	config := &KMSEncryptionConfig{
		FilePath:           filePath,
		EncryptedResources: make([]string, 0),
		KMSProviders:       make([]KMSProviderConfig, 0),
	}

	bytesRead := 0
	inResources := false
	inProviders := false
	var currentKMS *KMSProviderConfig
	firstProviderCaptured := false

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		bytesRead += len(line) + 1
		if bytesRead > MaxManifestBytes {
			return nil, fmt.Errorf("manifest exceeds maximum permitted size of %d bytes", MaxManifestBytes)
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Capture API version
		if strings.HasPrefix(trimmed, "apiVersion:") {
			config.ApiVersion = strings.TrimSpace(strings.TrimPrefix(trimmed, "apiVersion:"))
			if strings.Contains(config.ApiVersion, "v1beta1") || strings.Contains(config.ApiVersion, "v1alpha1") {
				config.IsKMSv2 = false
			} else if strings.Contains(config.ApiVersion, "apiserver.config.k8s.io/v1") {
				config.IsKMSv2 = true
			}
			continue
		}

		// Detect section starts
		if strings.HasPrefix(trimmed, "resources:") {
			inResources = true
			inProviders = false
			continue
		}
		if strings.HasPrefix(trimmed, "providers:") {
			inProviders = true
			inResources = false
			continue
		}

		// Parse resources
		if inResources && strings.HasPrefix(trimmed, "- ") {
			res := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			if res != "" && !strings.Contains(res, ":") {
				config.EncryptedResources = append(config.EncryptedResources, res)
			}
			continue
		}

		// Parse providers list
		if inProviders {
			if strings.HasPrefix(trimmed, "- kms:") || trimmed == "- kms" {
				if currentKMS != nil {
					config.KMSProviders = append(config.KMSProviders, *currentKMS)
				}
				if !firstProviderCaptured {
					config.PrimaryProviderType = "kms"
					firstProviderCaptured = true
				}
				currentKMS = &KMSProviderConfig{
					ApiVersion: KMSVersionV2, // Default assumption for KMS config
				}
				continue
			} else if strings.HasPrefix(trimmed, "- identity:") || trimmed == "- identity" || trimmed == "- identity: {}" {
				if currentKMS != nil {
					config.KMSProviders = append(config.KMSProviders, *currentKMS)
					currentKMS = nil
				}
				if !firstProviderCaptured {
					config.PrimaryProviderType = "identity"
					firstProviderCaptured = true
				}
				config.HasIdentityFallback = true
				continue
			} else if strings.HasPrefix(trimmed, "- aescbc:") || strings.HasPrefix(trimmed, "- secretbox:") {
				if currentKMS != nil {
					config.KMSProviders = append(config.KMSProviders, *currentKMS)
					currentKMS = nil
				}
				if !firstProviderCaptured {
					config.PrimaryProviderType = "static-key"
					firstProviderCaptured = true
				}
				continue
			}

			// Attributes of current KMS provider
			if currentKMS != nil {
				if strings.HasPrefix(trimmed, "name:") {
					currentKMS.Name = strings.TrimSpace(strings.TrimPrefix(trimmed, "name:"))
				} else if strings.HasPrefix(trimmed, "apiVersion:") {
					verStr := strings.TrimSpace(strings.TrimPrefix(trimmed, "apiVersion:"))
					if verStr == "v1" || verStr == "v1beta1" {
						currentKMS.ApiVersion = KMSVersionV1
						config.IsKMSv2 = false
					} else {
						currentKMS.ApiVersion = KMSVersionV2
					}
				} else if strings.HasPrefix(trimmed, "endpoint:") {
					ep := strings.TrimSpace(strings.TrimPrefix(trimmed, "endpoint:"))
					currentKMS.Endpoint = ep
					currentKMS.IsUnixSocket = strings.HasPrefix(ep, "unix://")
				} else if strings.HasPrefix(trimmed, "timeout:") {
					tStr := strings.TrimSpace(strings.TrimPrefix(trimmed, "timeout:"))
					m := reTimeoutSec.FindStringSubmatch(tStr)
					if len(m) > 1 {
						sec, _ := strconv.Atoi(m[1])
						currentKMS.TimeoutSeconds = sec
					}
				} else if strings.HasPrefix(trimmed, "cachesize:") {
					cStr := strings.TrimSpace(strings.TrimPrefix(trimmed, "cachesize:"))
					cs, _ := strconv.Atoi(cStr)
					currentKMS.CacheSize = cs
				}
			}
		}
	}

	if currentKMS != nil {
		config.KMSProviders = append(config.KMSProviders, *currentKMS)
	}

	if len(config.KMSProviders) > 1 {
		config.HasKMSFallback = true
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading encryption configuration: %w", err)
	}

	return config, nil
}

// ParsePKCS11URI parses an RFC 7512 PKCS#11 URI string and extracts security metadata.
func ParsePKCS11URI(rawURI string, sourceFile string, lineNum int) (*PKCS11Declaration, error) {
	if len(rawURI) > 2048 {
		return nil, fmt.Errorf("PKCS#11 URI exceeds maximum length ceiling")
	}

	decl := &PKCS11Declaration{
		CipherSuite: CipherUnknown,
		SourceFile:  sourceFile,
		LineNumber:  lineNum,
	}

	// Check for plaintext PIN
	if rePinValue.MatchString(rawURI) {
		decl.HasPlaintextPIN = true
	}

	trimmed := strings.TrimPrefix(rawURI, "pkcs11:")
	parts := strings.Split(trimmed, ";")

	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])

		switch key {
		case "slot-id":
			if s, err := strconv.Atoi(val); err == nil {
				decl.SlotID = s
			}
		case "token":
			decl.TokenLabel = val
		case "object":
			decl.KeyLabel = val
		case "id":
			decl.KeyID = val
		case "module-path", "module":
			decl.ModulePath = val
		case "pin-source":
			decl.HasPinSourceFile = true
		case "cipher", "algorithm":
			decl.CipherSuite = NormalizeCipherSuite(val)
		case "read-only":
			decl.IsReadOnlySlot = strings.ToLower(val) == "true" || val == "1"
		}
	}

	return decl, nil
}

// NormalizeCipherSuite converts algorithm strings to canonical CipherSuite constants.
func NormalizeCipherSuite(raw string) CipherSuite {
	s := strings.ToUpper(strings.TrimSpace(raw))
	switch {
	case strings.Contains(s, "GCM") && strings.Contains(s, "256"):
		return CipherAESGCM256
	case strings.Contains(s, "CHACHA"):
		return CipherChaCha20Poly1305
	case strings.Contains(s, "CBC") && strings.Contains(s, "256"):
		return CipherAESCBC256
	case strings.Contains(s, "CBC") && (strings.Contains(s, "128") || !strings.Contains(s, "256")):
		return CipherAESCBC128
	case strings.Contains(s, "3DES") || strings.Contains(s, "DES"):
		return Cipher3DES
	case strings.Contains(s, "4096"):
		return CipherRSA4096
	case strings.Contains(s, "2048"):
		return CipherRSA2048
	case strings.Contains(s, "1024"):
		return CipherRSA1024
	case strings.Contains(s, "ML-KEM") || strings.Contains(s, "KYBER"):
		return CipherPQCMLKEM
	default:
		return CipherUnknown
	}
}

// SanitizePIN masks sensitive plaintext PINs in URIs and manifests to prevent credential leaks.
func SanitizePIN(input string) string {
	return rePinValue.ReplaceAllString(input, "pin-value=[REDACTED]")
}

// ParseNixOSHSMConfig audits host NixOS modules for hardware security daemon declarations.
func ParseNixOSHSMConfig(r io.Reader, filePath string) ([]PKCS11Declaration, []NitroEnclaveDeclaration, bool, bool, error) {
	scanner := bufio.NewScanner(io.LimitReader(r, MaxManifestBytes+1))
	p11List := make([]PKCS11Declaration, 0)
	nitroList := make([]NitroEnclaveDeclaration, 0)
	p11Enabled := false
	nitroEnabled := false

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if m := reNixP11Enable.FindStringSubmatch(trimmed); len(m) > 1 {
			if m[1] == "true" {
				p11Enabled = true
			}
		}
		if m := reNixNitroEnable.FindStringSubmatch(trimmed); len(m) > 1 {
			if m[1] == "true" {
				nitroEnabled = true
			}
		}

		// Detect embedded PKCS#11 URIs
		if matches := rePKCS11URI.FindAllString(line, -1); len(matches) > 0 {
			for _, uri := range matches {
				decl, err := ParsePKCS11URI(uri, filePath, lineNum)
				if err == nil {
					p11List = append(p11List, *decl)
				}
			}
		}

		// Detect Nitro Enclave parameters
		if strings.Contains(trimmed, "nitro-enclaves") || strings.Contains(trimmed, "vsock") {
			if strings.Contains(trimmed, "vsock_cid") || strings.Contains(trimmed, "cid") {
				nitroList = append(nitroList, NitroEnclaveDeclaration{
					SourceFile: filePath,
					LineNumber: lineNum,
				})
			}
		}
	}

	return p11List, nitroList, p11Enabled, nitroEnabled, scanner.Err()
}

// ReadFileSafely reads a file with strict byte size constraints.
func ReadFileSafely(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if stat.Size() > maxBytes {
		return nil, fmt.Errorf("file %s size %d exceeds maximum limit of %d bytes", path, stat.Size(), maxBytes)
	}

	return io.ReadAll(io.LimitReader(f, maxBytes+1))
}
