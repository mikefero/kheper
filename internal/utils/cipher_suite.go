// Copyright © 2024 Michael Fero
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package utils

import (
	"crypto/tls"
	"fmt"
	"strings"
)

// cipherSuiteToTLSVersion maps a cipher suite to the minimum and maximum TLS
// version supported by the cipher suite.
//
//nolint:lll
var cipherSuiteToTLSVersion = map[uint16]struct {
	MinVersion uint16
	MaxVersion uint16
}{
	// TLS v1.2 only cipher suites
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       {tls.VersionTLS12, tls.VersionTLS12},
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       {tls.VersionTLS12, tls.VersionTLS12},
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: {tls.VersionTLS12, tls.VersionTLS12},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:       {tls.VersionTLS12, tls.VersionTLS12},
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         {tls.VersionTLS12, tls.VersionTLS12},
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         {tls.VersionTLS12, tls.VersionTLS12},
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   {tls.VersionTLS12, tls.VersionTLS12},
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:         {tls.VersionTLS12, tls.VersionTLS12}, // This cipher is deemed insecure by crypto/tls
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:               {tls.VersionTLS12, tls.VersionTLS12}, // This cipher is deemed insecure by crypto/tls
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:               {tls.VersionTLS12, tls.VersionTLS12}, // This cipher is deemed insecure by crypto/tls
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:               {tls.VersionTLS12, tls.VersionTLS12}, // This cipher is deemed insecure by crypto/tls

	// TLSv 1.0 - v1.2 cipher suites
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:   {tls.VersionTLS10, tls.VersionTLS12},
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:   {tls.VersionTLS10, tls.VersionTLS12},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: {tls.VersionTLS10, tls.VersionTLS12},
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: {tls.VersionTLS10, tls.VersionTLS12},
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:         {tls.VersionTLS10, tls.VersionTLS12}, // This cipher is deemed insecure by crypto/tls
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:         {tls.VersionTLS10, tls.VersionTLS12}, // This cipher is deemed insecure by crypto/tls
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:        {tls.VersionTLS10, tls.VersionTLS12}, // This cipher is deemed insecure by crypto/tls
}

// CipherSuite returns the TLS cipher suite enumeration for the given string.
// The enumeration is either OpenSSL (e.g. Kong Gateway) or TLS (e.g. Go).
//
// see: https://github.com/Kong/kong/blob/master/kong/conf_loader/constants.lua#L14
// for Kong Gateway OpenSSL cipher suites.
//
// see: https://www.openssl.org/docs/man1.1.1/man1/ciphers.html for mapping.
func CipherSuite(cipherSuite string) (uint16, error) {
	switch cipherSuite {
	case "ECDHE-RSA-AES128-GCM-SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":
		return tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, nil
	case "ECDHE-RSA-AES256-GCM-SHA384",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":
		return tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, nil
	case "ECDHE-RSA-CHACHA20-POLY1305",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":
		return tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, nil
	case "ECDHE-ECDSA-AES128-GCM-SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":
		return tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, nil
	case "ECDHE-ECDSA-AES256-GCM-SHA384",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":
		return tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, nil
	case "ECDHE-ECDSA-CHACHA20-POLY1305",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256":
		return tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, nil
	case "ECDHE-ECDSA-AES128-SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":
		return tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, nil
	case "ECDHE-RSA-AES128-SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":
		return tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, nil
	case "ECDHE-RSA-AES128-SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":
		return tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, nil
	case "ECDHE-RSA-AES256-SHA",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":
		return tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, nil
	case "ECDHE-ECDSA-AES128-SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":
		return tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, nil
	case "ECDHE-ECDSA-AES256-SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":
		return tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, nil
	case "AES128-GCM-SHA256",
		"TLS_RSA_WITH_AES_128_GCM_SHA256":
		return tls.TLS_RSA_WITH_AES_128_GCM_SHA256, nil
	case "AES256-GCM-SHA384",
		"TLS_RSA_WITH_AES_256_GCM_SHA384":
		return tls.TLS_RSA_WITH_AES_256_GCM_SHA384, nil
	case "AES128-SHA256",
		"TLS_RSA_WITH_AES_128_CBC_SHA256":
		return tls.TLS_RSA_WITH_AES_128_CBC_SHA256, nil
	case "AES128-SHA",
		"TLS_RSA_WITH_AES_128_CBC_SHA":
		return tls.TLS_RSA_WITH_AES_128_CBC_SHA, nil
	case "AES256-SHA",
		"TLS_RSA_WITH_AES_256_CBC_SHA":
		return tls.TLS_RSA_WITH_AES_256_CBC_SHA, nil
	case "AES256-SHA256",
		"TLS_RSA_WITH_AES_256_CBC_SHA256",
		"DES-CBC3-SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"DHE-RSA-AES128-GCM-SHA256",
		"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		"DHE-RSA-AES256-GCM-SHA384",
		"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		"DHE-RSA-CHACHA20-POLY1305",
		"TLS_DHE_RSA_WITH_CHACHA20_POLY1305",
		"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		"DHE-RSA-AES128-SHA256",
		"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
		"DHE-RSA-AES256-SHA256",
		"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
		"ECDHE-ECDSA-AES256-SHA384",
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
		"ECDHE-RSA-AES256-SHA384",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384":
		return 0, fmt.Errorf("unsupported Kong Gateway cipher suite in Go: %s", cipherSuite)
	default:
		return 0, fmt.Errorf("unsupported cipher suite: %s", cipherSuite)
	}
}

// TLSVersion returns the TLS version enumeration for the given string.
func TLSVersion(tlsVersion string) (uint16, error) {
	switch strings.TrimSpace(tlsVersion) {
	case "TLSv1", "TLSv1.0":
		return tls.VersionTLS10, nil
	case "TLSv1.1":
		return tls.VersionTLS11, nil
	case "TLSv1.2":
		return tls.VersionTLS12, nil
	case "TLSv1.3", "":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version: %s", tlsVersion)
	}
}

// IsCipherSuiteValid returns true if the given cipher suite is supported by the
// given TLS version.
func IsCipherSuiteValid(cipherSuite uint16, tlsVersion uint16) bool {
	versions, ok := cipherSuiteToTLSVersion[cipherSuite]
	if !ok {
		return false
	}
	return tlsVersion >= versions.MinVersion && tlsVersion <= versions.MaxVersion
}
