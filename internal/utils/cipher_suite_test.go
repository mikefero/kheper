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
package utils_test

import (
	"crypto/tls"
	"fmt"
	"testing"

	"github.com/mikefero/kheper/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestCipherSuite(t *testing.T) {
	t.Run("verify cipher suite is parsed correctly", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			cipherSuite string
			expected    uint16
			err         error
		}{
			{"ECDHE-ECDSA-AES128-GCM-SHA256", tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, nil},
			{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, nil},
			{"ECDHE-RSA-AES128-GCM-SHA256", tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, nil},
			{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, nil},
			{"ECDHE-ECDSA-AES256-GCM-SHA384", tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, nil},
			{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, nil},
			{"ECDHE-RSA-AES256-GCM-SHA384", tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, nil},
			{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, nil},
			{"ECDHE-ECDSA-CHACHA20-POLY1305", tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, nil},
			{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, nil},
			{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, nil},
			{"ECDHE-RSA-CHACHA20-POLY1305", tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, nil},
			{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, nil},
			{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, nil},
			{"ECDHE-ECDSA-AES128-SHA256", tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, nil},
			{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, nil},
			{"ECDHE-RSA-AES128-SHA256", tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, nil},
			{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, nil},
			{"ECDHE-ECDSA-AES128-SHA", tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, nil},
			{"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, nil},
			{"ECDHE-RSA-AES128-SHA", tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, nil},
			{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, nil},
			{"ECDHE-ECDSA-AES256-SHA", tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, nil},
			{"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, nil},
			{"ECDHE-RSA-AES256-SHA", tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, nil},
			{"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, nil},
			{"AES128-GCM-SHA256", tls.TLS_RSA_WITH_AES_128_GCM_SHA256, nil},
			{"TLS_RSA_WITH_AES_128_GCM_SHA256", tls.TLS_RSA_WITH_AES_128_GCM_SHA256, nil},
			{"AES256-GCM-SHA384", tls.TLS_RSA_WITH_AES_256_GCM_SHA384, nil},
			{"TLS_RSA_WITH_AES_256_GCM_SHA384", tls.TLS_RSA_WITH_AES_256_GCM_SHA384, nil},
			{"AES128-SHA256", tls.TLS_RSA_WITH_AES_128_CBC_SHA256, nil},
			{"TLS_RSA_WITH_AES_128_CBC_SHA256", tls.TLS_RSA_WITH_AES_128_CBC_SHA256, nil},
			{"AES128-SHA", tls.TLS_RSA_WITH_AES_128_CBC_SHA, nil},
			{"TLS_RSA_WITH_AES_128_CBC_SHA", tls.TLS_RSA_WITH_AES_128_CBC_SHA, nil},
			{"AES256-SHA", tls.TLS_RSA_WITH_AES_256_CBC_SHA, nil},
			{"TLS_RSA_WITH_AES_256_CBC_SHA", tls.TLS_RSA_WITH_AES_256_CBC_SHA, nil},
			{"AES256-SHA256", 0, fmt.Errorf("unsupported Kong Gateway cipher suite in Go: AES256-SHA256")},
			{"DES-CBC3-SHA", 0, fmt.Errorf("unsupported Kong Gateway cipher suite in Go: DES-CBC3-SHA")},
			{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0, fmt.Errorf("unsupported Kong Gateway cipher suite in Go: TLS_RSA_WITH_3DES_EDE_CBC_SHA")},
			{"ECDHE-ECDSA-AES256-SHA384", 0, fmt.Errorf("unsupported Kong Gateway cipher suite in Go: ECDHE-ECDSA-AES256-SHA384")},
			{"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", 0, fmt.Errorf("unsupported Kong Gateway cipher suite in Go: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384")},
			{"ECDHE-RSA-AES256-SHA384", 0, fmt.Errorf("unsupported Kong Gateway cipher suite in Go: ECDHE-RSA-AES256-SHA384")},
			{"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", 0, fmt.Errorf("unsupported Kong Gateway cipher suite in Go: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384")},
			{"DHE-RSA-AES128-GCM-SHA256", 0, fmt.Errorf("unsupported Kong Gateway cipher suite in Go: DHE-RSA-AES128-GCM-SHA256")},
			{"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0, fmt.Errorf("unsupported Kong Gateway cipher suite in Go: TLS_DHE_RSA_WITH_AES_128_GCM_SHA256")},
			{"DHE-RSA-AES256-GCM-SHA384", 0, fmt.Errorf("unsupported Kong Gateway cipher suite in Go: DHE-RSA-AES256-GCM-SHA384")},
			{"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 0, fmt.Errorf("unsupported Kong Gateway cipher suite in Go: TLS_DHE_RSA_WITH_AES_256_GCM_SHA384")},
			{"DHE-RSA-CHACHA20-POLY1305", 0, fmt.Errorf("unsupported Kong Gateway cipher suite in Go: DHE-RSA-CHACHA20-POLY1305")},
			{"TLS_DHE_RSA_WITH_CHACHA20_POLY1305", 0, fmt.Errorf("unsupported Kong Gateway cipher suite in Go: TLS_DHE_RSA_WITH_CHACHA20_POLY1305")},
			{"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0, fmt.Errorf("unsupported Kong Gateway cipher suite in Go: TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256")},
			{"DHE-RSA-AES128-SHA256", 0, fmt.Errorf("unsupported Kong Gateway cipher suite in Go: DHE-RSA-AES128-SHA256")},
			{"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", 0, fmt.Errorf("unsupported Kong Gateway cipher suite in Go: TLS_DHE_RSA_WITH_AES_128_CBC_SHA256")},
			{"DHE-RSA-AES256-SHA256", 0, fmt.Errorf("unsupported Kong Gateway cipher suite in Go: DHE-RSA-AES256-SHA256")},
			{"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", 0, fmt.Errorf("unsupported Kong Gateway cipher suite in Go: TLS_DHE_RSA_WITH_AES_256_CBC_SHA256")},
			{"invalid", 0, fmt.Errorf("unsupported cipher suite: invalid")},
		}

		for _, tt := range tests {
			tt := tt // create a new instance of tt for each iteration (loopclosure)

			t.Run(tt.cipherSuite, func(t *testing.T) {
				t.Parallel()

				c, err := utils.CipherSuite(tt.cipherSuite)
				require.Equal(t, tt.expected, c)
				require.Equal(t, tt.err, err)
			})
		}
	})

	t.Run("verify cipher suite is supported by TLS version", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			cipherSuite uint16
			tlsVersion  uint16
			expected    bool
		}{
			// TLS v1.2 only cipher suites
			{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.VersionTLS12, true},
			{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.VersionTLS12, true},
			{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.VersionTLS12, true},
			{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.VersionTLS12, true},
			{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.VersionTLS12, true},
			{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, tls.VersionTLS12, true},
			{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, tls.VersionTLS12, true},
			{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, tls.VersionTLS12, true},
			{tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.VersionTLS12, true},
			{tls.TLS_RSA_WITH_AES_256_GCM_SHA384, tls.VersionTLS12, true},
			{tls.TLS_RSA_WITH_AES_128_CBC_SHA256, tls.VersionTLS12, true},

			{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.VersionTLS11, false},
			{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.VersionTLS11, false},
			{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.VersionTLS11, false},
			{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.VersionTLS11, false},
			{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.VersionTLS11, false},
			{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, tls.VersionTLS11, false},
			{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, tls.VersionTLS11, false},
			{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, tls.VersionTLS11, false},
			{tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.VersionTLS11, false},
			{tls.TLS_RSA_WITH_AES_256_GCM_SHA384, tls.VersionTLS11, false},
			{tls.TLS_RSA_WITH_AES_128_CBC_SHA256, tls.VersionTLS11, false},

			{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.VersionTLS10, false},
			{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.VersionTLS10, false},
			{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.VersionTLS10, false},
			{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.VersionTLS10, false},
			{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.VersionTLS10, false},
			{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, tls.VersionTLS10, false},
			{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, tls.VersionTLS10, false},
			{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, tls.VersionTLS10, false},
			{tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.VersionTLS10, false},
			{tls.TLS_RSA_WITH_AES_256_GCM_SHA384, tls.VersionTLS10, false},
			{tls.TLS_RSA_WITH_AES_128_CBC_SHA256, tls.VersionTLS10, false},

			// TLS v1.0 - v1.2 cipher suites
			{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.VersionTLS10, true},
			{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.VersionTLS10, true},
			{tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, tls.VersionTLS10, true},
			{tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, tls.VersionTLS10, true},
			{tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.VersionTLS10, true},
			{tls.TLS_RSA_WITH_AES_256_CBC_SHA, tls.VersionTLS10, true},
			{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.VersionTLS10, true},

			{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.VersionTLS11, true},
			{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.VersionTLS11, true},
			{tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, tls.VersionTLS11, true},
			{tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, tls.VersionTLS11, true},
			{tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.VersionTLS11, true},
			{tls.TLS_RSA_WITH_AES_256_CBC_SHA, tls.VersionTLS11, true},
			{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.VersionTLS11, true},

			{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.VersionTLS12, true},
			{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.VersionTLS12, true},
			{tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, tls.VersionTLS12, true},
			{tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, tls.VersionTLS12, true},
			{tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.VersionTLS12, true},
			{tls.TLS_RSA_WITH_AES_256_CBC_SHA, tls.VersionTLS12, true},
			{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.VersionTLS12, true},

			// Invalid TLS cipher
			{0, tls.VersionTLS12, false},
		}

		for _, tt := range tests {
			tt := tt // create a new instance of tt for each iteration (loopclosure)

			t.Run(tls.CipherSuiteName(tt.cipherSuite), func(t *testing.T) {
				t.Parallel()

				require.Equal(t, tt.expected, utils.ValidateCipherSuite(tt.cipherSuite, tt.tlsVersion))
			})
		}
	})

	t.Run("verify TLS version is supported", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			tlsVersion string
			expected   uint16
			err        error
		}{
			{"TLSv1", tls.VersionTLS10, nil},
			{"TLSv1.0", tls.VersionTLS10, nil},
			{"TLSv1.1", tls.VersionTLS11, nil},
			{"TLSv1.2", tls.VersionTLS12, nil},
			{"TLSv1.3", tls.VersionTLS13, nil},
			{"", tls.VersionTLS13, nil},
			{"TLSv1.4", 0, fmt.Errorf("unsupported TLS version: TLSv1.4")},
			{"invalid", 0, fmt.Errorf("unsupported TLS version: invalid")},
		}
		for _, tt := range tests {
			tt := tt // create a new instance of tt for each iteration (loopclosure)

			t.Run(tt.tlsVersion, func(t *testing.T) {
				t.Parallel()

				v, err := utils.TLSVersion(tt.tlsVersion)
				require.Equal(t, tt.expected, v)
				require.Equal(t, tt.err, err)
			})
		}
	})
}
