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
	"strings"
	"testing"

	"github.com/mikefero/kheper/internal/utils"
	"github.com/stretchr/testify/assert"
)

func TestValidatePort(t *testing.T) {
	t.Parallel()

	t.Run("verify valid minimum port", func(t *testing.T) {
		t.Parallel()
		err := utils.ValidatePort(1)
		assert.NoError(t, err)
	})

	t.Run("verify valid maximum port", func(t *testing.T) {
		t.Parallel()
		err := utils.ValidatePort(65535)
		assert.NoError(t, err)
	})

	t.Run("verify valid port in range", func(t *testing.T) {
		t.Parallel()
		err := utils.ValidatePort(8080)
		assert.NoError(t, err)
	})

	t.Run("verify invalid port below minimum", func(t *testing.T) {
		t.Parallel()
		err := utils.ValidatePort(0)
		assert.EqualError(t, err, "port must be between 1 and 65535")
	})

	t.Run("verify invalid port above maximum", func(t *testing.T) {
		t.Parallel()
		err := utils.ValidatePort(65536)
		assert.EqualError(t, err, "port must be between 1 and 65535")
	})
}

func TestValidateHostname(t *testing.T) {
	t.Parallel()

	t.Run("verify valid hostname", func(t *testing.T) {
		t.Parallel()

		hostnames := []string{
			"example.com",
			"example.org",
			"example.tech",
			"example.net",
			"example.io",
			"localhost",
			"127.0.0.1",
		}
		for _, hostname := range hostnames {
			err := utils.ValidateHostname(hostname)
			assert.NoError(t, err)
		}
	})

	t.Run("verify valid hostname with subdomains", func(t *testing.T) {
		t.Parallel()

		hostnames := []string{
			"sub.example.com",
			"blog.example.org",
			"run.example.tech",
			"execute.example.net",
			"read.example.io",
		}
		for _, hostname := range hostnames {
			err := utils.ValidateHostname(hostname)
			assert.NoError(t, err)
		}
	})

	t.Run("verify valid hostname with numbers", func(t *testing.T) {
		t.Parallel()

		hostnames := []string{
			"example123.com",
			"123example.org",
			"exam123ple.tech",
		}
		for _, hostname := range hostnames {
			err := utils.ValidateHostname(hostname)
			assert.NoError(t, err)
		}
	})

	t.Run("verify valid single character hostname", func(t *testing.T) {
		t.Parallel()

		hostnames := []string{
			"a.com",
			"b.org",
			"c.tech",
			"d.net",
			"e.io",
			"f.localhost",
		}
		for _, hostname := range hostnames {
			err := utils.ValidateHostname(hostname)
			assert.NoError(t, err)
		}
	})

	t.Run("verify valid hostname with hyphens", func(t *testing.T) {
		t.Parallel()

		hostnames := []string{
			"ex-ample.com",
			"ex-am-ple.org",
			"ex-am-pl-e.tech",
		}
		for _, hostname := range hostnames {
			err := utils.ValidateHostname(hostname)
			assert.NoError(t, err)
		}
	})

	t.Run("verify invalid hostname that exceeds 255 characters", func(t *testing.T) {
		t.Parallel()
		err := utils.ValidateHostname(strings.Repeat("a", 256))
		assert.EqualError(t, err, "hostname exceeds 255 characters")
	})

	t.Run("verify invalid characters for RFC 1123 hostname format", func(t *testing.T) {
		t.Parallel()

		hostnames := []string{
			"invalid_hostname",
			"example!.com",
			"example .com",
		}
		for _, hostname := range hostnames {
			err := utils.ValidateHostname(hostname)
			assert.EqualError(t, err, "invalid RFC 1123 hostname format")
		}
	})

	t.Run("verify invalid hostname that contains a label exceeding 63 characters", func(t *testing.T) {
		t.Parallel()

		hostnames := []string{
			strings.Repeat("a", 64) + ".com",
			strings.Repeat("a", 63) + "." + strings.Repeat("a", 64) + ".com",
			strings.Repeat("a", 63) + ".com." + strings.Repeat("a", 64),
		}
		for _, hostname := range hostnames {
			t.Run(hostname, func(t *testing.T) {
				err := utils.ValidateHostname(hostname)
				assert.EqualError(t, err, "label exceeds 63 characters: "+strings.Repeat("a", 64))
			})
		}
	})

	t.Run("verify invalid hostname that starts with hyphen", func(t *testing.T) {
		t.Parallel()
		err := utils.ValidateHostname("-example.com")
		assert.EqualError(t, err, "invalid RFC 1123 hostname format")
	})

	t.Run("verify invalid hostname that ends with hyphen", func(t *testing.T) {
		t.Parallel()
		err := utils.ValidateHostname("example-.com")
		assert.EqualError(t, err, "invalid RFC 1123 hostname format")
	})

	t.Run("verify invalid hostname with consecutive dots", func(t *testing.T) {
		t.Parallel()

		hostnames := []string{
			"example..com",
			"sub..example.com",
		}
		for _, hostname := range hostnames {
			t.Run(hostname, func(t *testing.T) {
				err := utils.ValidateHostname(hostname)
				assert.EqualError(t, err, "invalid RFC 1123 hostname format")
			})
		}
	})

	t.Run("verify invalid hostname", func(t *testing.T) {
		t.Parallel()

		hostnames := []string{
			"",
			"   ",
			"\t",
			"\n",
			".",
		}
		for _, hostname := range hostnames {
			t.Run(hostname, func(t *testing.T) {
				err := utils.ValidateHostname(hostname)
				assert.EqualError(t, err, "invalid RFC 1123 hostname format")
			})
		}
	})
}
