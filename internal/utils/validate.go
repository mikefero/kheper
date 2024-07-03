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
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const rfc1123Format = `^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$`

var hostnameRegex = regexp.MustCompile(rfc1123Format)

// ValidatePort validates a port number is in the range 1-65535.
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

// ValidateHostname validates a hostname is valid according to RFC 1123.
func ValidateHostname(hostname string) error {
	if len(hostname) > 255 {
		return errors.New("hostname exceeds 255 characters")
	}

	// Check each label length (must be 63 characters or less)
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if len(label) > 63 {
			return fmt.Errorf("label exceeds 63 characters: %s", label)
		}
	}

	// Regular expression for validating a hostname according to RFC 1123
	if !hostnameRegex.MatchString(hostname) {
		return errors.New("invalid RFC 1123 hostname format")
	}

	return nil
}
