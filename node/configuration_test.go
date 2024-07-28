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
package node_test

import (
	"context"
	"testing"

	"github.com/mikefero/kheper/node"
	"github.com/stretchr/testify/require"
)

func TestConfiguration(t *testing.T) {
	pluginsDefault := []string{
		"acl",
		"acme",
		"ai-prompt-decorator",
		"ai-prompt-guard",
		"ai-prompt-template",
		"ai-proxy",
		"ai-request-transformer",
		"ai-response-transformer",
		"aws-lambda",
		"azure-functions",
		"basic-auth",
		"bot-detection",
		"correlation-id",
		"cors",
		"datadog",
		"file-log",
		"grpc-gateway",
		"grpc-web",
		"hmac-auth",
		"http-log",
		"ip-restriction",
		"jwt",
		"key-auth",
		"ldap-auth",
		"loggly",
		"oauth2",
		"opentelemetry",
		"post-function",
		"pre-function",
		"prometheus",
		"proxy-cache",
		"rate-limiting",
		"request-size-limiting",
		"request-termination",
		"request-transformer",
		"response-ratelimiting",
		"response-transformer",
		"session",
		"statsd",
		"syslog",
		"tcp-log",
		"udp-log",
		"zipkin",
	}

	plugins3712 := []string{
		"acl",
		"acme",
		"ai-azure-content-safety",
		"ai-prompt-decorator",
		"ai-prompt-guard",
		"ai-prompt-template",
		"ai-proxy",
		"ai-rate-limiting-advanced",
		"ai-request-transformer",
		"ai-response-transformer",
		"application-registration",
		"aws-lambda",
		"azure-functions",
		"basic-auth",
		"bot-detection",
		"canary",
		"correlation-id",
		"cors",
		"datadog",
		"degraphql",
		"exit-transformer",
		"file-log",
		"forward-proxy",
		"graphql-proxy-cache-advanced",
		"graphql-rate-limiting-advanced",
		"grpc-gateway",
		"grpc-web",
		"hmac-auth",
		"http-log",
		"ip-restriction",
		"jq",
		"jwe-decrypt",
		"jwt",
		"jwt-signer",
		"kafka-log",
		"kafka-upstream",
		"key-auth",
		"key-auth-enc",
		"konnect-application-auth",
		"ldap-auth",
		"ldap-auth-advanced",
		"loggly",
		"mocking",
		"mtls-auth",
		"oas-validation",
		"oauth2",
		"oauth2-introspection",
		"opa",
		"openid-connect",
		"opentelemetry",
		"post-function",
		"pre-function",
		"prometheus",
		"proxy-cache",
		"proxy-cache-advanced",
		"rate-limiting",
		"rate-limiting-advanced",
		"request-size-limiting",
		"request-termination",
		"request-transformer",
		"request-transformer-advanced",
		"request-validator",
		"response-ratelimiting",
		"response-transformer",
		"response-transformer-advanced",
		"route-by-header",
		"route-transformer-advanced",
		"saml",
		"session",
		"statsd",
		"statsd-advanced",
		"syslog",
		"tcp-log",
		"tls-handshake-modifier",
		"tls-metadata-headers",
		"udp-log",
		"upstream-timeout",
		"vault-auth",
		"websocket-size-limit",
		"websocket-validator",
		"xml-threat-protection",
		"zipkin",
	}

	t.Run("verify configuration is parsed correctly for a known version", func(t *testing.T) {
		plugins := []map[string]interface{}{}
		for _, plugin := range plugins3712 {
			plugins = append(plugins, map[string]interface{}{
				"name":    plugin,
				"version": "3.7.1.2",
			})
		}
		expected := map[string]interface{}{
			"type": "basic_info",
			"labels": map[string]interface{}{
				"kheper": "true",
			},
			"plugins": plugins,
		}

		require.Equal(t, expected, node.GetStandardBasicInfo(context.TODO(), "3.7.1.2"))
	})

	t.Run("verify configuration is parsed correctly for default or unknown version", func(t *testing.T) {
		plugins := []map[string]interface{}{}
		for _, plugin := range pluginsDefault {
			plugins = append(plugins, map[string]interface{}{
				"name":    plugin,
				"version": "0.0.1",
			})
		}
		expected := map[string]interface{}{
			"type": "basic_info",
			"labels": map[string]interface{}{
				"kheper": "true",
			},
			"plugins": plugins,
		}

		require.Equal(t, expected, node.GetStandardBasicInfo(context.TODO(), "0.0.1"))
	})
}
