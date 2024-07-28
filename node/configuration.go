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
package node

import (
	"context"
	"embed"
	"fmt"

	"github.com/mikefero/kheper/internal/monitoring"
	"gopkg.in/yaml.v3"
)

var (
	//go:embed basic_info.yml
	basicInfoConfigFile embed.FS
	basicInfoPlugins    map[string][]string
)

type basicInfo struct {
	Version string   `yaml:"version"`
	Plugins []string `yaml:"plugins"`
}

type basicInfoConfig struct {
	BasicInfo []basicInfo `yaml:"basic_info"`
}

// GetStandardBasicInfo returns the configuration information to be sent to the
// control plane. If the version is not found, a default configuration is
// returned.
func GetStandardBasicInfo(ctx context.Context, version string) map[string]interface{} {
	_, span := monitoring.Tracer.Start(ctx, "GetStandardBasicInfo")
	defer span.End()

	// Get the plugins for the version
	var versionPlugins []string
	var ok bool
	// Check if the version is already in the map
	if versionPlugins, ok = basicInfoPlugins[version]; !ok {
		if versionPlugins, ok = basicInfoPlugins["default"]; !ok {
			panic(fmt.Errorf("unable to find configuration for version %s", version))
		}
	}

	// Parse the node version plugins and generate the basic info message
	plugins := []map[string]interface{}{}
	for _, plugin := range versionPlugins {
		plugins = append(plugins, map[string]interface{}{
			"name":    plugin,
			"version": version,
		})
	}
	return map[string]interface{}{
		"type": "basic_info",
		"labels": map[string]interface{}{
			"kheper": "true",
		},
		"plugins": plugins,
	}
}

func init() {
	// Load the node information file
	data, err := basicInfoConfigFile.ReadFile("basic_info.yml")
	if err != nil {
		panic(fmt.Errorf("error reading node basic info configuration file: %w", err))
	}

	// Parse the node information YAML file
	var basicInfoConfig basicInfoConfig
	err = yaml.Unmarshal(data, &basicInfoConfig)
	if err != nil {
		panic(fmt.Errorf("error parsing node basic info configuration file: %w", err))
	}

	// Parse the node configuration and prepare it for use
	basicInfoPlugins = make(map[string][]string)
	for _, basicInfo := range basicInfoConfig.BasicInfo {
		versionPlugins := []string{}
		versionPlugins = append(versionPlugins, basicInfo.Plugins...)
		basicInfoPlugins[basicInfo.Version] = versionPlugins
	}
}
