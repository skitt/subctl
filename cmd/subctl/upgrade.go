//go:build !deploy

/*
SPDX-License-Identifier: Apache-2.0

Copyright Contributors to the Submariner project.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package subctl

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/coreos/go-semver/semver"
	"github.com/spf13/cobra"
	"github.com/submariner-io/admiral/pkg/reporter"
	"github.com/submariner-io/subctl/internal/cli"
	"github.com/submariner-io/subctl/internal/constants"
	"github.com/submariner-io/subctl/internal/exit"
	"github.com/submariner-io/subctl/internal/restconfig"
	"github.com/submariner-io/subctl/pkg/cluster"
	"github.com/submariner-io/subctl/pkg/deploy"
	"github.com/submariner-io/subctl/pkg/version"
	"github.com/submariner-io/submariner-operator/api/v1alpha1"
)

var (
	to                        string
	upgradeRestConfigProducer = restconfig.NewProducer()
)

// upgradeCmd represents the upgrade command.
var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Upgrades Submariner",
	Run:   upgrade,
}

func init() {
	upgradeCmd.Flags().StringVar(&to, "to", "", "the version of Submariner to upgrade to")
	upgradeRestConfigProducer.SetupFlags(upgradeCmd.Flags())
	rootCmd.AddCommand(upgradeCmd)
}

func upgrade(_ *cobra.Command, _ []string) {
	status := cli.NewReporter()

	// Step 1: upgrade subctl to match the requested version
	command, err := upgradeSubctl(status)
	exit.OnError(err)

	if command != nil {
		// Step 2a: subctl was upgraded, so run it instead of continuing
		cmd := exec.Cmd{
			Path:   *command,
			Args:   os.Args[1:],
			Stdin:  os.Stdin,
			Stdout: os.Stdout,
			Stderr: os.Stderr,
		}
		// exit.OnError outputs the version of subctl, which ends up being confusing here
		if err := cmd.Run(); err != nil {
			os.Exit(1)
		}
	} else {
		// Step 2b: this subctl is already the requested version, run it
		exit.OnError(upgradeRestConfigProducer.RunOnAllContexts(upgradeSubmariner, status))
	}
}

// upgradeSubctl upgrades the local copy of subctl, if necessary.
// Returns the path to the upgraded subctl if subctl was upgraded, nil if it wasn't.
func upgradeSubctl(status reporter.Interface) (*string, error) {
	if to == version.Version {
		// Already running the right version
		return nil, nil //nolint:nilnil // A nil command means subctl shouldn't be restarted.
	}

	// Default to downloading the latest version
	targetVersionString := "latest"

	if to != "" {
		if len(to) > 1 && to[0:1] == "v" {
			to = to[1:]
		}

		toVersion, err := semver.NewVersion(to)
		if toVersion == nil {
			return nil, status.Error(err, "Invalid target version")
		}

		// semver needs a dotted triplet, which is at least five characters;
		// on development or unknown versions, assume we need to upgrade
		if len(version.Version) >= 5 && version.Version[0:5] != "devel" {
			currentVersion, err := semver.NewVersion(version.Version)
			if currentVersion == nil {
				return nil, status.Error(err, "Error parsing current subctl version")
			}

			if toVersion.LessThan(*currentVersion) || toVersion.Equal(*currentVersion) {
				return nil, nil //nolint:nilnil // A nil command means subctl shouldn't be restarted.
			}
		}

		targetVersionString = "v" + toVersion.String()
	}

	status.Start(fmt.Sprintf("Upgrading subctl from %s to %s, replacing %s", version.Version, targetVersionString, os.Args[0]))
	defer status.End()

	url := "https://get.submariner.io"

	absolutePath, err := filepath.Abs(os.Args[0])
	if err != nil {
		return nil, status.Error(err, "Error determining the installation path")
	}

	_, err = exec.Command( //nolint:gosec // The user-controlled variables are sanitised above
		"sh", "-c", "curl "+url+" | VERSION="+targetVersionString+" DESTDIR="+filepath.Dir(absolutePath)+" bash").CombinedOutput()
	if err != nil {
		return nil, status.Error(err, "Error upgrading subctl")
	}

	status.Success("Upgraded and installed subctl version: %s", to)

	return &absolutePath, nil
}

func upgradeSubmariner(clusterInfo *cluster.Info, _ string, status reporter.Interface) error {
	ctx := context.TODO()

	status.Start("Starting upgrade process")
	defer status.End()

	brokerObj, found, err := getBroker(clusterInfo.RestConfig, constants.DefaultBrokerNamespace)
	if err != nil {
		return err
	}

	if found {
		// Role updates are part of Broker redeploy
		err = upgradeBroker(ctx, clusterInfo, status, brokerObj.Namespace, brokerObj.Spec)
		if err != nil {
			return status.Error(err, "Error upgrading Broker")
		}
	}

	var repository string
	var debug bool
	var imageOverride map[string]string

	if !found {
		if clusterInfo.Submariner != nil {
			repository = clusterInfo.Submariner.Spec.Repository
			imageOverride = clusterInfo.Submariner.Spec.ImageOverrides
			debug = clusterInfo.Submariner.Spec.Debug
		} else if clusterInfo.ServiceDiscovery != nil {
			repository = clusterInfo.ServiceDiscovery.Spec.Repository
			imageOverride = clusterInfo.ServiceDiscovery.Spec.ImageOverrides
			debug = clusterInfo.ServiceDiscovery.Spec.Debug
		}

		// Upgrade Operator if deployed
		if err := upgradeOperator(ctx, clusterInfo, repository, debug, imageOverride, status); err != nil {
			return status.Error(err, "Error upgrading Operator")
		}

		// Upgrade Submariner
		if clusterInfo.Submariner != nil {
			status.Start("Found Submariner components. Upgrading it to %s", to)

			clusterInfo.Submariner.Spec.Version = to

			err := deploy.SubmarinerFromSpec(ctx, clusterInfo.ClientProducer.ForGeneral(), &clusterInfo.Submariner.Spec)
			if err != nil {
				return status.Error(err, "Error upgrading Submariner")
			}

			status.Success("Submariner successfully upgraded")
		}

		// Upgrade Service discovery
		if clusterInfo.ServiceDiscovery != nil {
			status.Start("Found Service Discovery components. Upgrading it to %s", to)

			clusterInfo.ServiceDiscovery.Spec.Version = to

			err := deploy.ServiceDiscoveryFromSpec(ctx, clusterInfo.ClientProducer.ForGeneral(), &clusterInfo.ServiceDiscovery.Spec)
			if err != nil {
				return status.Error(err, "Error upgrading Service Discovery")
			}

			status.Success("Service discovery successfully upgraded.")
		}
	}

	return nil
}

func upgradeBroker(ctx context.Context, clusterInfo *cluster.Info, status reporter.Interface, namespace string,
	brokerSpec v1alpha1.BrokerSpec,
) error {
	status.Start("Found Broker installed. Upgrading it to %s", to)
	options := &deploy.BrokerOptions{
		ImageVersion:    to,
		BrokerNamespace: namespace,
		BrokerSpec:      brokerSpec,
	}

	if err := deploy.Deploy(ctx, options, status, clusterInfo.ClientProducer); err != nil {
		return err //nolint:wrapcheck // No need to wrap here
	}

	status.Success("Broker successfully upgraded.")

	return nil
}

func upgradeOperator(ctx context.Context, clusterInfo *cluster.Info, repository string, debug bool, imageOverride map[string]string,
	status reporter.Interface,
) error {
	status.Start("Checking if Operator is deployed")
	defer status.End()

	operatorFound, err := deploy.IsOperator(ctx, clusterInfo.ClientProducer.ForKubernetes())
	if err != nil {
		return status.Error(err, "Error retrieving Operator deployment")
	}

	if operatorFound {
		status.Success("Operator deployed. Upgrading it")

		err = deploy.Operator(
			ctx, status, repository, to, imageOverride,
			clusterInfo.ClientProducer, debug)
		if err != nil {
			return err //nolint:wrapcheck // No need to wrap here
		}

		status.Success("Operator successfully upgraded")
	}

	return nil
}
