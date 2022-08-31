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
	"fmt"

	"github.com/spf13/cobra"
	"github.com/submariner-io/admiral/pkg/reporter"
	"github.com/submariner-io/subctl/cmd/subctl/execute"
	"github.com/submariner-io/subctl/internal/cli"
	"github.com/submariner-io/subctl/internal/constants"
	"github.com/submariner-io/subctl/internal/exit"
	"github.com/submariner-io/subctl/internal/restconfig"
	"github.com/submariner-io/subctl/pkg/cluster"
	"github.com/submariner-io/subctl/pkg/diagnose"
)

var (
	diagnoseFirewallOptions diagnose.FirewallOptions

	diagnoseKubeProxyOptions struct {
		podNamespace string
	}

	diagnoseRestConfigProducer = restconfig.NewProducer()

	diagnoseFirewallTunnelRestConfigProducer = restconfig.NewProducer().
							WithDefaultNamespace(constants.OperatorNamespace).WithPrefixedContext("remote")
	diagnoseFirewallNatDiscoveryRestConfigProducer = restconfig.NewProducer().
							WithDefaultNamespace(constants.OperatorNamespace).WithPrefixedContext("remote")

	diagnoseCmd = &cobra.Command{
		Use:   "diagnose",
		Short: "Run diagnostic checks on the Submariner deployment and report any issues",
		Long:  "This command runs various diagnostic checks on the Submariner deployment and reports any issues",
	}

	diagnoseCNICmd = &cobra.Command{
		Use:   "cni",
		Short: "Check the CNI network plugin",
		Long:  "This command checks if the detected CNI network plugin is supported by Submariner.",
		Run: func(command *cobra.Command, args []string) {
			execute.OnMultiCluster(diagnoseRestConfigProducer, execute.IfSubmarinerInstalled(diagnose.CNIConfig))
		},
	}

	diagnoseConnectionsCmd = &cobra.Command{
		Use:   "connections",
		Short: "Check the Gateway connections",
		Long:  "This command checks that the Gateway connections to other clusters are all established",
		Run: func(command *cobra.Command, args []string) {
			execute.OnMultiCluster(diagnoseRestConfigProducer, execute.IfSubmarinerInstalled(diagnose.Connections))
		},
	}

	diagnoseDeploymentCmd = &cobra.Command{
		Use:   "deployment",
		Short: "Check the Submariner deployment",
		Long:  "This command checks that the Submariner components are properly deployed and running with no overlapping CIDRs.",
		Run: func(command *cobra.Command, args []string) {
			execute.OnMultiCluster(diagnoseRestConfigProducer, execute.IfSubmarinerInstalled(diagnose.Deployments))
		},
	}

	diagnoseVersionCmd = &cobra.Command{
		Use:   "k8s-version",
		Short: "Check the Kubernetes version",
		Long:  "This command checks if Submariner can be deployed on the Kubernetes version.",
		Run: func(command *cobra.Command, args []string) {
			execute.OnMultiCluster(diagnoseRestConfigProducer, func(info *cluster.Info, status reporter.Interface) bool {
				return diagnose.K8sVersion(info.ClientProducer.ForKubernetes(), status)
			})
		},
	}

	diagnoseKubeProxyModeCmd = &cobra.Command{
		Use:   "kube-proxy-mode",
		Short: "Check the kube-proxy mode",
		Long:  "This command checks if the kube-proxy mode is supported by Submariner.",
		Run: func(command *cobra.Command, args []string) {
			execute.OnMultiCluster(diagnoseRestConfigProducer, execute.IfSubmarinerInstalled(
				func(info *cluster.Info, status reporter.Interface) bool {
					return diagnose.KubeProxyMode(info.ClientProducer, diagnoseKubeProxyOptions.podNamespace,
						info.GetImageRepositoryInfo(), status)
				}))
		},
	}

	diagnoseFirewallCmd = &cobra.Command{
		Use:   "firewall",
		Short: "Check the firewall configuration",
		Long:  "This command checks if the firewall is configured as per Submariner pre-requisites.",
	}

	diagnoseFirewallMetricsCmd = &cobra.Command{
		Use:        "metrics",
		Short:      "Check firewall access to metrics",
		Deprecated: "Metrics check is now implicitly done as part of deployment check",
	}

	diagnoseFirewallVxLANCmd = &cobra.Command{
		Use:   "intra-cluster",
		Short: "Check firewall access for intra-cluster Submariner VxLAN traffic",
		Long:  "This command checks if the firewall configuration allows traffic over vx-submariner interface.",
		Run: func(command *cobra.Command, args []string) {
			execute.OnMultiCluster(diagnoseRestConfigProducer, execute.IfSubmarinerInstalled(
				func(info *cluster.Info, status reporter.Interface) bool {
					return diagnose.FirewallIntraVxLANConfig(info, diagnoseFirewallOptions, status)
				}))
		},
	}

	diagnoseFirewallTunnelCmd = &cobra.Command{
		Use:   "inter-cluster --context <localcontext> --remotecontext <remotecontext>",
		Short: "Check firewall access to setup tunnels between the Gateway node",
		Long:  "This command checks if the firewall configuration allows tunnels to be configured on the Gateway nodes.",
		Run: func(command *cobra.Command, args []string) {
			runLocalRemoteCommand(command, diagnoseFirewallTunnelRestConfigProducer, args, diagnose.TunnelConfigAcrossClusters)
		},
	}

	diagnoseFirewallNatDiscovery = &cobra.Command{
		Use:   "nat-discovery --context <localcontext> --remotecontext <remotecontext>",
		Short: "Check firewall access for nat-discovery to function properly",
		Long:  "This command checks if the firewall configuration allows nat-discovery between the configured Gateway nodes.",
		Run: func(command *cobra.Command, args []string) {
			runLocalRemoteCommand(command, diagnoseFirewallNatDiscoveryRestConfigProducer, args, diagnose.NatDiscoveryConfigAcrossClusters)
		},
	}

	diagnoseAllCmd = &cobra.Command{
		Use:   "all",
		Short: "Run all diagnostic checks (except those requiring two kubecontexts)",
		Long:  "This command runs all diagnostic checks (except those requiring two kubecontexts) and reports any issues",
		Run: func(command *cobra.Command, args []string) {
			execute.OnMultiCluster(diagnoseRestConfigProducer, diagnoseAll)
		},
	}
)

func init() {
	diagnoseRestConfigProducer.AddKubeConfigFlag(diagnoseCmd)
	diagnoseRestConfigProducer.AddInClusterConfigFlag(diagnoseCmd)
	rootCmd.AddCommand(diagnoseCmd)

	addDiagnoseSubCommands()
	addDiagnoseFirewallSubCommands()
}

func addDiagnoseSubCommands() {
	addDiagnosePodNamespaceFlag(diagnoseKubeProxyModeCmd, &diagnoseKubeProxyOptions.podNamespace)
	addDiagnoseFWConfigFlags(diagnoseAllCmd)
	addDiagnosePodNamespaceFlag(diagnoseAllCmd, &diagnoseFirewallOptions.PodNamespace)

	diagnoseCmd.AddCommand(diagnoseCNICmd)
	diagnoseCmd.AddCommand(diagnoseConnectionsCmd)
	diagnoseCmd.AddCommand(diagnoseDeploymentCmd)
	diagnoseCmd.AddCommand(diagnoseVersionCmd)
	diagnoseCmd.AddCommand(diagnoseKubeProxyModeCmd)
	diagnoseCmd.AddCommand(diagnoseAllCmd)
	diagnoseCmd.AddCommand(diagnoseFirewallCmd)
}

func addDiagnoseFirewallSubCommands() {
	addDiagnoseFWConfigFlags(diagnoseFirewallMetricsCmd)
	addDiagnosePodNamespaceFlag(diagnoseFirewallMetricsCmd, &diagnoseFirewallOptions.PodNamespace)
	addDiagnoseFWConfigFlags(diagnoseFirewallVxLANCmd)
	addDiagnosePodNamespaceFlag(diagnoseFirewallVxLANCmd, &diagnoseFirewallOptions.PodNamespace)
	diagnoseFirewallTunnelRestConfigProducer.SetupFlags(diagnoseFirewallTunnelCmd.Flags())
	addDiagnoseFWConfigFlags(diagnoseFirewallTunnelCmd)
	diagnoseFirewallNatDiscoveryRestConfigProducer.SetupFlags(diagnoseFirewallNatDiscovery.Flags())
	addDiagnoseFWConfigFlags(diagnoseFirewallNatDiscovery)

	diagnoseFirewallCmd.AddCommand(diagnoseFirewallMetricsCmd)
	diagnoseFirewallCmd.AddCommand(diagnoseFirewallVxLANCmd)
	diagnoseFirewallCmd.AddCommand(diagnoseFirewallTunnelCmd)
	diagnoseFirewallCmd.AddCommand(diagnoseFirewallNatDiscovery)
}

func addDiagnosePodNamespaceFlag(command *cobra.Command, value *string) {
	command.Flags().StringVar(value, "namespace", constants.OperatorNamespace, "namespace in which validation pods should be deployed")
}

func addDiagnoseFWConfigFlags(command *cobra.Command) {
	command.Flags().UintVar(&diagnoseFirewallOptions.ValidationTimeout, "validation-timeout", 90,
		"time to run in seconds while validating the firewall")
	command.Flags().BoolVar(&diagnoseFirewallOptions.VerboseOutput, "verbose", false,
		"produce verbose output while validating the firewall")
}

func diagnoseAll(clusterInfo *cluster.Info, status reporter.Interface) bool {
	success := diagnose.K8sVersion(clusterInfo.ClientProducer.ForKubernetes(), status)

	fmt.Println()

	if clusterInfo.Submariner == nil {
		status.Warning(constants.SubmarinerNotInstalled)

		return success
	}

	success = diagnose.CNIConfig(clusterInfo, status) && success

	fmt.Println()

	success = diagnose.Connections(clusterInfo, status) && success

	fmt.Println()

	success = diagnose.Deployments(clusterInfo, status) && success

	fmt.Println()

	success = diagnose.KubeProxyMode(clusterInfo.ClientProducer, diagnoseKubeProxyOptions.podNamespace,
		clusterInfo.GetImageRepositoryInfo(), status) && success

	fmt.Println()

	success = diagnose.FirewallIntraVxLANConfig(clusterInfo, diagnoseFirewallOptions, status) && success

	fmt.Println()

	success = diagnose.GlobalnetConfig(clusterInfo, status) && success

	fmt.Println()

	fmt.Printf("Skipping inter-cluster firewall check as it requires two kubeconfigs." +
		" Please run \"subctl diagnose firewall inter-cluster\" command manually.\n")

	return success
}

func runLocalRemoteCommand(command *cobra.Command, localRemoteRestConfigProducer *restconfig.Producer, args []string,
	function func(
		localClusterInfo, remoteClusterInfo *cluster.Info, options diagnose.FirewallOptions, status reporter.Interface,
	) error,
) {
	status := cli.NewReporter()

	if len(args) == 2 {
		status.Warning("The two-argument form of %s is deprecated, see the documentation for details", command.Name())

		localProducer := restconfig.NewProducerFrom(args[0], "")
		remoteProducer := restconfig.NewProducerFrom(args[1], "")

		exit.OnError(localProducer.RunOnSelectedContext(
			func(localClusterInfo *cluster.Info, localNamespace string, status reporter.Interface) error {
				return remoteProducer.RunOnSelectedContext( // nolint:wrapcheck // No need to wrap errors here.
					func(remoteClusterInfo *cluster.Info, remoteNamespace string, status reporter.Interface) error {
						diagnoseFirewallOptions.PodNamespace = remoteNamespace
						return function(localClusterInfo, remoteClusterInfo, diagnoseFirewallOptions, status)
					}, status)
			}, status))
	} else {
		exit.OnError(localRemoteRestConfigProducer.RunOnSelectedContext(
			func(localClusterInfo *cluster.Info, localNamespace string, status reporter.Interface) error {
				return localRemoteRestConfigProducer.RunOnSelectedPrefixedContext( // nolint:wrapcheck // No need to wrap errors here.
					"remote",
					func(remoteClusterInfo *cluster.Info, remoteNamespace string, status reporter.Interface) error {
						diagnoseFirewallOptions.PodNamespace = remoteNamespace
						return function(localClusterInfo, remoteClusterInfo, diagnoseFirewallOptions, status)
					}, status)
			}, status))
	}
}
