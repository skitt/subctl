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

package deploy

import (
	"context"

	"github.com/submariner-io/admiral/pkg/names"
	"github.com/submariner-io/admiral/pkg/reporter"
	"github.com/submariner-io/subctl/internal/constants"
	"github.com/submariner-io/subctl/pkg/client"
	"github.com/submariner-io/subctl/pkg/image"
	"github.com/submariner-io/subctl/pkg/operator"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func Operator(ctx context.Context, status reporter.Interface, repository, imageVersion string, overrides map[string]string,
	clientProducer client.Producer, operatorDebug bool,
) error {
	status.Start("Deploying the Submariner operator")

	repositoryInfo := image.NewRepositoryInfo(repository, imageVersion, overrides)

	err := operator.Ensure(
		ctx, status, clientProducer, constants.OperatorNamespace, repositoryInfo.GetOperatorImage(), operatorDebug)

	return err //nolint:wrapcheck // No need to wrap here
}

func IsOperator(ctx context.Context, clientSet kubernetes.Interface) (bool, error) {
	operatorDeployment, err := clientSet.AppsV1().Deployments(constants.OperatorNamespace).Get(ctx, names.OperatorComponent,
		metav1.GetOptions{})
	if err != nil {
		return false, err //nolint:wrapcheck // No need to wrap here
	}

	if operatorDeployment == nil {
		return false, nil
	}

	return true, nil
}
