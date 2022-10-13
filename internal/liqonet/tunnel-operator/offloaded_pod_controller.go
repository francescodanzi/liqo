/*
Copyright 2022.

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

package tunneloperator

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/containernetworking/plugins/pkg/ns"
	liqoconsts "github.com/liqotech/liqo/pkg/consts"
	"github.com/liqotech/liqo/pkg/liqonet/iptables"
	liqovk "github.com/liqotech/liqo/pkg/virtualKubelet/forge"
)

// OffloadedPodController reconciles an offloaded Pod object
type OffloadedPodController struct {
	client.Client
	iptables.IPTHandler
	Scheme         *runtime.Scheme
	gatewayNetns   ns.NetNS
	localClusterID string
}

//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=pods/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=core,resources=pods/finalizers,verbs=update

func NewOffloadedPodController(cl client.Client, gatewayNetns ns.NetNS, localClusterID string) (*OffloadedPodController, error) {
	iptablesHandler, err := iptables.NewIPTHandler()
	if err != nil {
		return nil, err
	}
	return &OffloadedPodController{
		Client:         cl,
		IPTHandler:     iptablesHandler,
		gatewayNetns:   gatewayNetns,
		localClusterID: localClusterID,
	}, nil
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Pod object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.13.0/pkg/reconcile
func (r *OffloadedPodController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	nsName := req.NamespacedName
	klog.Infof("Reconcile Pod %q", nsName.Name)

	pod := corev1.Pod{}
	if err := r.Get(ctx, nsName, &pod); err != nil {
		err = client.IgnoreNotFound(err)
		if err == nil {
			klog.Infof("Pod %q not found: skipping the creation of iptables rule", nsName.Name)
		}
		return ctrl.Result{}, err
	}

	remoteClusterID := pod.Labels[liqovk.LiqoOriginClusterIDKey]

	// Intercept if the object is under deletion
	if !pod.ObjectMeta.DeletionTimestamp.IsZero() {
		// Delete iptables rules for remote cluster id if being deleted
		klog.Infof("Pod %q is under deletion: trying to delete relevant iptables rule for cluster %q", nsName.Name, remoteClusterID)
		if err := r.executeInGatewayNetns(r.DeleteClusterPodsForwardRules, remoteClusterID, pod.Status.PodIP); err != nil {
			klog.Errorf("Error while deleting iptables rules for cluster %q and pod %q: %w", remoteClusterID, nsName.Name, err)
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Ensure iptables rules for that pod ip and remote cluster id otherwise
	if err := r.executeInGatewayNetns(r.EnsureClusterPodsForwardRules, remoteClusterID, pod.Status.PodIP); err != nil {
		klog.Errorf("Error while ensuring iptables rules for cluster %q and pod %q: %w", remoteClusterID, nsName.Name, err)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *OffloadedPodController) executeInGatewayNetns(f func(string, string) error, remoteClusterID, podIP string) error {
	if err := r.gatewayNetns.Do(func(netns ns.NetNS) error {
		if err := f(remoteClusterID, podIP); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *OffloadedPodController) SetupWithManager(mgr ctrl.Manager) error {
	// podPredicate selects those pods matching the provided label
	podPredicate, err := predicate.LabelSelectorPredicate(metav1.LabelSelector{
		MatchLabels: map[string]string{
			liqoconsts.ManagedByLabelKey:       liqoconsts.ManagedByShadowPodValue,
			liqovk.LiqoDestinationClusterIDKey: r.localClusterID,
		},
	})
	if err != nil {
		klog.Error(err)
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}, builder.WithPredicates(podPredicate)).
		Complete(r)
}
