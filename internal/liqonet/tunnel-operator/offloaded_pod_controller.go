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
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/containernetworking/plugins/pkg/ns"
	liqoconsts "github.com/liqotech/liqo/pkg/consts"
	liqoipset "github.com/liqotech/liqo/pkg/liqonet/ipset"
	liqoiptables "github.com/liqotech/liqo/pkg/liqonet/iptables"
	liqovk "github.com/liqotech/liqo/pkg/virtualKubelet/forge"
)

// OffloadedPodController reconciles an offloaded Pod object
type OffloadedPodController struct {
	client.Client
	liqoiptables.IPTHandler
	*liqoipset.IPSetHandler

	// Liqo Gateway network namespace
	gatewayNetns ns.NetNS

	// Local cache of podInfo objects
	podsInfo *sync.Map
}

//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;
//+kubebuilder:rbac:groups=core,resources=pods/status,verbs=get;

// NewOffloadedPodController instantiates and initializes the offloaded pod controller.
func NewOffloadedPodController(cl client.Client, gatewayNetns ns.NetNS) (*OffloadedPodController, error) {
	// Create the IPTables handler
	iptablesHandler, err := liqoiptables.NewIPTHandler()
	if err != nil {
		return nil, err
	}
	// Create the IPSet handler
	ipsetHandler := liqoipset.NewIPSetHandler()
	// Create and return the controller
	return &OffloadedPodController{
		Client:       cl,
		IPTHandler:   iptablesHandler,
		IPSetHandler: &ipsetHandler,
		gatewayNetns: gatewayNetns,
		podsInfo:     &sync.Map{},
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
	klog.Infof("Reconcile Pod %q", nsName)

	pod := corev1.Pod{}
	if err := r.Get(ctx, nsName, &pod); err != nil {
		err = client.IgnoreNotFound(err)
		if err == nil {
			// Delete podInfo object
			if value, ok := r.podsInfo.LoadAndDelete(nsName); ok {
				// Pod not found, podInfo object found: ensure iptables rules
				klog.Infof("Pod %q not found: ensuring updated iptables rules", nsName)

				// Soft delete object
				podInfo := value.(liqoiptables.PodInfo)
				podInfo.Deleting = true
				r.podsInfo.Store(nsName, podInfo)

				if err := r.gatewayNetns.Do(r.ensureIptablesRules); err != nil {
					klog.Errorf("Error while ensuring iptables rules: %w", err)
					return ctrl.Result{}, err
				}

				// Hard delete object
				r.podsInfo.Delete(nsName)
			}
		}
		return ctrl.Result{}, err
	}

	// Build podInfo object
	podInfo := liqoiptables.PodInfo{
		PodIP:           pod.Status.PodIP,
		RemoteClusterID: pod.Labels[liqovk.LiqoOriginClusterIDKey],
	}

	// Check if the object is under deletion
	if !pod.ObjectMeta.DeletionTimestamp.IsZero() {
		// Pod under deletion: skip creation of iptables rules and return no error
		klog.Infof("Pod %q under deletion: skipping iptables rules update", nsName)
		return ctrl.Result{}, nil
	}

	// Check if the pod IP is set
	if podInfo.PodIP == "" {
		// Pod IP address not yet set: skip creation of iptables rules and return no error
		klog.Infof("Pod %q IP address not yet set: skipping iptables rules update", nsName)
		return ctrl.Result{}, nil
	}

	// Store podInfo object
	r.podsInfo.Store(nsName, podInfo)

	// Ensure iptables rules
	klog.Infof("Ensuring updated iptables rules")
	if err := r.gatewayNetns.Do(r.ensureIptablesRules); err != nil {
		klog.Errorf("Error while ensuring iptables rules: %w", err)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *OffloadedPodController) ensureIptablesRules(netns ns.NetNS) error {
	return r.EnsureRulesForOffloadedPods(r.podsInfo, r.IPSetHandler)
}

// SetupWithManager sets up the controller with the Manager.
func (r *OffloadedPodController) SetupWithManager(mgr ctrl.Manager) error {
	// podPredicate selects those pods matching the provided label
	podPredicate, err := predicate.LabelSelectorPredicate(metav1.LabelSelector{
		MatchLabels: map[string]string{
			liqoconsts.ManagedByLabelKey: liqoconsts.ManagedByShadowPodValue,
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
