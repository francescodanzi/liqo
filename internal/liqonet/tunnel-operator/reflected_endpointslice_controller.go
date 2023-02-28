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

	"github.com/containernetworking/plugins/pkg/ns"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	liqoipset "github.com/liqotech/liqo/pkg/liqonet/ipset"
	liqoiptables "github.com/liqotech/liqo/pkg/liqonet/iptables"
	liqovk "github.com/liqotech/liqo/pkg/virtualKubelet/forge"
)

// reflectedEndpointsliceController reconciles an offloaded Service object
type reflectedEndpointsliceController struct {
	client.Client
	liqoiptables.IPTHandler
	*liqoipset.IPSetHandler

	// Liqo Gateway network namespace
	gatewayNetns ns.NetNS

	// Local cache of serviceInfo objects
	endpointslicesInfo *sync.Map
}

//+kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch;
//+kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices/endpoints,verbs=get;list;watch;
//+kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices/endpoints/addresses,verbs=get;list;watch;

// NewOffloadedPodController instantiates and initializes the offloaded service controller.
func NewReflectedEndpointsliceController(cl client.Client, gatewayNetns ns.NetNS) (*reflectedEndpointsliceController, error) {
	// Create the IPTables handler
	iptablesHandler, err := liqoiptables.NewIPTHandler()
	if err != nil {
		return nil, err
	}
	// Create the IPSet handler
	ipsetHandler := liqoipset.NewIPSetHandler()
	// Create and return the controller
	return &reflectedEndpointsliceController{
		Client:             cl,
		IPTHandler:         iptablesHandler,
		IPSetHandler:       &ipsetHandler,
		gatewayNetns:       gatewayNetns,
		endpointslicesInfo: &sync.Map{},
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
func (r *reflectedEndpointsliceController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	nsName := req.NamespacedName
	klog.Infof("Reconcile Endpointslice %q", nsName)

	endpointslice := discoveryv1.EndpointSlice{}
	if err := r.Get(ctx, nsName, &endpointslice); err != nil {
		err = client.IgnoreNotFound(err)
		if err == nil {
			// Delete endpointliceInfo object
			if value, ok := r.endpointslicesInfo.LoadAndDelete(nsName); ok {
				// Endpointslice not found, endpointsliceInfo object found: ensure iptables rules
				klog.Infof("Endpointslice %q not found: ensuring updated iptables rules", nsName)

				// Soft delete object
				endpointsliceInfo := value.(liqoiptables.ReflectedEndpointsliceInfo)
				endpointsliceInfo.Deleting = true
				r.endpointslicesInfo.Store(nsName, endpointsliceInfo)

				if err := r.gatewayNetns.Do(r.ensureIptablesRules); err != nil {
					klog.Errorf("Error while ensuring iptables rules: %w", err)
					return ctrl.Result{}, err
				}

				// Hard delete object
				r.endpointslicesInfo.Delete(nsName)
			}
		}
		return ctrl.Result{}, err
	}

	endpointsAddresses := []string{}

	for _, endpoints := range endpointslice.Endpoints {
		endpointsAddresses = append(endpointsAddresses, endpoints.Addresses...)
	}

	// Build endpointliceInfo object
	endpointsliceInfo := liqoiptables.ReflectedEndpointsliceInfo{
		EndpointsAddresses: endpointsAddresses,
		RemoteClusterID:    endpointslice.Labels[liqovk.LiqoOriginClusterIDKey],
	}

	// Check if the object is under deletion
	if !endpointslice.ObjectMeta.DeletionTimestamp.IsZero() {
		// Endpointslice under deletion: skip creation of iptables rules and return no error
		klog.Infof("Endpointslice %q under deletion: skipping iptables rules update", nsName)
		return ctrl.Result{}, nil
	}

	// Check if EndpointsAddresses is empty
	if len(endpointsliceInfo.EndpointsAddresses) == 0 {
		// EndpointsAddresses yet empty: skip creation of iptables rules and return no error
		klog.Infof("Endpointslice %q IP addresses not yet set: skipping iptables rules update", nsName)
		return ctrl.Result{}, nil
	}

	// Store endpointslicesInfo object
	r.endpointslicesInfo.Store(nsName, endpointsliceInfo)

	// Ensure iptables rules
	klog.Infof("Ensuring updated iptables rules")
	if err := r.gatewayNetns.Do(r.ensureIptablesRules); err != nil {
		klog.Errorf("Error while ensuring iptables rules: %w", err)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *reflectedEndpointsliceController) ensureIptablesRules(netns ns.NetNS) error {
	return r.EnsureRulesForRemoteEndpointslicesReflected(r.endpointslicesInfo, r.IPSetHandler)
}

// SetupWithManager sets up the controller with the Manager.
func (r *reflectedEndpointsliceController) SetupWithManager(mgr ctrl.Manager) error {
	// endpointslicePredicate selects those endpointslices matching the provided label
	endpointslicePredicate, err := predicate.LabelSelectorPredicate(metav1.LabelSelector{
		MatchLabels: map[string]string{
			discoveryv1.LabelManagedBy: liqovk.EndpointSliceManagedBy,
		},
	})
	if err != nil {
		klog.Error(err)
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&discoveryv1.EndpointSlice{}, builder.WithPredicates(endpointslicePredicate)).
		Complete(r)
}
