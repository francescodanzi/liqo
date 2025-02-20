// Copyright 2019-2023 The Liqo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package exposition

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	corev1listers "k8s.io/client-go/listers/core/v1"
	discoveryv1listers "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/klog/v2"
	"k8s.io/utils/trace"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vkv1alpha1 "github.com/liqotech/liqo/apis/virtualkubelet/v1alpha1"
	vkv1alpha1clients "github.com/liqotech/liqo/pkg/client/clientset/versioned/typed/virtualkubelet/v1alpha1"
	vkv1alpha1listers "github.com/liqotech/liqo/pkg/client/listers/virtualkubelet/v1alpha1"
	"github.com/liqotech/liqo/pkg/liqonet/ipam"
	"github.com/liqotech/liqo/pkg/virtualKubelet/forge"
	"github.com/liqotech/liqo/pkg/virtualKubelet/reflection/generic"
	"github.com/liqotech/liqo/pkg/virtualKubelet/reflection/manager"
	"github.com/liqotech/liqo/pkg/virtualKubelet/reflection/options"
)

var _ manager.NamespacedReflector = (*NamespacedEndpointSliceReflector)(nil)

const (
	// EndpointSliceReflectorName -> The name associated with the EndpointSlice reflector.
	EndpointSliceReflectorName = "EndpointSlice"
)

// NamespacedEndpointSliceReflector manages the EndpointSlice reflection for a given pair of local and remote namespaces.
type NamespacedEndpointSliceReflector struct {
	generic.NamespacedReflector

	localServices                    corev1listers.ServiceNamespaceLister
	localEndpointSlices              discoveryv1listers.EndpointSliceNamespaceLister
	remoteShadowEndpointSlices       vkv1alpha1listers.ShadowEndpointSliceNamespaceLister
	remoteShadowEndpointSlicesClient vkv1alpha1clients.ShadowEndpointSliceInterface

	ipamclient   ipam.IpamClient
	translations sync.Map
}

// NewEndpointSliceReflector returns a new EndpointSliceReflector instance.
func NewEndpointSliceReflector(ipamclient ipam.IpamClient, workers uint) manager.Reflector {
	return generic.NewReflector(EndpointSliceReflectorName, NewNamespacedEndpointSliceReflector(ipamclient), generic.WithoutFallback(), workers)
}

// NewNamespacedEndpointSliceReflector returns a function generating NamespacedEndpointSliceReflector instances.
func NewNamespacedEndpointSliceReflector(ipamclient ipam.IpamClient) func(*options.NamespacedOpts) manager.NamespacedReflector {
	return func(opts *options.NamespacedOpts) manager.NamespacedReflector {
		localServices := opts.LocalFactory.Core().V1().Services()
		local := opts.LocalFactory.Discovery().V1().EndpointSlices()
		remoteShadow := opts.RemoteLiqoFactory.Virtualkubelet().V1alpha1().ShadowEndpointSlices()

		local.Informer().AddEventHandler(opts.HandlerFactory(generic.NamespacedKeyer(opts.LocalNamespace)))
		_, err := remoteShadow.Informer().AddEventHandler(opts.HandlerFactory(generic.NamespacedKeyer(opts.LocalNamespace)))
		utilruntime.Must(err)

		ner := &NamespacedEndpointSliceReflector{
			NamespacedReflector:              generic.NewNamespacedReflector(opts, EndpointSliceReflectorName),
			localServices:                    localServices.Lister().Services(opts.LocalNamespace),
			localEndpointSlices:              local.Lister().EndpointSlices(opts.LocalNamespace),
			remoteShadowEndpointSlices:       remoteShadow.Lister().ShadowEndpointSlices(opts.RemoteNamespace),
			remoteShadowEndpointSlicesClient: opts.RemoteLiqoClient.VirtualkubeletV1alpha1().ShadowEndpointSlices(opts.RemoteNamespace),
			ipamclient:                       ipamclient,
		}

		// Enqueue all existing remote EndpointSlices in case the local Service has the "skip-reflection" annotation, to ensure they are also deleted.
		localServices.Informer().AddEventHandler(opts.HandlerFactory(ner.ServiceToEndpointSlicesKeyer))

		return ner
	}
}

// Handle reconciles endpointslice objects.
func (ner *NamespacedEndpointSliceReflector) Handle(ctx context.Context, name string) error {
	tracer := trace.FromContext(ctx)

	// Skip the kubernetes service, as meaningless to reflect.
	if ner.LocalNamespace() == corev1.NamespaceDefault && name == kubernetesServiceName {
		klog.V(4).Infof("Skipping reflection of local EndpointSlice %q as blacklisted", ner.LocalRef(name))
		return nil
	}

	// Retrieve the local and remote objects (only not found errors can occur).
	klog.V(4).Infof("Handling reflection of local EndpointSlice %q (remote: %q)", ner.LocalRef(name), ner.RemoteRef(name))

	local, lerr := ner.localEndpointSlices.Get(name)
	utilruntime.Must(client.IgnoreNotFound(lerr))
	localExists := !kerrors.IsNotFound(lerr)

	remote, rerr := ner.remoteShadowEndpointSlices.Get(name)
	utilruntime.Must(client.IgnoreNotFound(rerr))
	remoteExists := !kerrors.IsNotFound(rerr)

	tracer.Step("Retrieved the local and remote objects")

	// Abort the reflection if the remote object is not managed by us, as we do not want to mutate others' objects.
	if remoteExists && (!forge.IsReflected(remote) || !forge.IsEndpointSliceManagedByReflection(remote)) {
		// Prevent misleading warnings triggered by remote non-reflected endpointslices, since they inherit
		// the labels from the service. Hence, vanilla remote endpointslices do also trigger the Handle function.
		if localExists {
			klog.Infof("Skipping reflection of local EndpointSlice %q as remote already exists and is not managed by us", ner.LocalRef(name))
			ner.Event(local, corev1.EventTypeWarning, forge.EventFailedReflection, forge.EventFailedReflectionAlreadyExistsMsg())
		}
		return nil
	}

	// Abort the reflection if the local object has the "skip-reflection" annotation.
	if localExists && ner.ShouldSkipReflection(local) {
		klog.Infof("Skipping reflection of local EndpointSlice %q as marked with the skip annotation", ner.LocalRef(name))
		ner.Event(local, corev1.EventTypeNormal, forge.EventReflectionDisabled, forge.EventObjectReflectionDisabledMsg())
		if !remoteExists { // The shadow object does not already exist, hence no further action is required.
			return nil
		}

		// Otherwise, let pretend the local object does not exist, so that the remote one gets deleted.
		localExists = false
	}

	tracer.Step("Performed the sanity checks")

	// The local endpointslice does no longer exist. Ensure it is also absent from the remote cluster.
	if !localExists {
		// Release the address translations
		if err := ner.UnmapEndpointIPs(ctx, name); err != nil {
			return err
		}

		defer tracer.Step("Ensured the absence of the remote object")
		if remoteExists {
			klog.V(4).Infof("Deleting remote shadowendpointslice %q, since local %q does no longer exist", ner.RemoteRef(name), ner.LocalRef(name))
			return ner.DeleteRemote(ctx, ner.remoteShadowEndpointSlicesClient, "ShadowEndpointSlice", name, remote.GetUID())
		}

		klog.V(4).Infof("Local EndpointSlice %q and remote EndpointSlice %q both vanished", ner.LocalRef(name), ner.RemoteRef(name))
		return nil
	}

	// Wrap the address translation logic, so that we do not have to handle errors in the forge logic.
	var terr error
	translator := func(originals []string) []string {
		// Avoid processing further addresses if one already failed.
		if terr != nil {
			return nil
		}

		var translations []string
		translations, terr = ner.MapEndpointIPs(ctx, name, originals)
		return translations
	}

	target := forge.RemoteShadowEndpointSlice(local, remote, ner.RemoteNamespace(), translator)
	if terr != nil {
		klog.Errorf("Reflection of local EndpointSlice %q to %q failed: %v", ner.LocalRef(name), ner.RemoteRef(name), terr)
		ner.Event(local, corev1.EventTypeWarning, forge.EventFailedReflection, forge.EventFailedReflectionMsg(terr))
		return terr
	}
	tracer.Step("Forged the remote shadowendpointslice")

	// If the remote shadowendpointslice does not exist, then create it.
	if !remoteExists {
		defer tracer.Step("Ensured the presence of the remote object")
		_, err := ner.remoteShadowEndpointSlicesClient.Create(ctx, target, metav1.CreateOptions{FieldManager: forge.ReflectionFieldManager})
		if err != nil {
			if kerrors.IsAlreadyExists(err) {
				klog.Infof("Remote shadowendpointslice %q already exists (local endpointslice: %q)", ner.RemoteRef(name), ner.LocalRef(name))
				return nil
			}
			klog.Errorf("Failed to create remote shadowendpointslice %q (local endpointslice: %q): %v", ner.RemoteRef(name), ner.LocalRef(name), err)
			if !kerrors.IsConflict(err) {
				ner.Event(local, corev1.EventTypeWarning, forge.EventFailedReflection, forge.EventFailedReflectionMsg(err))
			}
			return err
		}

		klog.Infof("Remote shadowendpointslice %q successfully created (local: %q)", ner.RemoteRef(name), ner.LocalRef(name))
		ner.Event(local, corev1.EventTypeNormal, forge.EventSuccessfulReflection, forge.EventSuccessfulReflectionMsg())
		tracer.Step("Created the remote shadowendpointslice")
		return nil
	}

	// If so, perform the actual update operation if needed.
	if ner.ShouldUpdateShadowEndpointSlice(ctx, remote, target) {
		_, err := ner.remoteShadowEndpointSlicesClient.Update(ctx, target, metav1.UpdateOptions{FieldManager: forge.ReflectionFieldManager})
		if err != nil {
			klog.Errorf("Failed to update remote shadowendpointslice %q (local endpointslice: %q): %v", ner.RemoteRef(name), ner.LocalRef(name), err)
			if !kerrors.IsConflict(err) {
				ner.Event(local, corev1.EventTypeWarning, forge.EventFailedReflection, forge.EventFailedReflectionMsg(err))
			}
			return err
		}

		klog.Infof("Remote shadowendpointslice %q successfully updated (local endpointslice: %q)", ner.RemoteRef(name), ner.LocalRef(name))
		ner.Event(local, corev1.EventTypeNormal, forge.EventSuccessfulReflection, forge.EventSuccessfulReflectionMsg())
		tracer.Step("Updated the remote shadowendpointslice")
	} else {
		klog.V(4).Infof("Skipping remote shadowendpointslice %q update, as already synced", ner.RemoteRef(name))
	}

	return nil
}

// ShouldUpdateShadowEndpointSlice checks whether it is necessary to update the remote shadowendpointslice, based on the forged one.
func (ner *NamespacedEndpointSliceReflector) ShouldUpdateShadowEndpointSlice(ctx context.Context,
	remote, target *vkv1alpha1.ShadowEndpointSlice) bool {
	defer trace.FromContext(ctx).Step("Checked whether a shadowendpointslice update was needed")
	return !labels.Equals(remote.GetLabels(), target.GetLabels()) ||
		!labels.Equals(remote.GetAnnotations(), target.GetAnnotations()) ||
		!reflect.DeepEqual(remote.Spec.Template.AddressType, target.Spec.Template.AddressType) ||
		!reflect.DeepEqual(remote.Spec.Template.Endpoints, target.Spec.Template.Endpoints) ||
		!reflect.DeepEqual(remote.Spec.Template.Ports, target.Spec.Template.Ports)
}

// MapEndpointIPs maps the local set of addresses to the corresponding remote ones.
func (ner *NamespacedEndpointSliceReflector) MapEndpointIPs(ctx context.Context, endpointslice string, originals []string) ([]string, error) {
	var translations []string

	// Retrieve the cache for the given endpointslice. The cache is not synchronized,
	// since we are guaranteed to be the only ones operating on this object.
	ucache, _ := ner.translations.LoadOrStore(endpointslice, map[string]string{})
	cache := ucache.(map[string]string)

	for _, original := range originals {
		// Check if we already know the translation.
		translation, found := cache[original]

		if !found {
			switch ner.ipamclient.(type) {
			case nil:
				// If the IPAM is not enabled we just use the original IP.
				translation = original
			default:
				// Cache miss -> we need to interact with the IPAM to request the translation.
				response, err := ner.ipamclient.MapEndpointIP(ctx, &ipam.MapRequest{ClusterID: forge.RemoteCluster.ClusterID, Ip: original})
				if err != nil {
					return nil, fmt.Errorf("failed to translate endpoint IP %v: %w", original, err)
				}
				translation = response.GetIp()
				cache[original] = translation
			}
		}

		translations = append(translations, translation)
		klog.V(6).Infof("Translated local endpoint IP %v to remote %v", original, translation)
	}

	return translations, nil
}

// UnmapEndpointIPs unmaps the local set of addresses for the given endpointslice and releases the corresponding remote ones.
func (ner *NamespacedEndpointSliceReflector) UnmapEndpointIPs(ctx context.Context, endpointslice string) error {
	// Retrieve the cache for the given endpointslice. The cache is not synchronized,
	// since we are guaranteed to be the only ones operating on this object.
	ucache, found := ner.translations.Load(endpointslice)
	if !found {
		klog.V(4).Infof("Mappings from local EndpointSlice %q to remote %q already released",
			ner.LocalRef(endpointslice), ner.RemoteRef(endpointslice))
		return nil
	}

	cache := ucache.(map[string]string)
	for original, translation := range cache {
		switch ner.ipamclient.(type) {
		case nil:
			// If the IPAM is not enabled we do not need to release the translation.
		default:
			// Interact with the IPAM to release the translation.
			_, err := ner.ipamclient.UnmapEndpointIP(ctx, &ipam.UnmapRequest{ClusterID: forge.RemoteCluster.ClusterID, Ip: original})
			if err != nil {
				klog.Errorf("Failed to release endpoint IP %v of EndpointSlice %q: %w", original, ner.LocalRef(endpointslice), err)
				return fmt.Errorf("failed to release endpoint IP %v of EndpointSlice %q: %w", original, ner.LocalRef(endpointslice), err)
			}
		}

		// Remove the object from our local cache, to avoid retrying to free it again if an error occurs with the subsequent entries.
		klog.V(6).Infof("Released mapping from local endpoint IP %v to remote %v of EndpointSlice %q", original, translation, ner.LocalRef(endpointslice))
		delete(cache, original)
	}

	// Remove the cache for this endpointslice.
	ner.translations.Delete(endpointslice)
	klog.V(4).Infof("Released mappings from local EndpointSlice %q to remote %q", ner.LocalRef(endpointslice), ner.RemoteRef(endpointslice))
	return nil
}

// ShouldSkipReflection returns whether the reflection of the given object should be skipped.
func (ner *NamespacedEndpointSliceReflector) ShouldSkipReflection(obj metav1.Object) bool {
	if ner.NamespacedReflector.ShouldSkipReflection(obj) {
		return true
	}

	// Check if a service is associated to the EndpointSlice, and whether it is marked to be skipped.
	svcname, ok := obj.GetLabels()[discoveryv1.LabelServiceName]
	if !ok {
		return false
	}

	svc, err := ner.localServices.Get(svcname)
	// Continue with the reflection in case the service is not found, as this is likely due to a race conditions
	// (i.e., the service has not yet been cached). If necessary, the informer will trigger a re-enqueue,
	// thus performing once more this check.
	return err == nil && ner.NamespacedReflector.ShouldSkipReflection(svc)
}

// ServiceToEndpointSlicesKeyer returns the NamespacedName of all local EndpointSlices associated with the given local Service.
func (ner *NamespacedEndpointSliceReflector) ServiceToEndpointSlicesKeyer(metadata metav1.Object) []types.NamespacedName {
	req, err := labels.NewRequirement(discoveryv1.LabelServiceName, selection.Equals, []string{metadata.GetName()})
	utilruntime.Must(err)
	eps, err := ner.localEndpointSlices.List(labels.NewSelector().Add(*req))
	utilruntime.Must(err)

	keys := make([]types.NamespacedName, 0, len(eps))
	keyer := generic.NamespacedKeyer(ner.LocalNamespace())
	for _, ep := range eps {
		keys = append(keys, keyer(ep)...)
	}

	return keys
}
