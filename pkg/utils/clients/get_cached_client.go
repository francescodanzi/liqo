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

// Package clients contains utility methods to create and manage clients with custom features.
package clients

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"

	"github.com/liqotech/liqo/pkg/utils/mapper"
)

// GetCachedClient returns a controller runtime client with the cache initialized only for the resources added to
// the scheme. The necessary rest.Config is generated inside this function.
func GetCachedClient(ctx context.Context, scheme *runtime.Scheme) (client.Client, error) {
	conf := ctrl.GetConfigOrDie()
	if conf == nil {
		err := fmt.Errorf("unable to get the config file")
		klog.Error(err)
		return nil, err
	}

	return GetCachedClientWithConfig(ctx, scheme, conf, nil)
}

// GetCachedClientWithConfig returns a controller runtime client with the cache initialized only for the resources added to
// the scheme. The necessary rest.Config is passed as third parameter, it must not be nil.
func GetCachedClientWithConfig(ctx context.Context,
	scheme *runtime.Scheme, conf *rest.Config, cacheOptions *cache.Options) (client.Client, error) {
	if conf == nil {
		err := fmt.Errorf("the rest.Config parameter is nil")
		klog.Error(err)
		return nil, err
	}

	liqoMapper, err := (mapper.LiqoMapperProvider(scheme))(conf, nil)
	if err != nil {
		klog.Errorf("mapper: %s", err)
		return nil, err
	}

	c, err := cluster.New(conf, func(o *cluster.Options) {
		o.Client = client.Options{Scheme: scheme, Mapper: liqoMapper}
		if cacheOptions != nil {
			o.Cache = *cacheOptions
		} else {
			o.Cache = cache.Options{Scheme: scheme, Mapper: liqoMapper}
		}
	})
	if err != nil {
		klog.Errorf("unable to create the client: %s", err)
		return nil, err
	}

	newClient := c.GetClient()
	return newClient, nil
}
