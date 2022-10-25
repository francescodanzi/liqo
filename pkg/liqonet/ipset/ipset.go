// Copyright 2019-2022 The Liqo Authors
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

package ipset

import (
	"k8s.io/kubernetes/pkg/util/ipset"
	"k8s.io/utils/exec"
)

const (
	// HashIP represents the `hash:ip` type ipset. The hash:ip set type stores IP address.
	HashIP ipset.Type = "hash:ip"
)

// IPSetHandler is a handler exposing functions to use the ipset utility.
type IPSetHandler struct {
	ips ipset.Interface
}

func NewIPSetHandler() IPSetHandler {
	ipset.ValidIPSetTypes = append(ipset.ValidIPSetTypes, HashIP)
	return IPSetHandler{
		ips: ipset.New(exec.New()),
	}
}

func (h *IPSetHandler) CreateSet(name, comment string) (*ipset.IPSet, error) {
	ipset := newSet(name, comment)
	if err := h.ips.CreateSet(ipset, true); err != nil {
		return nil, err
	}
	return ipset, nil
}

func (h *IPSetHandler) FlushSet(name string) error {
	return h.ips.FlushSet(name)
}

func (h *IPSetHandler) AddEntry(ip string, set *ipset.IPSet) error {
	if err := h.ips.AddEntry(ip, set, true); err != nil {
		return err
	}
	return nil
}

// Non-exported functions

func newSet(name, comment string) *ipset.IPSet {
	return &ipset.IPSet{
		Name:    name,
		SetType: HashIP,
		Comment: comment,
	}
}
