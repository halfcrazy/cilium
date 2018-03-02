// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipcache

import (
	"encoding/json"
	"path"
	"sort"
	"sync"

	"github.com/cilium/cilium/pkg/envoy"
	envoyAPI "github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

const (
	// DefaultAddressSpace is the address space used if none is provided.
	DefaultAddressSpace = "default"
)

var (
	// IPIdentitiesPath is the path to where endpoint IPs are stored in the key-value
	//store.
	IPIdentitiesPath = path.Join(kvstore.BaseKeyPrefix, "state", "endpointIPs", "v1")

	// IPIdentityCache caches the mapping of endpoint IPs to their corresponding
	// security identities across the entire cluster in which this instance of
	// Cilium is running.
	IPIdentityCache = NewIPCache(envoy.NetworkPolicyHostsCache)

	// AddressSpace is the address space (cluster, etc.) in which policy is
	// computed. It is determined by the orchestration system / runtime.
	AddressSpace = DefaultAddressSpace

	setupIPIdentityWatcher sync.Once
)

// IPCache is a caching of endpoint IP to security identity (and vice-versa) for
// all endpoints which are part of the same cluster.
type IPCache struct {
	mutex              lock.RWMutex
	ipToIdentityCache  map[string]identity.NumericIdentity
	identityToIPCache  map[identity.NumericIdentity]map[string]struct{}
	xdsResourceMutator xds.ResourceMutator
}

// NewIPCache returns a new IPCache with the mappings of endpoint IP to security
// identity (and vice-versa) initialized, along with the provided resourceMutator.
func NewIPCache(resourceMutator xds.ResourceMutator) *IPCache {
	return &IPCache{
		ipToIdentityCache:  map[string]identity.NumericIdentity{},
		identityToIPCache:  map[identity.NumericIdentity]map[string]struct{}{},
		xdsResourceMutator: resourceMutator,
	}
}

// Upsert adds / updates  the provided IP and identity into both caches contained
// within ipc.
func (ipc *IPCache) Upsert(endpointIP string, identity identity.NumericIdentity) {
	ipc.mutex.Lock()
	log.Debugf("ipcache.Upsert: locking ipcache")

	// Update both maps.
	ipc.ipToIdentityCache[endpointIP] = identity

	_, found := ipc.identityToIPCache[identity]
	if !found {
		ipc.identityToIPCache[identity] = map[string]struct{}{}
	}
	ipc.identityToIPCache[identity][endpointIP] = struct{}{}
	endpointIPs := ipc.identityToIPCache[identity]

	// Sort IPs for Upsert into xdsResourceMutator.
	ipStrings := make([]string, 0, len(endpointIPs))
	for endpointIP := range endpointIPs {
		ipStrings = append(ipStrings, endpointIP)
	}
	sort.Strings(ipStrings)
	log.Debugf("ipcache.Upsert: unlocking ipcache")
	ipc.mutex.Unlock()
	ipc.xdsResourceMutator.Upsert(envoy.NetworkPolicyHostsTypeURL, identity.StringID(), &envoyAPI.NetworkPolicyHosts{Policy: uint64(identity), HostAddresses: ipStrings}, false)
}

// Delete removes the provided IP-to-security-identity mapping from both caches
// within ipc.
func (ipc *IPCache) Delete(endpointIP string) {
	ipc.mutex.Lock()
	log.Debugf("ipcache.Delete: locking ipcache")

	identity, found := ipc.ipToIdentityCache[endpointIP]
	if found {
		delete(ipc.ipToIdentityCache, endpointIP)
		delete(ipc.identityToIPCache[identity], endpointIP)
		if len(ipc.identityToIPCache[identity]) == 0 {
			delete(ipc.identityToIPCache, identity)
		}
		log.Debugf("ipcache.Delete: unlocking ipcache before resource mutator delete")
		ipc.mutex.Unlock()
		ipc.xdsResourceMutator.Delete(envoy.NetworkPolicyHostsTypeURL, identity.StringID(), false)
	} else {
		log.Debugf("ipcache.Delete: unlocking ipcache without resource mutator delete")
		ipc.mutex.Unlock()
	}
}

// LookupByIP returns the corresponding security identity that endpoint IP maps
// to within the provided IPCache, as well as if the corresponding entry exists
// in the IPCache.
func (ipc *IPCache) LookupByIP(endpointIP string) (identity.NumericIdentity, bool) {
	ipc.mutex.RLock()
	log.Debugf("ipcache.LookupByIP: RLocking ipcache")
	identity, exists := ipc.ipToIdentityCache[endpointIP]
	log.Debugf("ipcache.LookupByIP: RUnlocking ipcache")
	ipc.mutex.RUnlock()
	return identity, exists
}

// LookupByIdentity returns the set of endpoint IPs that have security identity
// ID, as well as if the corresponding entry exists in the IPCache.
func (ipc *IPCache) LookupByIdentity(id identity.NumericIdentity) (map[string]struct{}, bool) {
	ipc.mutex.RLock()
	log.Debugf("ipcache.LookupByIdentity: RLocking ipcache")
	ips, exists := ipc.identityToIPCache[id]
	log.Debugf("ipcache.LookupByIdentity: RUnlocking ipcache")
	ipc.mutex.RUnlock()
	return ips, exists
}

// IPIdentityMappingOwner is the interface the owner of an identity allocator
// must implement
type IPIdentityMappingOwner interface {
	// TriggerPolicyUpdates will be called whenever a policy recalculation
	// must be triggered
	TriggerPolicyUpdates(force bool) *sync.WaitGroup
}

// GetIPIdentityMapModel returns all known endpoint IP to security identity mappings
// stored in the key-value store.
func GetIPIdentityMapModel() {
	// TODO (ianvernon) return model of ip to identity mapping. For use in CLI.
	// see GH-2555
}

func ipIdentityWatcher(owner IPIdentityMappingOwner) {

watch:
	watcher := kvstore.ListAndWatch("endpointIPWatcher", IPIdentitiesPath, 512)
	for {
		var (
			identity     identity.NumericIdentity
			cacheChanged bool
		)

		// Get events from channel as they come in.
		event, ok := <-watcher.Events

		log.Debugf("ipIdentityWatcher: received event")

		// If for whatever reason channel is closed for watcher, try to list and
		// watch again.
		if !ok {
			log.Debugf("%s closed, restarting watch", watcher.String())
			goto watch
		}

		_ = json.Unmarshal(event.Value, &identity)

		// Synchronize local caching of endpoint IP to identity mapping with
		// operation key-value store has informed us about.

		cachedIdentity, exists := IPIdentityCache.LookupByIP(event.Key)

		switch event.Typ {
		case kvstore.EventTypeCreate, kvstore.EventTypeModify:
			// Update local cache
			if !exists || cachedIdentity != identity {
				IPIdentityCache.Upsert(event.Key, identity)
				cacheChanged = true
			}
		case kvstore.EventTypeDelete:
			if exists {
				IPIdentityCache.Delete(event.Key)
				cacheChanged = true
			}
		}

		// Trigger policy updates only if cache has changed.
		if cacheChanged {
			log.WithFields(logrus.Fields{
				"endpoint-ip":      event.Key,
				"cached-identity":  cachedIdentity,
				logfields.Identity: identity,
			}).Debugf("triggering policy updates because endpoint IP cache changed state")
			owner.TriggerPolicyUpdates(true)
		}
	}
}

// InitIPIdentityWatcher initializes the watcher for ip-identity mapping events
// in the key-value store.
func InitIPIdentityWatcher(owner IPIdentityMappingOwner) {
	setupIPIdentityWatcher.Do(func() {
		go ipIdentityWatcher(owner)
	})
}
