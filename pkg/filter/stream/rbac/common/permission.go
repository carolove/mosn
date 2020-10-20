/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package common

import (
	"fmt"
	"mosn.io/api"
	"net"
	"reflect"
	"strconv"

	"mosn.io/mosn/pkg/log"
	envoy_config_rbac_v2 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v2"
)

type InheritPermission interface {
	isInheritPermission()
	// A policy matches if and only if at least one of InheritPermission.Match return true
	// AND at least one of InheritPrincipal.Match return true
	Match(cb api.StreamReceiverFilterHandler, headers api.HeaderMap) bool
}

func (*PermissionAny) isInheritPermission()             {}
func (*PermissionDestinationIp) isInheritPermission()   {}
func (*PermissionDestinationPort) isInheritPermission() {}
func (*PermissionHeader) isInheritPermission()          {}
func (*PermissionAndRules) isInheritPermission()        {}
func (*PermissionOrRules) isInheritPermission()         {}

// Permission_Any
type PermissionAny struct {
	Any bool
}

func NewPermissionAny(permission *envoy_config_rbac_v2.Permission_Any) (*PermissionAny, error) {
	return &PermissionAny{
		Any: permission.Any,
	}, nil
}

func (permission *PermissionAny) Match(cb api.StreamReceiverFilterHandler, headers api.HeaderMap) bool {
	return permission.Any
}

// Permission_DestinationIp
type PermissionDestinationIp struct {
	CidrRange *net.IPNet
}

func NewPermissionDestinationIp(permission *envoy_config_rbac_v2.Permission_DestinationIp) (*PermissionDestinationIp, error) {
	addressPrefix := permission.DestinationIp.AddressPrefix
	prefixLen := permission.DestinationIp.PrefixLen.GetValue()
	if _, ipNet, err := net.ParseCIDR(addressPrefix + "/" + strconv.Itoa(int(prefixLen))); err != nil {
		return nil, err
	} else {
		inheritPermission := &PermissionDestinationIp{
			CidrRange: ipNet,
		}
		return inheritPermission, nil
	}
}

func (permission *PermissionDestinationIp) Match(cb api.StreamReceiverFilterHandler, headers api.HeaderMap) bool {
	localAddr := cb.Connection().LocalAddr()
	addr, err := net.ResolveTCPAddr(localAddr.Network(), localAddr.String())
	if err != nil {
		log.DefaultLogger.Errorf(
			"[PermissionDestinationIp.Match] failed to parse local address in rbac filter, err: ", err)
		return false
	}
	if permission.CidrRange.Contains(addr.IP) {
		return true
	} else {
		return false
	}
}

// Permission_DestinationPort
type PermissionDestinationPort struct {
	DestinationPort uint32
}

func NewPermissionDestinationPort(permission *envoy_config_rbac_v2.Permission_DestinationPort) (*PermissionDestinationPort, error) {
	return &PermissionDestinationPort{
		DestinationPort: permission.DestinationPort,
	}, nil
}

func (permission *PermissionDestinationPort) Match(cb api.StreamReceiverFilterHandler, headers api.HeaderMap) bool {
	localAddr := cb.Connection().LocalAddr()
	addr, err := net.ResolveTCPAddr(localAddr.Network(), localAddr.String())
	if err != nil {
		panic(fmt.Errorf("[PermissionDestinationPort.Match] failed to parse local address in rbac filter, err: %v", err))
	}
	if addr.Port == int(permission.DestinationPort) {
		return true
	} else {
		return false
	}
}

// Permission_Header
type PermissionHeader struct {
	Target      string
	Matcher     HeaderMatcher
	InvertMatch bool
}

func NewPermissionHeader(permission *envoy_config_rbac_v2.Permission_Header) (*PermissionHeader, error) {
	inheritPermission := &PermissionHeader{}
	inheritPermission.Target = permission.Header.Name
	inheritPermission.InvertMatch = permission.Header.InvertMatch
	if headerMatcher, err := NewHeaderMatcher(permission.Header); err != nil {
		return nil, err
	} else {
		inheritPermission.Matcher = headerMatcher
		return inheritPermission, nil
	}
}

func (permission *PermissionHeader) Match(cb api.StreamReceiverFilterHandler, headers api.HeaderMap) bool {
	targetValue, found := headerMapper(permission.Target, headers)

	// HeaderMatcherPresentMatch is a little special
	if matcher, ok := permission.Matcher.(*HeaderMatcherPresentMatch); ok {
		// HeaderMatcherPresentMatch matches if and only if header found and PresentMatch is true
		isMatch := found && matcher.PresentMatch
		return permission.InvertMatch != isMatch
	}

	// return false when targetValue is not found, except matcher is `HeaderMatcherPresentMatch`
	if !found {
		return false
	} else {
		isMatch := permission.Matcher.Equal(targetValue)
		// permission.InvertMatch xor isMatch
		return permission.InvertMatch != isMatch
	}
}

// Permission_AndRules
type PermissionAndRules struct {
	AndRules []InheritPermission
}

func NewPermissionAndRules(permission *envoy_config_rbac_v2.Permission_AndRules) (*PermissionAndRules, error) {
	inheritPermission := &PermissionAndRules{}
	inheritPermission.AndRules = make([]InheritPermission, len(permission.AndRules.Rules))
	for idx, subPermission := range permission.AndRules.Rules {
		if subInheritPermission, err := NewInheritPermission(subPermission); err != nil {
			return nil, err
		} else {
			inheritPermission.AndRules[idx] = subInheritPermission
		}
	}
	return inheritPermission, nil
}

func (permission *PermissionAndRules) Match(cb api.StreamReceiverFilterHandler, headers api.HeaderMap) bool {
	for _, rule := range permission.AndRules {
		if isMatch := rule.Match(cb, headers); isMatch {
			continue
		} else {
			return false
		}
	}
	return true
}

// Permission_OrRules
type PermissionOrRules struct {
	OrRules []InheritPermission
}

func NewPermissionOrRules(permission *envoy_config_rbac_v2.Permission_OrRules) (*PermissionOrRules, error) {
	inheritPermission := &PermissionOrRules{}
	inheritPermission.OrRules = make([]InheritPermission, len(permission.OrRules.Rules))
	for idx, subPermission := range permission.OrRules.Rules {
		if subInheritPermission, err := NewInheritPermission(subPermission); err != nil {
			return nil, err
		} else {
			inheritPermission.OrRules[idx] = subInheritPermission
		}
	}
	return inheritPermission, nil
}

func (permission *PermissionOrRules) Match(cb api.StreamReceiverFilterHandler, headers api.HeaderMap) bool {
	for _, rule := range permission.OrRules {
		if isMatch := rule.Match(cb, headers); isMatch {
			return true
		} else {
			continue
		}
	}
	return false
}

// Receive the envoy_config_rbac_v2.Permission input and convert it to mosn rbac permission
func NewInheritPermission(permission *envoy_config_rbac_v2.Permission) (InheritPermission, error) {
	// Types that are valid to be assigned to Rule:
	//	*Permission_AndRules (supported)
	//	*Permission_OrRules (supported)
	//	*Permission_Any (supported)
	//	*Permission_Header (supported)
	//	*Permission_DestinationIp (supported)
	//	*Permission_DestinationPort (supported)
	// TODO: Permission_Metadata support
	//	*Permission_Metadata
	switch permission.Rule.(type) {
	case *envoy_config_rbac_v2.Permission_Any:
		return NewPermissionAny(permission.Rule.(*envoy_config_rbac_v2.Permission_Any))
	case *envoy_config_rbac_v2.Permission_DestinationIp:
		return NewPermissionDestinationIp(permission.Rule.(*envoy_config_rbac_v2.Permission_DestinationIp))
	case *envoy_config_rbac_v2.Permission_DestinationPort:
		return NewPermissionDestinationPort(permission.Rule.(*envoy_config_rbac_v2.Permission_DestinationPort))
	case *envoy_config_rbac_v2.Permission_Header:
		return NewPermissionHeader(permission.Rule.(*envoy_config_rbac_v2.Permission_Header))
	case *envoy_config_rbac_v2.Permission_AndRules:
		return NewPermissionAndRules(permission.Rule.(*envoy_config_rbac_v2.Permission_AndRules))
	case *envoy_config_rbac_v2.Permission_OrRules:
		return NewPermissionOrRules(permission.Rule.(*envoy_config_rbac_v2.Permission_OrRules))
	default:
		return nil, fmt.Errorf("[NewInheritPermission] not supported Permission.Rule type found, detail: %v",
			reflect.TypeOf(permission.Rule))
	}
}
