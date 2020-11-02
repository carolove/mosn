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
	envoy_config_v2 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v2"
	"mosn.io/api"
	"mosn.io/mosn/pkg/log"
)

type RoleBasedAccessControlEngine struct {
	// The request is allowed if and only if:
	//   * `action` is "ALLOWED" and at least one policy matches
	//   * `action` is "DENY" and none of the policies match
	// default is ALLOWED
	Action envoy_config_v2.RBAC_Action
	// Maps from policy name to policy. A match occurs when at least one policy matches the request.
	InheritPolicies map[string]*InheritPolicy
}

// Receive the envoy_config_rbac_v2.RBAC input and convert it to mosn rbac engine
func NewRoleBasedAccessControlEngine(rbacConfig *envoy_config_v2.RBAC) (*RoleBasedAccessControlEngine, error) {
	engine := new(RoleBasedAccessControlEngine)

	// fill engine action
	engine.Action = rbacConfig.GetAction()

	// fill engine policies
	if rbacConfig != nil {
		engine.InheritPolicies = make(map[string]*InheritPolicy)
		for name, policy := range rbacConfig.Policies {
			if inheritPolicy, err := NewInheritPolicy(policy); err != nil {
				// skip to the next policy
				continue
			} else {
				engine.InheritPolicies[name] = inheritPolicy
			}
		}
	}

	return engine, nil
}

// echo request will be handled in `Allowed` function
func (engine *RoleBasedAccessControlEngine) Allowed(cb api.StreamReceiverFilterHandler, headers api.HeaderMap) (allowed bool, matchPolicyName string) {
	defer func() {
		if err := recover(); err != nil {
			log.DefaultLogger.Errorf("recover from rbac engine, error: %v", err)

			// defer runs after the return statement but before the function is actually returned,
			// so we can use named return values to hack function return
			allowed, matchPolicyName = true, ""
		}
	}()

	/*if engine.Action == envoy_config_rbac_v2.RBAC_ALLOW {
		// when engine action is ALLOW, return allowed if matched any policy
		for name, policy := range engine.InheritPolicies {
			if policy.Match(cb, headers) {
				return true, name
			}
		}
		return false, ""
	} else if engine.Action == envoy_config_rbac_v2.RBAC_DENY {
		// when engine action is DENY, return allowed if not matched any policy
		for name, policy := range engine.InheritPolicies {
			if policy.Match(cb, headers) {
				return false, name
			}
		}
		return true, ""
	}*/

	for name, policy := range engine.InheritPolicies {
		if !policy.Match(cb, headers) {
			return false, name
		}
	}

	return true, ""
}

func (engine *RoleBasedAccessControlEngine) GetPoliciesSize() int {
	return len(engine.InheritPolicies)
}
