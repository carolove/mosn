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

package rbac

import (
	"context"

	"mosn.io/api"
	v2 "mosn.io/mosn/pkg/config/v2"
	"mosn.io/mosn/pkg/filter/stream/rbac/common"
	"mosn.io/mosn/pkg/log"
)

func init() {
	api.RegisterStream(v2.RBACFilterType, CreateRbacFilterFactory)
}

// filterConfigFactory is an implement of types.StreamFilterChainFactory
type filterConfigFactory struct {
	Status       *Status
	Config       *v2.RBAC
	Engine       *common.RoleBasedAccessControlEngine
	ShadowEngine *common.RoleBasedAccessControlEngine
}

// CreateFilterChain will be invoked in echo request in proxy.NewStreamDetect function if filter has been injected
func (factory *filterConfigFactory) CreateFilterChain(context context.Context, callbacks api.StreamFilterChainFactoryCallbacks) {
	log.DefaultLogger.Debugf("create a new rbac filter")
	filter := NewFilter(context, factory)
	callbacks.AddStreamReceiverFilter(filter, api.AfterRoute)
}

func CreateRbacFilterFactory(conf map[string]interface{}) (api.StreamFilterChainFactory, error) {
	log.DefaultLogger.Debugf("create rbac filter factory")
	sfcf := new(filterConfigFactory)

	// parse rabc filter conf from mosn conf
	filterConfig, err := common.ParseRbacFilterConfig(conf)
	if err != nil {
		log.DefaultLogger.Errorf("failed to parse rabc filter configuration, rbac filter will not be registered, err: %v", err)
		return nil, err
	}

	// build rbac status
	sfcf.Status = NewStatus(filterConfig)

	// build rbac engine
	engine, err := common.NewRoleBasedAccessControlEngine(filterConfig.GetRules())
	if err != nil {
		log.DefaultLogger.Errorf("failed to build rbac engine, rbac filter will not be registered, err: %v", err)
		return nil, err
	}
	sfcf.Engine = engine

	// build rbac shadow engine
	shadowEngine, err := common.NewRoleBasedAccessControlEngine(filterConfig.GetShadowRules())
	if err != nil {
		log.DefaultLogger.Errorf("failed to build rbac shadow engine, rbac filter will not be registered, err: %v", err)
		return nil, err
	}
	sfcf.ShadowEngine = shadowEngine

	log.DefaultLogger.Debugf("rbac engine initialized, %v policies in engine, %v policies in shadow engine",
		sfcf.Engine.GetPoliciesSize(), sfcf.ShadowEngine.GetPoliciesSize())

	return sfcf, nil
}
