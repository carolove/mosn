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
	"net"
	"reflect"
	"strconv"

	"mosn.io/api"
	"mosn.io/mosn/pkg/log"

	envoy_config_rbac_v2 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v2"
	"mosn.io/mosn/pkg/mtls"
)

type InheritPrincipal interface {
	isInheritPrincipal()
	// A policy matches if and only if at least one of InheritPermission.Match return true
	// AND at least one of InheritPrincipal.Match return true
	Match(cb api.StreamReceiverFilterHandler, headers api.HeaderMap) bool
}

func (*PrincipalAny) isInheritPrincipal()           {}
func (*PrincipalSourceIp) isInheritPrincipal()      {}
func (*PrincipalHeader) isInheritPrincipal()        {}
func (*PrincipalAndIds) isInheritPrincipal()        {}
func (*PrincipalOrIds) isInheritPrincipal()         {}
func (*PrincipalAuthenticated) isInheritPrincipal() {}

// Principal_Any
type PrincipalAny struct {
	Any bool
}

func NewPrincipalAny(principal *envoy_config_rbac_v2.Principal_Any) (*PrincipalAny, error) {
	return &PrincipalAny{
		Any: principal.Any,
	}, nil
}

func (principal *PrincipalAny) Match(cb api.StreamReceiverFilterHandler, headers api.HeaderMap) bool {
	return principal.Any
}

// Principal_SourceIp
type PrincipalSourceIp struct {
	CidrRange *net.IPNet
}

func NewPrincipalSourceIp(principal *envoy_config_rbac_v2.Principal_SourceIp) (*PrincipalSourceIp, error) {
	addressPrefix := principal.SourceIp.AddressPrefix
	prefixLen := principal.SourceIp.PrefixLen.GetValue()
	if _, ipNet, err := net.ParseCIDR(addressPrefix + "/" + strconv.Itoa(int(prefixLen))); err != nil {
		return nil, err
	} else {
		inheritPrincipal := &PrincipalSourceIp{
			CidrRange: ipNet,
		}
		return inheritPrincipal, nil
	}
}

func (principal *PrincipalSourceIp) Match(cb api.StreamReceiverFilterHandler, headers api.HeaderMap) bool {
	remoteAddr := cb.Connection().RemoteAddr()
	addr, err := net.ResolveTCPAddr(remoteAddr.Network(), remoteAddr.String())
	if err != nil {
		panic(fmt.Errorf("[PrincipalSourceIp.Match] failed to parse remote address in rbac filter, err: %v", err))
	}
	if principal.CidrRange.Contains(addr.IP) {
		return true
	} else {
		return false
	}
}

// Principal_Header
type PrincipalHeader struct {
	Target      string
	Matcher     HeaderMatcher
	InvertMatch bool
}

func NewPrincipalHeader(principal *envoy_config_rbac_v2.Principal_Header) (*PrincipalHeader, error) {
	inheritPrincipal := &PrincipalHeader{}
	inheritPrincipal.Target = principal.Header.Name
	inheritPrincipal.InvertMatch = principal.Header.InvertMatch
	if headerMatcher, err := NewHeaderMatcher(principal.Header); err != nil {
		return nil, err
	} else {
		inheritPrincipal.Matcher = headerMatcher
		return inheritPrincipal, nil
	}
}

func (principal *PrincipalHeader) Match(cb api.StreamReceiverFilterHandler, headers api.HeaderMap) bool {
	targetValue, found := headerMapper(principal.Target, headers)

	// HeaderMatcherPresentMatch is a little special
	if matcher, ok := principal.Matcher.(*HeaderMatcherPresentMatch); ok {
		// HeaderMatcherPresentMatch matches if and only if header found and PresentMatch is true
		isMatch := found && matcher.PresentMatch
		return principal.InvertMatch != isMatch
	}

	// return false when targetValue is not found, except matcher is `HeaderMatcherPresentMatch`
	if !found {
		return false
	} else {
		isMatch := principal.Matcher.Equal(targetValue)
		// principal.InvertMatch xor isMatch
		return principal.InvertMatch != isMatch
	}
}

// Principal_AndIds
type PrincipalAndIds struct {
	AndIds []InheritPrincipal
}

func NewPrincipalAndIds(principal *envoy_config_rbac_v2.Principal_AndIds) (*PrincipalAndIds, error) {
	inheritPrincipal := &PrincipalAndIds{}
	inheritPrincipal.AndIds = make([]InheritPrincipal, len(principal.AndIds.Ids))
	for idx, subPrincipal := range principal.AndIds.Ids {
		if subInheritPrincipal, err := NewInheritPrincipal(subPrincipal); err != nil {
			return nil, err
		} else {
			inheritPrincipal.AndIds[idx] = subInheritPrincipal
		}
	}
	return inheritPrincipal, nil
}

func (principal *PrincipalAndIds) Match(cb api.StreamReceiverFilterHandler, headers api.HeaderMap) bool {
	for _, ids := range principal.AndIds {
		if isMatch := ids.Match(cb, headers); isMatch {
			continue
		} else {
			return false
		}
	}
	return true
}

// Principal_OrIds
type PrincipalOrIds struct {
	OrIds []InheritPrincipal
}

func NewPrincipalOrIds(principal *envoy_config_rbac_v2.Principal_OrIds) (*PrincipalOrIds, error) {
	inheritPrincipal := &PrincipalOrIds{}
	inheritPrincipal.OrIds = make([]InheritPrincipal, len(principal.OrIds.Ids))
	for idx, subPrincipal := range principal.OrIds.Ids {
		if subInheritPrincipal, err := NewInheritPrincipal(subPrincipal); err != nil {
			return nil, err
		} else {
			inheritPrincipal.OrIds[idx] = subInheritPrincipal
		}
	}
	return inheritPrincipal, nil
}

func (principal *PrincipalOrIds) Match(cb api.StreamReceiverFilterHandler, headers api.HeaderMap) bool {
	for _, ids := range principal.OrIds {
		if isMatch := ids.Match(cb, headers); isMatch {
			return true
		} else {
			continue
		}
	}
	return false
}

// Principal_Authenticated_
type PrincipalAuthenticated struct {
	Name string
}

func NewPrincipalAuthenticated(principal *envoy_config_rbac_v2.Principal_Authenticated_) (*PrincipalAuthenticated, error) {
	return &PrincipalAuthenticated{
		// TODO: principal.Authenticated.GetName()
		Name: principal.Authenticated.GetPrincipalName().String(),
	}, nil
}

/*
 * here is C++ implement in Envoy

	bool AuthenticatedMatcher::matches(const Network::Connection& connection,
									   const Envoy::Http::HeaderMap&,
									   const envoy::api::v2::core::Metadata&) const {
	  const auto* ssl = connection.ssl();
	  if (!ssl) { // connection was not authenticated
		return false;
	  } else if (!matcher_.has_value()) { // matcher allows any subject
		return true;
	  }

	  std::string principal = ssl->uriSanPeerCertificate();
	  principal = principal.empty() ? ssl->subjectPeerCertificate() : principal;

	  return matcher_.value().match(principal);
	}

	std::string SslSocket::uriSanPeerCertificate() const {
	  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl_.get()));
	  if (!cert) {
		return "";
	  }
	  // TODO(PiotrSikora): Figure out if returning only one URI is valid limitation.
	  const std::vector<std::string>& san_uris = Utility::getSubjectAltNames(*cert, GEN_URI);
	  return (san_uris.size() > 0) ? san_uris[0] : "";
	}

	std::string SslSocket::subjectPeerCertificate() const {
	  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl_.get()));
	  if (!cert) {
		return "";
	  }
	  return Utility::getSubjectFromCertificate(*cert);
	}
*/
func (principal *PrincipalAuthenticated) Match(cb api.StreamReceiverFilterHandler, headers api.HeaderMap) bool {
	conn := cb.Connection().RawConn()
	if tlsConn, ok := conn.(*mtls.TLSConn); ok {
		log.DefaultLogger.Debugf("[PrincipalAuthenticated] match, ServerName:%s", tlsConn.ConnectionState().ServerName)
		cert := tlsConn.ConnectionState().PeerCertificates[0]

		// TODO: x509.Certificate.URIs is supported after go1.10
		// SAN URIs check

		for _, uri := range cert.URIs {
			log.DefaultLogger.Debugf("[PrincipalAuthenticated] match, principal.Name: %s, cert.URIs:%s", principal.Name, uri.String())
			if principal.Name == uri.String() {
				return true
			}
		}

		// Subject Common Name check
		if principal.Name == cert.Subject.CommonName {
			log.DefaultLogger.Debugf("[PrincipalAuthenticated] match, pricipal.Name:%s, cert.Subject.CommonName: %s", principal.Name, cert.Subject.CommonName)
			return true
		}

		return false
	} else {
		return false
	}
}

func NewPrincipalMetadata(principal *envoy_config_rbac_v2.Principal_Metadata) (*PrincipalAuthenticated, error) {
	return &PrincipalAuthenticated{
		// TODO: principal.Authenticated.GetName()
		Name: fmt.Sprintf("spiffe://%s", principal.Metadata.GetValue().GetStringMatch().GetExact()),
	}, nil
}

// Receive the envoy_config_rbac_v2.Principal input and convert it to mosn rbac principal
func NewInheritPrincipal(principal *envoy_config_rbac_v2.Principal) (InheritPrincipal, error) {
	// Types that are valid to be assigned to Identifier:
	//	*Principal_AndIds (supported)
	//	*Principal_OrIds (supported)
	//	*Principal_Any (supported)
	//	*Principal_SourceIp (supported)
	//	*Principal_Header (supported)
	//	*Principal_Authenticated_ (supported)
	// TODO: Principal_Authenticated_ & Principal_Metadata support
	//	*Principal_Metadata (unsupported)
	switch principal.Identifier.(type) {
	case *envoy_config_rbac_v2.Principal_Any:
		return NewPrincipalAny(principal.Identifier.(*envoy_config_rbac_v2.Principal_Any))
	case *envoy_config_rbac_v2.Principal_SourceIp:
		return NewPrincipalSourceIp(principal.Identifier.(*envoy_config_rbac_v2.Principal_SourceIp))
	case *envoy_config_rbac_v2.Principal_Header:
		return NewPrincipalHeader(principal.Identifier.(*envoy_config_rbac_v2.Principal_Header))
	case *envoy_config_rbac_v2.Principal_AndIds:
		return NewPrincipalAndIds(principal.Identifier.(*envoy_config_rbac_v2.Principal_AndIds))
	case *envoy_config_rbac_v2.Principal_OrIds:
		return NewPrincipalOrIds(principal.Identifier.(*envoy_config_rbac_v2.Principal_OrIds))
	case *envoy_config_rbac_v2.Principal_Authenticated_:
		return NewPrincipalAuthenticated(principal.Identifier.(*envoy_config_rbac_v2.Principal_Authenticated_))
	case *envoy_config_rbac_v2.Principal_Metadata:
		return NewPrincipalMetadata(principal.Identifier.(*envoy_config_rbac_v2.Principal_Metadata))
	default:
		return nil, fmt.Errorf("[NewInheritPrincipal] not supported Principal.Identifier type found, detail: %v",
			reflect.TypeOf(principal.Identifier))
	}
}
