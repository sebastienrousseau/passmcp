// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package a2a checks an agent that speaks the Agent2Agent (A2A) protocol,
// from its Agent Card: the transport it is served over, whether the card
// is a valid A2A v1 card, whether its signature verifies, and whether the
// agent serves requests without credentials.
//
// The source of truth is the A2A v1.0 specification and its protocol
// definition, specification/a2a.proto in github.com/a2aproject/A2A. A2A v1
// publishes no JSON Schema; the card's JSON form is the proto3 JSON mapping
// of the AgentCard message, so the shape below is transcribed from that
// message, field by field, with the proto's REQUIRED and `optional`
// markings. docs/a2a.md names the revision it was taken from.
package a2a

// kind is the JSON type a field must have.
type kind int

const (
	kString kind = iota
	kBool
	kObject    // a message: validated against its own shape
	kArray     // a repeated field: elements validated against elem
	kMap       // a map<string, message>: values validated against elem
	kStringMap // a map<string, string>
	kStruct    // google.protobuf.Struct: any JSON object, not inspected
)

// field is one member of a message as the proto declares it.
type field struct {
	kind     kind
	required bool // [(google.api.field_behavior) = REQUIRED]
	// optional marks proto3 explicit presence (the `optional` keyword).
	// Such a field is kept in the canonical form when present, even at
	// its default value; the specification's section 8.4.1 depends on it.
	optional bool
	// elem is the element or value type of an array or map, and the shape
	// of an object; elemKind is the element type of an array of scalars.
	elem     *shape
	elemKind kind
	// enum lists the accepted values of a string, when the proto closes it.
	enum []string
	// url marks a string that must be an absolute URL.
	url bool
}

// shape is one message.
type shape struct {
	name   string
	fields map[string]field
	// oneof names members of which exactly one must be present.
	oneof []string
}

func str() field                 { return field{kind: kString} }
func reqStr() field              { return field{kind: kString, required: true} }
func reqURL() field              { return field{kind: kString, required: true, url: true} }
func optStr() field              { return field{kind: kString, optional: true} }
func optBool() field             { return field{kind: kBool, optional: true} }
func obj(s *shape) field         { return field{kind: kObject, elem: s} }
func reqObj(s *shape) field      { return field{kind: kObject, elem: s, required: true} }
func arr(s *shape) field         { return field{kind: kArray, elem: s} }
func reqArr(s *shape) field      { return field{kind: kArray, elem: s, required: true} }
func strs() field                { return field{kind: kArray, elemKind: kString} }
func reqStrs() field             { return field{kind: kArray, elemKind: kString, required: true} }
func mapOf(s *shape) field       { return field{kind: kMap, elem: s} }
func scopes(required bool) field { return field{kind: kStringMap, required: required} }

var (
	stringList = &shape{name: "StringList", fields: map[string]field{"list": strs()}}

	securityRequirement = &shape{name: "SecurityRequirement", fields: map[string]field{
		"schemes": mapOf(stringList),
	}}

	apiKeyScheme = &shape{name: "APIKeySecurityScheme", fields: map[string]field{
		"description": str(),
		"location":    {kind: kString, required: true, enum: []string{"query", "header", "cookie"}},
		"name":        reqStr(),
	}}
	httpAuthScheme = &shape{name: "HTTPAuthSecurityScheme", fields: map[string]field{
		"description": str(), "scheme": reqStr(), "bearerFormat": str(),
	}}
	authorizationCodeFlow = &shape{name: "AuthorizationCodeOAuthFlow", fields: map[string]field{
		"authorizationUrl": reqURL(), "tokenUrl": reqURL(), "refreshUrl": str(),
		"scopes": scopes(true), "pkceRequired": {kind: kBool},
	}}
	clientCredentialsFlow = &shape{name: "ClientCredentialsOAuthFlow", fields: map[string]field{
		"tokenUrl": reqURL(), "refreshUrl": str(), "scopes": scopes(true),
	}}
	implicitFlow = &shape{name: "ImplicitOAuthFlow", fields: map[string]field{
		"authorizationUrl": str(), "refreshUrl": str(), "scopes": scopes(false),
	}}
	passwordFlow = &shape{name: "PasswordOAuthFlow", fields: map[string]field{
		"tokenUrl": str(), "refreshUrl": str(), "scopes": scopes(false),
	}}
	deviceCodeFlow = &shape{name: "DeviceCodeOAuthFlow", fields: map[string]field{
		"deviceAuthorizationUrl": reqURL(), "tokenUrl": reqURL(), "refreshUrl": str(), "scopes": scopes(true),
	}}
	oauthFlows = &shape{
		name: "OAuthFlows",
		fields: map[string]field{
			"authorizationCode": obj(authorizationCodeFlow), "clientCredentials": obj(clientCredentialsFlow),
			"implicit": obj(implicitFlow), "password": obj(passwordFlow), "deviceCode": obj(deviceCodeFlow),
		},
		oneof: []string{"authorizationCode", "clientCredentials", "implicit", "password", "deviceCode"},
	}
	oauth2Scheme = &shape{name: "OAuth2SecurityScheme", fields: map[string]field{
		"description": str(), "flows": reqObj(oauthFlows), "oauth2MetadataUrl": str(),
	}}
	oidcScheme = &shape{name: "OpenIdConnectSecurityScheme", fields: map[string]field{
		"description": str(), "openIdConnectUrl": reqURL(),
	}}
	mtlsScheme = &shape{name: "MutualTlsSecurityScheme", fields: map[string]field{"description": str()}}

	securityScheme = &shape{
		name: "SecurityScheme",
		fields: map[string]field{
			"apiKeySecurityScheme": obj(apiKeyScheme), "httpAuthSecurityScheme": obj(httpAuthScheme),
			"oauth2SecurityScheme": obj(oauth2Scheme), "openIdConnectSecurityScheme": obj(oidcScheme),
			"mtlsSecurityScheme": obj(mtlsScheme),
		},
		oneof: []string{"apiKeySecurityScheme", "httpAuthSecurityScheme", "oauth2SecurityScheme", "openIdConnectSecurityScheme", "mtlsSecurityScheme"},
	}

	agentInterface = &shape{name: "AgentInterface", fields: map[string]field{
		"url": reqStr(), "protocolBinding": reqStr(), "tenant": str(), "protocolVersion": reqStr(),
	}}
	agentProvider = &shape{name: "AgentProvider", fields: map[string]field{
		"url": reqURL(), "organization": reqStr(),
	}}
	agentExtension = &shape{name: "AgentExtension", fields: map[string]field{
		"uri": str(), "description": str(), "required": {kind: kBool}, "params": {kind: kStruct},
	}}
	agentCapabilities = &shape{name: "AgentCapabilities", fields: map[string]field{
		"streaming": optBool(), "pushNotifications": optBool(),
		"extensions": arr(agentExtension), "extendedAgentCard": optBool(),
	}}
	agentSkill = &shape{name: "AgentSkill", fields: map[string]field{
		"id": reqStr(), "name": reqStr(), "description": reqStr(), "tags": reqStrs(),
		"examples": strs(), "inputModes": strs(), "outputModes": strs(),
		"securityRequirements": arr(securityRequirement),
	}}
	agentCardSignature = &shape{name: "AgentCardSignature", fields: map[string]field{
		"protected": reqStr(), "signature": reqStr(), "header": {kind: kStruct},
	}}

	// agentCard is message AgentCard.
	agentCard = &shape{name: "AgentCard", fields: map[string]field{
		"name":                 reqStr(),
		"description":          reqStr(),
		"supportedInterfaces":  reqArr(agentInterface),
		"provider":             obj(agentProvider),
		"version":              reqStr(),
		"documentationUrl":     optStr(),
		"capabilities":         reqObj(agentCapabilities),
		"securitySchemes":      mapOf(securityScheme),
		"securityRequirements": arr(securityRequirement),
		"defaultInputModes":    reqStrs(),
		"defaultOutputModes":   reqStrs(),
		"skills":               reqArr(agentSkill),
		"signatures":           arr(agentCardSignature),
		"iconUrl":              optStr(),
	}}
)
