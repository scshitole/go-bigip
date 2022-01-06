/*
Original work Copyright © 2015 Scott Ware
Modifications Copyright 2019 F5 Networks Inc
Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
*/
package bigip

import (
/*	"regexp"
	"strings"*/
"time"
)

// WAF Policies  on the BIG-IP system.
type WAFpolicies struct {
	WAFpolicies []WAFpolicy `json:"items"`
}

type WApolicy struct {
	Kind       string `json:"kind"`
	SelfLink   string `json:"selfLink"`
	TotalItems int    `json:"totalItems"`
	Items      []struct {
		PlainTextProfileReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"plainTextProfileReference"`
		DataGuardReference struct {
			Link string `json:"link"`
		} `json:"dataGuardReference"`
		CreatedDatetime             time.Time `json:"createdDatetime"`
		DatabaseProtectionReference struct {
			Link string `json:"link"`
		} `json:"databaseProtectionReference"`
		CookieSettingsReference struct {
			Link string `json:"link"`
		} `json:"cookieSettingsReference"`
		CsrfURLReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"csrfUrlReference"`
		VersionLastChange       string `json:"versionLastChange"`
		Name                    string `json:"name"`
		CaseInsensitive         bool   `json:"caseInsensitive"`
		HeaderSettingsReference struct {
			Link string `json:"link"`
		} `json:"headerSettingsReference"`
		SectionReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"sectionReference"`
		FlowReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"flowReference"`
		LoginPageReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"loginPageReference"`
		Description                     string `json:"description"`
		FullPath                        string `json:"fullPath"`
		PolicyBuilderParameterReference struct {
			Link string `json:"link"`
		} `json:"policyBuilderParameterReference"`
		HasParent               bool `json:"hasParent"`
		ThreatCampaignReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"threatCampaignReference"`
		Partition               string `json:"partition"`
		CsrfProtectionReference struct {
			Link string `json:"link"`
		} `json:"csrfProtectionReference"`
		PolicyAntivirusReference struct {
			Link string `json:"link"`
		} `json:"policyAntivirusReference"`
		Kind                         string        `json:"kind"`
		VirtualServers               []interface{} `json:"virtualServers"`
		PolicyBuilderCookieReference struct {
			Link string `json:"link"`
		} `json:"policyBuilderCookieReference"`
		IPIntelligenceReference struct {
			Link string `json:"link"`
		} `json:"ipIntelligenceReference"`
		ProtocolIndependent               bool `json:"protocolIndependent"`
		SessionAwarenessSettingsReference struct {
			Link string `json:"link"`
		} `json:"sessionAwarenessSettingsReference"`
		PolicyBuilderURLReference struct {
			Link string `json:"link"`
		} `json:"policyBuilderUrlReference"`
		PolicyBuilderServerTechnologiesReference struct {
			Link string `json:"link"`
		} `json:"policyBuilderServerTechnologiesReference"`
		PolicyBuilderFiletypeReference struct {
			Link string `json:"link"`
		} `json:"policyBuilderFiletypeReference"`
		SignatureSetReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"signatureSetReference"`
		ParameterReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"parameterReference"`
		ApplicationLanguage       string `json:"applicationLanguage"`
		EnforcementMode           string `json:"enforcementMode"`
		LoginEnforcementReference struct {
			Link string `json:"link"`
		} `json:"loginEnforcementReference"`
		NavigationParameterReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"navigationParameterReference"`
		GwtProfileReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"gwtProfileReference"`
		WhitelistIPReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"whitelistIpReference"`
		HistoryRevisionReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"historyRevisionReference"`
		PolicyBuilderReference struct {
			Link string `json:"link"`
		} `json:"policyBuilderReference"`
		ResponsePageReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"responsePageReference"`
		VulnerabilityAssessmentReference struct {
			Link string `json:"link"`
		} `json:"vulnerabilityAssessmentReference"`
		ServerTechnologyReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"serverTechnologyReference"`
		CookieReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"cookieReference"`
		BlockingSettingReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"blockingSettingReference"`
		HostNameReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"hostNameReference"`
		VersionDeviceName              string `json:"versionDeviceName"`
		SelfLink                       string `json:"selfLink"`
		ThreatCampaignSettingReference struct {
			Link string `json:"link"`
		} `json:"threatCampaignSettingReference"`
		SignatureReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"signatureReference"`
		PolicyBuilderRedirectionProtectionReference struct {
			Link string `json:"link"`
		} `json:"policyBuilderRedirectionProtectionReference"`
		FiletypeReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"filetypeReference"`
		ID                             string        `json:"id"`
		ModifierName                   string        `json:"modifierName"`
		ManualVirtualServers           []interface{} `json:"manualVirtualServers"`
		VersionDatetime                time.Time     `json:"versionDatetime"`
		SubPath                        string        `json:"subPath"`
		SessionTrackingStatusReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"sessionTrackingStatusReference"`
		Active            bool `json:"active"`
		AuditLogReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"auditLogReference"`
		DisallowedGeolocationReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"disallowedGeolocationReference"`
		RedirectionProtectionDomainReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"redirectionProtectionDomainReference"`
		Type                      string `json:"type"`
		SignatureSettingReference struct {
			Link string `json:"link"`
		} `json:"signatureSettingReference"`
		WebsocketURLReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"websocketUrlReference"`
		XMLProfileReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"xmlProfileReference"`
		MethodReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"methodReference"`
		VulnerabilityReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"vulnerabilityReference"`
		RedirectionProtectionReference struct {
			Link string `json:"link"`
		} `json:"redirectionProtectionReference"`
		PolicyBuilderSessionsAndLoginsReference struct {
			Link string `json:"link"`
		} `json:"policyBuilderSessionsAndLoginsReference"`
		TemplateReference struct {
			Link  string `json:"link"`
			Title string `json:"title"`
		} `json:"templateReference"`
		PolicyBuilderHeaderReference struct {
			Link string `json:"link"`
		} `json:"policyBuilderHeaderReference"`
		CreatorName  string `json:"creatorName"`
		URLReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"urlReference"`
		HeaderReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"headerReference"`
		ActionItemReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"actionItemReference"`
		MicroserviceReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"microserviceReference"`
		XMLValidationFileReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"xmlValidationFileReference"`
		LastUpdateMicros     int64 `json:"lastUpdateMicros"`
		JSONProfileReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"jsonProfileReference"`
		BruteForceAttackPreventionReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"bruteForceAttackPreventionReference"`
		DisabledActionItemReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"disabledActionItemReference"`
		ExtractionReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"extractionReference"`
		CharacterSetReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"characterSetReference"`
		SuggestionReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"suggestionReference"`
		IsModified                  bool `json:"isModified"`
		SensitiveParameterReference struct {
			Link            string `json:"link"`
			IsSubCollection bool   `json:"isSubCollection"`
		} `json:"sensitiveParameterReference"`
		GeneralReference struct {
			Link string `json:"link"`
		} `json:"generalReference"`
		VersionPolicyName                          string `json:"versionPolicyName"`
		PolicyBuilderCentralConfigurationReference struct {
			Link string `json:"link"`
		} `json:"policyBuilderCentralConfigurationReference"`
	} `json:"items"`
}

const (
	uriWAF            = "asm"
  uriWAFPolicies    = "policies"
)

//  returns a list of server-ssl profiles.
func (b *BigIP) WAFpolicies() (*WAFpolicies, error) {
	var wAFpolicies WAFpolicies
	err, _ := b.getForEntity(&wAFpolicies, uriWAF, uriWAFPolicies, name)
	if err != nil {
		return nil, err
	}

	return &wAFpolicies, nil
}

// AddServerWAFProfile adds a new WAF profile on the BIG-IP system.
func (b *BigIP) AddWAFpolicy(config *WAFpolicies) error {
	return b.post(config, uriWAF, uriWAFPolicies)
}
