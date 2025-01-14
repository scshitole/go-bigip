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
)

// WAF Policies  on the BIG-IP system.
type WAFpolicies struct {
	WAFpolicies []WAFpolicy `json:"items"`
}

type WAFpolicy struct {
	Kind                      string   `json:"kind"`
	SelfLink                  string   `json:"selfLink"`
	TotalItems                int      `json:"totalItems"`
	Items                     []string `json:"items,omitempty"`
	Name                      string   `json:"name"`
	PolicyID                  string   `json:"id"`
	PlainTextProfileReference struct {
		Link            string `json:"link"`
		IsSubCollection bool   `json:"isSubCollection"`
	}
	ParameterReference struct {
		Link            string `json:"link"`
		IsSubCollection bool   `json:"isSubCollection"`
	}
}

const (
	uriWAF         = "asm"
	uriWAFPolicies = "policies"
	uriParameters  = "parameters"
	uriFiletype  = "filetypes"
)

//  returns a list of WAF .
func (b *BigIP) WAFpolicies() (*WAFpolicies, error) {
	var wAFpolicies WAFpolicies
	err, _ := b.getForEntity(&wAFpolicies, uriWAF, uriWAFPolicies)
	if err != nil {
		return nil, err
	}

	return &wAFpolicies, nil
}

// WAF adds a new WAF profile on the BIG-IP system.
func (b *BigIP) AddWAFpolicy(config *WAFpolicies) error {
	return b.post(config, uriWAF, uriWAFPolicies)
}

func (b *BigIP) Readpolicyparameters(name string) (*WAFpolicies, error) {
	var wAFpolicies WAFpolicies
	err, _ := b.getForEntity(&wAFpolicies, uriWAF, uriWAFPolicies, name, uriParameters)
	if err != nil {
		return nil, err
	}

	return &wAFpolicies, nil
}

func (b *BigIP) Readfiletypes(name string) (*WAFpolicies, error) {
	var wAFpolicies WAFpolicies
	err, _ := b.getForEntity(&wAFpolicies, uriWAF, uriWAFPolicies, name, uriFiletype)
	if err != nil {
		return nil, err
	}

	return &wAFpolicies, nil
}
