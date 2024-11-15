// Copyright 2024-2025 NetCracker Technology Corporation
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

package dbaas

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/Netcracker/qubership-dbaas-adapter-core/pkg/dao"
	"github.com/Netcracker/qubership-dbaas-adapter-core/pkg/utils"
	"github.com/docker/distribution/uuid"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func Simplstr() string {
	return utils.Substr(uuid.Generate().String(), 0, 7)
}

func TestClient_requestAggregatorVersion(t *testing.T) {
	// logger := utils.GetLogger(true)
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	aggAddress := "http://testdbbaasaggr.com"

	responder, err := httpmock.NewJsonResponder(200, dao.DbaasAggregatorVersion{SupportedMajors: []int{3}})
	if err != nil {
		assert.Fail(t, err.Error())
	}
	httpmock.RegisterResponder("GET", fmt.Sprintf("%s/api-version", aggAddress), responder)
	dbaasClient, err := NewDbaasClient(aggAddress, &dao.BasicAuth{Username: "foo", Password: "bar"}, nil)
	if err != nil {
		assert.Fail(t, err.Error())
	}

	t.Run("Registration failed", func(t *testing.T) {
		httpmock.RegisterResponder("GET", aggAddress, httpmock.NewErrorResponder(fmt.Errorf("anyerror")))

		response, err := dbaasClient.PhysicalDatabaseRegistration("anydbid", "adnydbname", dao.PhysicalDatabaseRegistrationRequest{})

		assert.Empty(t, response)
		assert.Error(t, err)
	})

	t.Run("Health returns 200", func(t *testing.T) {
		httpmock.RegisterResponder("GET", fmt.Sprintf("%s/health", aggAddress), httpmock.NewStringResponder(http.StatusOK, ""))
		assert.True(t, dbaasClient.Health())
	})

	t.Run("Health returns 404", func(t *testing.T) {
		httpmock.RegisterResponder("GET", fmt.Sprintf("%s/health", aggAddress), httpmock.NewStringResponder(http.StatusNotFound, ""))
		assert.False(t, dbaasClient.Health())
	})
}

func TestClient_PhysicalDatabaseRegistration(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	aggAddress := "http://testdbbaasaggr.com"
	responder, err := httpmock.NewJsonResponder(200, dao.DbaasAggregatorVersion{SupportedMajors: []int{3}})
	if err != nil {
		assert.Fail(t, err.Error())
	}
	httpmock.RegisterResponder("GET", fmt.Sprintf("%s/api-version", aggAddress), responder)

	dbaasClient, err := NewDbaasClient(aggAddress, &dao.BasicAuth{Username: "foo", Password: "bar"}, nil)
	if err != nil {
		assert.Fail(t, err.Error())
	}

	t.Run("Registration ok", func(t *testing.T) {
		httpmock.RegisterResponder("PUT", fmt.Sprintf("%s/api/v3/dbaas/anydbid/physical_databases/anydbname", aggAddress), httpmock.NewStringResponder(http.StatusOK, ""))
		response, err := dbaasClient.PhysicalDatabaseRegistration("anydbid", "anydbname", dao.PhysicalDatabaseRegistrationRequest{})

		assert.NoError(t, err)
		assert.NotNil(t, response)
	})

}

func TestClient_PhysicalDatabaseRegistrationRoles(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	aggAddress := "http://testdbbaasaggr.com"

	responder, err := httpmock.NewJsonResponder(200, dao.DbaasAggregatorVersion{SupportedMajors: []int{3}})
	if err != nil {
		assert.Fail(t, err.Error())
	}
	httpmock.RegisterResponder("GET", fmt.Sprintf("%s/api-version", aggAddress), responder)

	id := uuid.Generate().String()
	roleId := uuid.Generate().String()
	dbName := Simplstr()

	dbaasClient, err := NewDbaasClient(aggAddress, &dao.BasicAuth{Username: "foo", Password: "bar"}, nil)
	if err != nil {
		assert.Fail(t, err.Error())
	}

	t.Run("Registration ok", func(t *testing.T) {

		httpmock.RegisterResponder("POST", fmt.Sprintf(`=~.+/api/v3/dbaas/%s/physical_databases/anydbid/instruction/%s/additional-roles`, dbName, id),
			httpmock.NewStringResponder(200, ""))
		response, err := dbaasClient.AdditionalRoles("anydbid", dbName,
			dao.PhysicalDatabaseRoleRequest{},
			dao.Instruction{Id: id,
				AdditionalRoles: []dao.AdditionalRole{
					{Id: roleId,
						DbName: dbName,
						ConnectionProperties: []dao.ConnectionProperties{{
							"role":     "",
							"username": "",
						},
						}},
				}})

		assert.NoError(t, err)
		assert.NotNil(t, response)
	})

}
