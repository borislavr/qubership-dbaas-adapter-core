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

package service

import (
	"context"
	"fmt"

	entity "github.com/Netcracker/qubership-dbaas-adapter-core/pkg/dao"
)

func (srv *PhysicalDatabaseRegistrationService) registerWithRoles() {
	srv.mutex.Lock()
	defer srv.mutex.Unlock()
	roleProcessingStarted := false
	defer func() {
		if r := recover(); r != nil {
			srv.Health = entity.PhysicalDatabaseRegistrationHealth{Status: "WARNING"}
			if roleProcessingStarted {
				panic(r)
			}
			if srv.client.Health() {
				srv.logger.Info("Aggregator is healthy")
				panic(r)
			} else {
				srv.logger.Info("Aggregator is not healthy")
				srv.logger.Error(fmt.Sprintf("%v", r))
			}
		} else {
			srv.Health = entity.PhysicalDatabaseRegistrationHealth{Status: "OK"}
		}
		srv.status = entity.StatusRun
	}()

	resp := srv.sendRegisterRequest()
	roleProcessingStarted = true
	if len(resp.Instruction.AdditionalRoles) > 0 {
		srv.performAdditionalRoles(resp.Instruction)
	}
	srv.logger.Info("Registration finished")
}

func (srv *PhysicalDatabaseRegistrationService) performAdditionalRoles(instruction entity.Instruction) {
	additionalRoles := instruction.AdditionalRoles
	var err error
	srv.logger.Info("Start processing additional roles")
	for len(additionalRoles) > 0 {
		success, failure := srv.administrationService.CreateRoles(context.Background(), additionalRoles)
		result := entity.PhysicalDatabaseRoleRequest{
			Success: success,
			Failure: failure,
		}

		additionalRoles, err = srv.client.AdditionalRoles(srv.phydbid, srv.dbName, result, instruction)
		if failure != nil {
			panic(fmt.Errorf("Failed to create additional roles. Error message: %s", failure.Message))
		}
		if err != nil {
			panic(fmt.Errorf("Failed to create additional roles. err: %v", err))
		}
	}
}

func (srv *PhysicalDatabaseRegistrationService) modifyReqParams(request *entity.PhysicalDatabaseRegistrationRequest) {
	dbaasApiVersion := srv.administrationService.GetVersion()

	if dbaasApiVersion == "v2" {
		request.Metadata = entity.Metadata{
			ApiVersion: dbaasApiVersion,
			ApiVersions: entity.ApiVersions{Specs: []entity.ApiVersionsSpec{
				{
					SpecRootUrl:     entity.RootUrl,
					Major:           entity.MajorAPIVersion,
					Minor:           entity.MinorAPIVersion,
					SupportedMajors: entity.SupportedMajorsVersions,
				},
			}},
			SupportedRoles: srv.administrationService.GetSupportedRoles(),
			Features:       srv.administrationService.GetFeatures(),
			ROHost:         srv.administrationService.GetROHost(),
		}
		request.Status = srv.status
	}
}
