//(C) Copyright [2020] Hewlett Packard Enterprise Development LP
//(C) Copyright 2020 Intel Corporation
//
//Licensed under the Apache License, Version 2.0 (the "License"); you may
//not use this file except in compliance with the License. You may obtain
//a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
//License for the specific language governing permissions and limitations
// under the License.

// Package router ...
package router

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/ODIM-Project/ODIM/lib-utilities/common"
	"github.com/ODIM-Project/ODIM/lib-utilities/config"
	customLogs "github.com/ODIM-Project/ODIM/lib-utilities/logs"
	l "github.com/ODIM-Project/ODIM/lib-utilities/logs"
	loggingService "github.com/ODIM-Project/ODIM/lib-utilities/logservice"
	"github.com/ODIM-Project/ODIM/lib-utilities/response"
	srv "github.com/ODIM-Project/ODIM/lib-utilities/services"
	"github.com/ODIM-Project/ODIM/svc-api/handle"
	"github.com/ODIM-Project/ODIM/svc-api/middleware"
	"github.com/ODIM-Project/ODIM/svc-api/ratelimiter"
	"github.com/ODIM-Project/ODIM/svc-api/rpc"
	"github.com/kataras/iris/v12"
)

var isCompositionEnabled bool
var cs handle.CompositionServiceRPCs

const (
	sessionsURI               = "/Sessions"
	sessionsIDURI             = "/Sessions/{sessionID}"
	accountsURI               = "/Accounts"
	accountsIDURI             = "/Accounts/{id}"
	rolesIDURI                = "/Roles/{id}"
	taskIDURI                 = "/Tasks/{TaskID}"
	ethernetInterfaceURI      = "/{id}/EthernetInterfaces"
	ethernetInterfaceIDURI    = "/{id}/EthernetInterfaces/{rid}"
	secureBootURI             = "/{id}/SecureBoot"
	logServiceURI             = "/{id}/LogServices"
	logServiceIDURI           = "/{id}/LogServices/{rid}"
	logServiceEntriesURI      = "/{id}/LogServices/{rid}/Entries"
	logServiceEntriesIDURI    = "/{id}/LogServices/{rid}/Entries/{rid2}"
	logServiceActionURI       = "/{id}/LogServices/{rid}/Actions/LogService.ClearLog"
	pcieDevicesIDURI          = "/{id}/PCIeDevices/{rid}"
	volumesURI                = "/{id2}/Volumes"
	volumesIDURI              = "/{id2}/Volumes/{rid}"
	aggregationSourceIDURI    = "/AggregationSources/{id}"
	aggregatesURI             = "/Aggregates/"
	subscriptionURI           = "/Subscriptions"
	switchPortIDURI           = "/{id}/Switches/{switchID}/Ports/{port_uuid}"
	zoneIDURI                 = "/{id}/Zones/{zone_uuid}"
	endpointsIDURI            = "/{id}/Endpoints/{endpoint_uuid}"
	addressPoolIDURI          = "/{id}/AddressPools/{addresspool_uuid}"
	remoteAccountServiceURI   = "/{id}/RemoteAccountService/Accounts"
	remoteAccountServiceIDURI = "/{id}/RemoteAccountService/Accounts/{rid}"
	triggersIDURI             = "/Triggers/{id}"
	licensesURI               = "/Licenses"
	resourceBlockURI          = "/ResourceBlocks"
	resourceBlockIDURI        = "/ResourceBlocks/{id}"
	resourceZonesURI          = "/ResourceZones"
	resourceZonesIDURI        = "/ResourceZones/{id}"
)

// Router method to register API handlers.
func Router() *iris.Application {
	r := handle.RoleRPCs{
		GetAllRolesRPC: rpc.GetAllRoles,
		GetRoleRPC:     rpc.GetRole,
		UpdateRoleRPC:  rpc.UpdateRole,
		DeleteRoleRPC:  rpc.DeleteRole,
	}
	a := handle.AccountRPCs{
		GetServiceRPC:     rpc.DoGetAccountServiceRequest,
		CreateRPC:         rpc.DoAccountCreationRequest,
		GetAllAccountsRPC: rpc.DoGetAllAccountRequest,
		GetAccountRPC:     rpc.DoGetAccountRequest,
		UpdateRPC:         rpc.DoUpdateAccountRequest,
		DeleteRPC:         rpc.DoAccountDeleteRequest,
	}
	pc := handle.AggregatorRPCs{
		GetAggregationServiceRPC:                rpc.DoGetAggregationService,
		ResetRPC:                                rpc.DoResetRequest,
		SetDefaultBootOrderRPC:                  rpc.DoSetDefaultBootOrderRequest,
		AddAggregationSourceRPC:                 rpc.DoAddAggregationSource,
		GetAllAggregationSourceRPC:              rpc.DoGetAllAggregationSource,
		GetAggregationSourceRPC:                 rpc.DoGetAggregationSource,
		UpdateAggregationSourceRPC:              rpc.DoUpdateAggregationSource,
		DeleteAggregationSourceRPC:              rpc.DoDeleteAggregationSource,
		CreateAggregateRPC:                      rpc.DoCreateAggregate,
		GetAggregateCollectionRPC:               rpc.DoGetAggregateCollection,
		GetAggregateRPC:                         rpc.DoGeteAggregate,
		DeleteAggregateRPC:                      rpc.DoDeleteAggregate,
		AddElementsToAggregateRPC:               rpc.DoAddElementsToAggregate,
		RemoveElementsFromAggregateRPC:          rpc.DoRemoveElementsFromAggregate,
		ResetAggregateElementsRPC:               rpc.DoResetAggregateElements,
		SetDefaultBootOrderAggregateElementsRPC: rpc.DoSetDefaultBootOrderAggregateElements,
		GetAllConnectionMethodsRPC:              rpc.DoGetAllConnectionMethods,
		GetConnectionMethodRPC:                  rpc.DoGetConnectionMethod,
		GetResetActionInfoServiceRPC:            rpc.DoGetResetActionInfoService,
		GetSetDefaultBootOrderActionInfoRPC:     rpc.DoGetSetDefaultBootOrderActionInfo,
	}

	s := handle.SessionRPCs{
		CreateSessionRPC:        rpc.DoSessionCreationRequest,
		DeleteSessionRPC:        rpc.DeleteSessionRequest,
		GetSessionRPC:           rpc.GetSessionRequest,
		GetAllActiveSessionsRPC: rpc.GetAllActiveSessionRequest,
		GetSessionServiceRPC:    rpc.GetSessionServiceRequest,
	}

	ts := handle.TaskRPCs{
		DeleteTaskRPC:     rpc.DeleteTaskRequest,
		GetTaskRPC:        rpc.GetTaskRequest,
		GetSubTasksRPC:    rpc.GetSubTasks,
		GetSubTaskRPC:     rpc.GetSubTask,
		GetTaskMonitorRPC: rpc.GetTaskMonitor,
		TaskCollectionRPC: rpc.TaskCollection,
		GetTaskServiceRPC: rpc.GetTaskService,
	}

	system := handle.SystemRPCs{
		GetSystemsCollectionRPC:    rpc.GetSystemsCollection,
		GetSystemRPC:               rpc.GetSystemRequestRPC,
		GetSystemResourceRPC:       rpc.GetSystemResource,
		SystemResetRPC:             rpc.ComputerSystemReset,
		SetDefaultBootOrderRPC:     rpc.SetDefaultBootOrder,
		ChangeBiosSettingsRPC:      rpc.ChangeBiosSettings,
		ChangeBootOrderSettingsRPC: rpc.ChangeBootOrderSettings,
		CreateVolumeRPC:            rpc.CreateVolume,
		DeleteVolumeRPC:            rpc.DeleteVolume,
		UpdateSecureBootRPC:        rpc.UpdateSecureBoot,
		ResetSecureBootRPC:         rpc.ResetSecureBoot,
	}

	cha := handle.ChassisRPCs{
		GetChassisCollectionRPC: rpc.GetChassisCollection,
		GetChassisResourceRPC:   rpc.GetChassisResource,
		GetChassisRPC:           rpc.GetChassis,
		CreateChassisRPC:        rpc.CreateChassis,
		DeleteChassisRPC:        rpc.DeleteChassis,
		UpdateChassisRPC:        rpc.UpdateChassis,
	}

	evt := handle.EventsRPCs{
		GetEventServiceRPC:                 rpc.DoGetEventService,
		CreateEventSubscriptionRPC:         rpc.DoCreateEventSubscription,
		SubmitTestEventRPC:                 rpc.DoSubmitTestEvent,
		GetEventSubscriptionRPC:            rpc.DoGetEventSubscription,
		DeleteEventSubscriptionRPC:         rpc.DoDeleteEventSubscription,
		GetEventSubscriptionsCollectionRPC: rpc.DoGetEventSubscriptionsCollection,
	}

	fab := handle.FabricRPCs{
		GetFabricResourceRPC:    rpc.GetFabricResource,
		UpdateFabricResourceRPC: rpc.UpdateFabricResource,
		DeleteFabricResourceRPC: rpc.DeleteFabricResource,
	}

	manager := handle.ManagersRPCs{
		GetManagersCollectionRPC:      rpc.GetManagersCollection,
		GetManagersRPC:                rpc.GetManagers,
		GetManagersResourceRPC:        rpc.GetManagersResource,
		VirtualMediaInsertRPC:         rpc.VirtualMediaInsert,
		VirtualMediaEjectRPC:          rpc.VirtualMediaEject,
		GetRemoteAccountServiceRPC:    rpc.GetRemoteAccountService,
		CreateRemoteAccountServiceRPC: rpc.CreateRemoteAccountService,
		UpdateRemoteAccountServiceRPC: rpc.UpdateRemoteAccountService,
		DeleteRemoteAccountServiceRPC: rpc.DeleteRemoteAccountService,
	}

	update := handle.UpdateRPCs{
		GetUpdateServiceRPC:               rpc.DoGetUpdateService,
		SimpleUpdateRPC:                   rpc.DoSimpleUpdate,
		StartUpdateRPC:                    rpc.DoStartUpdate,
		GetFirmwareInventoryRPC:           rpc.DoGetFirmwareInventory,
		GetFirmwareInventoryCollectionRPC: rpc.DoGetFirmwareInventoryCollection,
		GetSoftwareInventoryRPC:           rpc.DoGetSoftwareInventory,
		GetSoftwareInventoryCollectionRPC: rpc.DoGetSoftwareInventoryCollection,
	}

	telemetry := handle.TelemetryRPCs{
		GetTelemetryServiceRPC:                 rpc.DoGetTelemetryService,
		GetMetricDefinitionCollectionRPC:       rpc.DoGetMetricDefinitionCollection,
		GetMetricReportDefinitionCollectionRPC: rpc.DoGetMetricReportDefinitionCollection,
		GetMetricReportCollectionRPC:           rpc.DoGetMetricReportCollection,
		GetTriggerCollectionRPC:                rpc.DoGetTriggerCollection,
		GetMetricDefinitionRPC:                 rpc.DoGetMetricDefinition,
		GetMetricReportDefinitionRPC:           rpc.DoGetMetricReportDefinition,
		GetMetricReportRPC:                     rpc.DoGetMetricReport,
		GetTriggerRPC:                          rpc.DoGetTrigger,
		UpdateTriggerRPC:                       rpc.DoUpdateTrigger,
	}

	for _, service := range config.Data.EnabledServices {
		if service == "CompositionService" {
			isCompositionEnabled = true
		}
	}

	if isCompositionEnabled {
		cs = handle.CompositionServiceRPCs{
			GetCompositionServiceRPC:      rpc.GetCompositionService,
			GetResourceBlockCollectionRPC: rpc.GetResourceBlockCollection,
			GetResourceBlockRPC:           rpc.GetResourceBlock,
			CreateResourceBlockRPC:        rpc.CreateResourceBlock,
			DeleteResourceBlockRPC:        rpc.DeleteResourceBlock,
			GetResourceZoneCollectionRPC:  rpc.GetResourceZoneCollection,
			GetResourceZoneRPC:            rpc.GetResourceZone,
			CreateResourceZoneRPC:         rpc.CreateResourceZone,
			DeleteResourceZoneRPC:         rpc.DeleteResourceZone,
			ComposeRPC:                    rpc.Compose,
			GetActivePoolRPC:              rpc.GetActivePool,
			GetFreePoolRPC:                rpc.GetFreePool,
			GetCompositionReservationsRPC: rpc.GetCompositionReservations,
		}
	}

	licenses := handle.LicenseRPCs{
		GetLicenseServiceRPC:     rpc.GetLicenseService,
		GetLicenseCollectionRPC:  rpc.GetLicenseCollection,
		GetLicenseResourceRPC:    rpc.GetLicenseResource,
		InstallLicenseServiceRPC: rpc.InstallLicenseService,
	}

	registryFile := handle.Registry{
		Auth: srv.IsAuthorized,
	}
	logService := l.Logging{
		GetUserDetails: loggingService.GetUserDetails,
	}

	serviceRoot := handle.InitServiceRoot()

	router := iris.New()
	router.OnErrorCode(iris.StatusNotFound, handle.SystemsMethodInvalidURI)
	// Parses the URL and performs URL decoding for path
	// Getting the request body copy
	router.WrapRouter(func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		ctx := r.Context()
		rawURI := r.RequestURI
		parsedURI, err := url.Parse(rawURI)
		if err != nil {
			errMessage := "while trying to parse the URL: " + err.Error()
			l.LogWithFields(ctx).Error(errMessage)
			return
		}
		path := strings.Replace(rawURI, parsedURI.EscapedPath(), parsedURI.Path, -1)
		r.RequestURI = path
		r.URL.Path = parsedURI.Path
		var reqBody map[string]interface{}

		// Validating session token
		sessionToken := r.Header.Get("X-Auth-Token")
		if sessionToken == "" {
			authRequired := true
			for _, item := range common.URIWithNoAuth {
				if item == r.URL.Path {
					authRequired = false
					break
				}
			}
			if r.URL.Path == common.SessionURI && r.Method == http.MethodGet {
				authRequired = true
			}
			if authRequired {
				ctx = context.WithValue(ctx, common.SessionToken, sessionToken)
				ctx = context.WithValue(ctx, common.StatusCode, int32(http.StatusUnauthorized))
				customLogs.AuthLog(ctx).Info("X-Auth-Token is missing in the request header")
			}
		}

		// getting the request body for audit logs
		if r.Body != nil {
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				l.LogWithFields(ctx).Error("while reading request body ", err.Error())
			}
			r.Body = ioutil.NopCloser(bytes.NewReader(body))

			if len(body) > 0 {
				err = json.Unmarshal(body, &reqBody)
				if err != nil {
					l.LogWithFields(ctx).Error("while unmarshalling request body", err.Error())
				}
			}
		}
		if config.Data.RequestLimitCountPerSession > 0 {
			err = ratelimiter.RequestRateLimiter(ctx, sessionToken)
			if err != nil {
				common.SetCommonHeaders(w)
				w.WriteHeader(http.StatusServiceUnavailable)
				body, _ := json.Marshal(common.GeneralError(http.StatusServiceUnavailable, response.GeneralError, err.Error(), nil, nil).Body)
				w.Write([]byte(body))
				return
			}
		}
		next(w, r)

	})
	router.Done(func(ctx iris.Context) {
		var reqBody map[string]interface{}
		ctxt := ctx.Request().Context()
		if ctxt.Value(common.RequestBody) != nil {
			reqBody = ctxt.Value(common.RequestBody).(map[string]interface{})
		}
		l.AuditLog(&logService, ctx, reqBody).Info()
		// before returning response, decrement the session limit counter
		sessionToken := ctx.Request().Header.Get("X-Auth-Token")
		if sessionToken != "" && config.Data.RequestLimitCountPerSession > 0 {
			ratelimiter.DecrementCounter(sessionToken, ratelimiter.SessionRateLimit)
		}
	})
	taskmon := router.Party("/taskmon")
	taskmon.SetRegisterRule(iris.RouteSkip)
	taskmon.Get("/{TaskID}", ts.GetTaskMonitor)
	taskmon.Any("/{TaskID}", handle.TsMethodNotAllowed)

	redfish := router.Party("/redfish")
	redfish.SetRegisterRule(iris.RouteSkip)
	redfish.Get("/", handle.GetVersion)

	v1 := redfish.Party("/v1")
	v1.SetRegisterRule(iris.RouteSkip)
	v1.Get("/", serviceRoot.GetServiceRoot)
	v1.Get("/odata", handle.GetOdata)
	v1.Get("/$metadata", handle.GetMetadata)
	v1.Any("/", handle.SRMethodNotAllowed)
	v1.Any("/odata", handle.SRMethodNotAllowed)
	v1.Any("/$metadata", handle.SRMethodNotAllowed)

	registry := v1.Party("/Registries")
	registry.SetRegisterRule(iris.RouteSkip)
	registry.Get("/", registryFile.GetRegistryFileCollection)
	registry.Get("/{id}", registryFile.GetMessageRegistryFileID)
	registry.Any("/", handle.RegMethodNotAllowed)
	registry.Any("/{id}", handle.RegMethodNotAllowed)

	session := v1.Party("/SessionService")
	session.SetRegisterRule(iris.RouteSkip)
	session.Get("/", s.GetSessionService)
	session.Get(sessionsURI, middleware.SessionDelMiddleware, s.GetAllActiveSessions)
	session.Get(sessionsIDURI, middleware.SessionDelMiddleware, s.GetSession)
	session.Post(sessionsURI, s.CreateSession)
	session.Delete(sessionsIDURI, middleware.SessionDelMiddleware, s.DeleteSession)
	session.Any("/", handle.SsMethodNotAllowed)
	session.Any(sessionsURI, handle.SsMethodNotAllowed)
	session.Any(sessionsIDURI, handle.SsMethodNotAllowed)

	account := v1.Party("/AccountService", middleware.SessionDelMiddleware)
	account.SetRegisterRule(iris.RouteSkip)
	account.Get("/", a.GetAccountService)
	account.Get(accountsURI, a.GetAllAccounts)
	account.Get(accountsIDURI, a.GetAccount)
	account.Post(accountsURI, a.CreateAccount)
	account.Patch(accountsIDURI, a.UpdateAccount)
	account.Delete(accountsIDURI, a.DeleteAccount)
	account.Any("/", handle.AsMethodNotAllowed)
	account.Any(accountsURI, handle.AsMethodNotAllowed)
	account.Any(accountsIDURI, handle.AsMethodNotAllowed)
	account.Get("/Roles/", r.GetAllRoles)
	account.Get(rolesIDURI, r.GetRole)
	account.Patch(rolesIDURI, r.UpdateRole)
	account.Delete(rolesIDURI, r.DeleteRole)
	account.Any("/Roles", handle.RoleMethodNotAllowed)
	account.Any("Roles/{id}", handle.RoleMethodNotAllowed)

	task := v1.Party("/TaskService", middleware.SessionDelMiddleware)
	task.SetRegisterRule(iris.RouteSkip)
	task.Get("/", ts.GetTaskService)
	task.Get("/Tasks", ts.TaskCollection)
	task.Get(taskIDURI, ts.GetTaskStatus)
	task.Get("/Tasks/{TaskID}/SubTasks", ts.GetSubTasks)
	task.Get("/Tasks/{TaskID}/SubTasks/{subTaskID}", ts.GetSubTask)
	task.Delete(taskIDURI, ts.DeleteTask)
	task.Any("/", handle.TsMethodNotAllowed)
	task.Any("/Tasks", handle.TsMethodNotAllowed)
	task.Any(taskIDURI, handle.TsMethodNotAllowed)
	task.Any("/Tasks/{TaskID}/SubTasks", handle.TsMethodNotAllowed)
	task.Any("/Tasks/{TaskID}/SubTasks/{subTaskID}", handle.TsMethodNotAllowed)

	systems := v1.Party("/Systems", middleware.SessionDelMiddleware)
	systems.SetRegisterRule(iris.RouteSkip)
	systems.Get("/", system.GetSystemsCollection)
	systems.Get("/{id}", system.GetSystem)
	systems.Get("/{id}/Processors", system.GetSystemResource)
	systems.Get("/{id}/Processors/{rid}", system.GetSystemResource)
	systems.Get("/{id}/Memory", system.GetSystemResource)
	systems.Get("/{id}/Memory/{rid}", system.GetSystemResource)
	systems.Get("/{id}/NetworkInterfaces", system.GetSystemResource)
	systems.Get("/{id}/NetworkInterfaces/{rid}", system.GetSystemResource)
	systems.Get("/{id}/MemoryDomains", system.GetSystemResource)
	systems.Get(ethernetInterfaceURI, system.GetSystemResource)
	systems.Get(ethernetInterfaceIDURI, system.GetSystemResource)
	systems.Get("/{id}/EthernetInterfaces/{id2}/VLANS", system.GetSystemResource)
	systems.Get("/{id}/EthernetInterfaces/{id2}/VLANS/{rid}", system.GetSystemResource)
	systems.Get(secureBootURI, system.GetSystemResource)
	systems.Patch(secureBootURI, system.UpdateSecureBoot)
	systems.Post("/{id}/SecureBoot/Actions/SecureBoot.ResetKeys", system.ResetSecureBoot)
	systems.Get("/{id}/SecureBoot/SecureBootDatabases", system.GetSystemResource)
	systems.Get("/{id}/SecureBoot/SecureBootDatabases/{rid}", system.GetSystemResource)
	systems.Get("/{id}/SecureBoot/SecureBootDatabases/{rid}/Certificates", system.GetSystemResource)
	systems.Get("/{id}/SecureBoot/SecureBootDatabases/{rid}/Certificates/{rid2}", system.GetSystemResource)
	systems.Get("/{id}/SecureBoot/SecureBootDatabases/{rid}/Signatures", system.GetSystemResource)
	systems.Get("/{id}/SecureBoot/SecureBootDatabases/{rid}/Signatures/{rid2}", system.GetSystemResource)
	systems.Get("/{id}/BootOptions", system.GetSystemResource)
	systems.Get("/{id}/BootOptions/{rid}", system.GetSystemResource)
	systems.Get(logServiceURI, system.GetSystemResource)
	systems.Get(logServiceIDURI, system.GetSystemResource)
	systems.Get(logServiceEntriesURI, ratelimiter.ResourceRateLimiter, system.GetSystemResource)
	systems.Get(logServiceEntriesIDURI, ratelimiter.ResourceRateLimiter, system.GetSystemResource)
	systems.Post(logServiceActionURI, system.GetSystemResource)
	systems.Patch("/{id}", system.ChangeBootOrderSettings)
	systems.Get(pcieDevicesIDURI, system.GetSystemResource)
	systems.Any(pcieDevicesIDURI, handle.SystemsMethodNotAllowed)
	systems.Any("/", handle.SystemsMethodNotAllowed)
	systems.Any("/{id}", handle.SystemsMethodNotAllowed)
	systems.Any(ethernetInterfaceURI, handle.SystemsMethodNotAllowed)
	systems.Any(ethernetInterfaceIDURI, handle.SystemsMethodNotAllowed)
	systems.Any(secureBootURI, handle.SystemsMethodNotAllowed)
	systems.Any("/{id}/SecureBoot/Actions/SecureBoot.ResetKeys", handle.SystemsMethodNotAllowed)
	systems.Any("/{id}/SecureBoot/SecureBootDatabases", handle.SystemsMethodNotAllowed)
	systems.Any("/{id}/SecureBoot/SecureBootDatabases/{rid}", handle.SystemsMethodNotAllowed)
	systems.Any("/{id}/SecureBoot/SecureBootDatabases/{rid}/Certificates", handle.SystemsMethodNotAllowed)
	systems.Any("/{id}/SecureBoot/SecureBootDatabases/{rid}/Certificates/{rid2}", handle.SystemsMethodNotAllowed)
	systems.Any("/{id}/SecureBoot/SecureBootDatabases/{rid}/Signatures", handle.SystemsMethodNotAllowed)
	systems.Any("/{id}/SecureBoot/SecureBootDatabases/{rid}/Signatures/{rid2}", handle.SystemsMethodNotAllowed)
	systems.Any("/{id}/MemoryDomains", handle.SystemsMethodNotAllowed)
	systems.Any("/{id}/NetworkInterfaces", handle.SystemsMethodNotAllowed)
	systems.Any("/{id}/Memory", handle.SystemsMethodNotAllowed)
	systems.Any("/{id}/Processors", handle.SystemsMethodNotAllowed)
	systems.Any("/{id}/BootOptions", handle.SystemsMethodNotAllowed)
	systems.Any("/{id}/BootOptions/{rid}", handle.SystemsMethodNotAllowed)
	systems.Any(logServiceURI, handle.SystemsMethodNotAllowed)
	systems.Any(logServiceIDURI, handle.SystemsMethodNotAllowed)
	systems.Any(logServiceEntriesURI, handle.SystemsMethodNotAllowed)
	systems.Any(logServiceEntriesIDURI, handle.SystemsMethodNotAllowed)
	systems.Any("/{id}/LogServices/{rid}/Actions", handle.SystemsMethodNotAllowed)
	systems.Any(logServiceActionURI, handle.SystemsMethodNotAllowed)

	systems.Get("/{id}/Bios", system.GetSystemResource)
	systems.Get("/{id}/Bios/Settings", system.GetSystemResource)
	systems.Patch("/{id}/Bios/Settings", system.ChangeBiosSettings)
	systems.Any("/{id}/Bios", handle.SystemsMethodNotAllowed)
	systems.Any("/{id}/Processors/{rid}", handle.SystemsMethodNotAllowed)
	systems.Any("{id}/Bios/Settings/Actions/Bios.ChangePasswords", handle.SystemsMethodNotAllowed)
	systems.Any("{id}/Bios/Settings/Actions/Bios.ResetBios/", handle.SystemsMethodNotAllowed)
	systems.Any("/{id}/Memory/{rid}", handle.SystemsMethodNotAllowed)
	systems.Post("/{id}/Actions/ComputerSystem.Reset", system.ComputerSystemReset)
	systems.Post("/{id}/Actions/ComputerSystem.SetDefaultBootOrder", system.SetDefaultBootOrder)

	storage := v1.Party("/Systems/{id}/Storage", middleware.SessionDelMiddleware)
	storage.SetRegisterRule(iris.RouteSkip)
	storage.Get("/", system.GetSystemResource)
	storage.Get("/{rid}", system.GetSystemResource)
	storage.Get("/{id2}/Drives/{rid}", system.GetSystemResource)
	storage.Get("/{id2}/Controllers", system.GetSystemResource)
	storage.Get("/{id2}/Controllers/{rid}", system.GetSystemResource)
	storage.Get("/{id2}/Controllers/{rid}/Ports", system.GetSystemResource)
	storage.Get("/{id2}/Controllers/{rid}/Ports/{portID}", system.GetSystemResource)
	storage.Get(volumesURI, system.GetSystemResource)
	storage.Post(volumesURI, system.CreateVolume)
	storage.Get("/{id2}/Volumes/Capabilities", system.GetSystemResource)

	storage.Delete(volumesIDURI, system.DeleteVolume)
	storage.Get(volumesIDURI, system.GetSystemResource)
	storage.Any("/", handle.SystemsMethodNotAllowed)
	storage.Any("/{id2}/Drives/{rid}", handle.SystemsMethodNotAllowed)
	storage.Any("/{rid}", handle.SystemsMethodNotAllowed)
	storage.Any(volumesURI, handle.SystemsMethodNotAllowed)
	storage.Any(volumesIDURI, handle.SystemsMethodNotAllowed)
	storage.Get("/{rid}/StoragePools", system.GetSystemResource)
	storage.Get("/{id2}/StoragePools/{rid}", system.GetSystemResource)
	storage.Any("/{rid}/StoragePools", handle.SystemsMethodNotAllowed)
	storage.Any("/{id2}/StoragePools/{rid}", handle.SystemsMethodNotAllowed)
	storage.Get("/{id2}/StoragePools/{rid}/AllocatedVolumes", system.GetSystemResource)
	storage.Any("/{id2}/StoragePools/{rid}/AllocatedVolumes", handle.SystemsMethodNotAllowed)
	storage.Get("/{id2}/StoragePools/{id3}/AllocatedVolumes/{rid}", system.GetSystemResource)
	storage.Any("/{id2}/StoragePools/{id3}/AllocatedVolumes/{rid}", handle.SystemsMethodNotAllowed)
	storage.Get("/{id2}/StoragePools/{id3}/CapacitySources/{rid}/ProvidingVolumes", system.GetSystemResource)
	storage.Any("/{id2}/StoragePools/{id3}/CapacitySources/{rid}/ProvidingVolumes", handle.SystemsMethodNotAllowed)
	storage.Get("/{id2}/StoragePools/{id3}/CapacitySources/{id4}/ProvidingVolumes/{rid}", system.GetSystemResource)
	storage.Any("/{id2}/StoragePools/{id3}/CapacitySources/{id4}/ProvidingVolumes/{rid}", handle.SystemsMethodNotAllowed)
	storage.Get("/{id2}/StoragePools/{id3}/CapacitySources/{rid}/ProvidingDrives", system.GetSystemResource)
	storage.Any("/{id2}/StoragePools/{id3}/CapacitySources/{rid}/ProvidingDrives", handle.SystemsMethodNotAllowed)

	aggregation := v1.Party("/AggregationService", middleware.SessionDelMiddleware)
	aggregation.SetRegisterRule(iris.RouteSkip)
	aggregation.Get("/", pc.GetAggregationService)
	aggregation.Get("/ResetActionInfo", pc.GetResetActionInfoService)
	aggregation.Get("/SetDefaultBootOrderActionInfo", pc.GetSetDefaultBootOrderActionInfo)
	aggregation.Post("/Actions/AggregationService.Reset/", pc.Reset)
	aggregation.Any("/Actions/AggregationService.Reset/", handle.AggMethodNotAllowed)
	aggregation.Post("/Actions/AggregationService.SetDefaultBootOrder/", pc.SetDefaultBootOrder)
	aggregation.Any("/Actions/AggregationService.SetDefaultBootOrder/", handle.AggMethodNotAllowed)
	aggregation.Post("/AggregationSources/", pc.AddAggregationSource)
	aggregation.Get("/AggregationSources", pc.GetAllAggregationSource)
	aggregation.Any("/AggregationSources", handle.AggMethodNotAllowed)
	aggregation.Get(aggregationSourceIDURI, pc.GetAggregationSource)
	aggregation.Patch(aggregationSourceIDURI, pc.UpdateAggregationSource)
	aggregation.Delete(aggregationSourceIDURI, pc.DeleteAggregationSource)
	aggregation.Any(aggregationSourceIDURI, handle.AggMethodNotAllowed)
	aggregation.Get("/ConnectionMethods/", pc.GetAllConnectionMethods)
	aggregation.Get("/ConnectionMethods/{id}", pc.GetConnectionMethod)
	aggregation.Any("/ConnectionMethods/", handle.AggMethodNotAllowed)
	aggregation.Any("/ConnectionMethods/{id}", handle.AggMethodNotAllowed)
	aggregation.Post(aggregatesURI, pc.CreateAggregate)
	aggregation.Get(aggregatesURI, pc.GetAggregateCollection)
	aggregation.Any(aggregatesURI, handle.AggregateMethodNotAllowed)
	aggregation.Get("/Aggregates//{id}", pc.GetAggregate)
	aggregation.Delete("/Aggregates//{id}", pc.DeleteAggregate)
	aggregation.Any("/Aggregates/{id}", handle.AggregateMethodNotAllowed)
	aggregation.Post("/Aggregates/{id}/Actions/Aggregate.AddElements/", pc.AddElementsToAggregate)
	aggregation.Any("/Aggregates/{id}/Actions/Aggregate.AddElements/", handle.AggregateMethodNotAllowed)
	aggregation.Post("/Aggregates/{id}/Actions/Aggregate.RemoveElements/", pc.RemoveElementsFromAggregate)
	aggregation.Any("/Aggregates/{id}/Actions/Aggregate.RemoveElements/", handle.AggregateMethodNotAllowed)
	aggregation.Post("/Aggregates/{id}/Actions/Aggregate.Reset/", pc.ResetAggregateElements)
	aggregation.Any("/Aggregates/{id}/Actions/Aggregate.Reset/", handle.AggregateMethodNotAllowed)
	aggregation.Post("/Aggregates/{id}/Actions/Aggregate.SetDefaultBootOrder/", pc.SetDefaultBootOrderAggregateElements)
	aggregation.Any("/Aggregates/{id}/Actions/Aggregate.SetDefaultBootOrder/", handle.AggregateMethodNotAllowed)
	aggregation.Any("/", handle.AggMethodNotAllowed)

	chassis := v1.Party("/Chassis", middleware.SessionDelMiddleware)
	chassis.SetRegisterRule(iris.RouteSkip)
	chassis.Get("/", cha.GetChassisCollection)
	chassis.Post("/", cha.CreateChassis)
	chassis.Get("/{id}", cha.GetChassis)
	chassis.Patch("/{id}", cha.UpdateChassis)
	chassis.Delete("/{id}", cha.DeleteChassis)
	chassis.Get("/{id}/NetworkAdapters", cha.GetChassisResource)
	chassis.Get("/{id}/NetworkAdapters/{rid}", cha.GetChassisResource)
	chassis.Get("/{id}/NetworkAdapters/{id2}/NetworkDeviceFunctions", cha.GetChassisResource)
	chassis.Get("/{id}/NetworkAdapters/{id2}/NetworkPorts", cha.GetChassisResource)
	chassis.Get("/{id}/NetworkAdapters/{id2}/NetworkDeviceFunctions/{rid}", cha.GetChassisResource)
	chassis.Get("/{id}/NetworkAdapters/{id2}/NetworkPorts/{rid}", cha.GetChassisResource)
	chassis.Get("/{id}/NetworkAdapters/{id2}/Ports", cha.GetChassisResource)
	chassis.Get("/{id}/NetworkAdapters/{id2}/Ports/{rid}", cha.GetChassisResource)
	chassis.Any("/", handle.ChassisMethodNotAllowed)
	chassis.Any("/{id}", handle.ChassisMethodNotAllowed)
	chassis.Any("/{id}/NetworkAdapters", handle.ChassisMethodNotAllowed)
	chassis.Any("/{id}/NetworkAdapters/{rid}", handle.ChassisMethodNotAllowed)
	chassis.Any("/{id}/NetworkAdapters/{id2}/NetworkDeviceFunctions", handle.ChassisMethodNotAllowed)
	chassis.Any("/{id}/NetworkAdapters/{id2}/NetworkPorts", handle.ChassisMethodNotAllowed)
	chassis.Any("/{id}/NetworkAdapters/{id2}/NetworkDeviceFunctions/{rid}", handle.ChassisMethodNotAllowed)
	chassis.Any("/{id}/NetworkAdapters/{id2}/NetworkPorts/{rid}", handle.ChassisMethodNotAllowed)
	chassis.Get("/{id}/Assembly", cha.GetChassisResource)
	chassis.Any("/{id}/Assembly", handle.ChassisMethodNotAllowed)
	chassis.Get("/{id}/PCIeSlots", cha.GetChassisResource)
	chassis.Get("/{id}/PCIeSlots/{rid}", cha.GetChassisResource)
	chassis.Any("/{id}/PCIeSlots", handle.ChassisMethodNotAllowed)
	chassis.Any("/{id}/PCIeSlots/{rid}", handle.ChassisMethodNotAllowed)
	chassis.Get("/{id}/PCIeDevices", cha.GetChassisResource)
	chassis.Get(pcieDevicesIDURI, cha.GetChassisResource)
	chassis.Any("/{id}/PCIeDevices", handle.ChassisMethodNotAllowed)
	chassis.Any(pcieDevicesIDURI, handle.ChassisMethodNotAllowed)
	chassis.Get("/{id}/PCIeDevices/{rid}/PCIeFunctions", cha.GetChassisResource)
	chassis.Any("/{id}/PCIeDevices/{rid}/PCIeFunctions", handle.ChassisMethodNotAllowed)
	chassis.Get("/{id}/PCIeDevices/{rid}/PCIeFunctions/{rid2}", cha.GetChassisResource)
	chassis.Any("/{id}/PCIeDevices/{rid}/PCIeFunctions/{rid2}", handle.ChassisMethodNotAllowed)
	chassis.Get("/{id}/Sensors", cha.GetChassisResource)
	chassis.Get("/{id}/Sensors/{rid}", cha.GetChassisResource)
	chassis.Any("/{id}/Sensors", handle.ChassisMethodNotAllowed)
	chassis.Any("/{id}/Sensors/{rid}", handle.ChassisMethodNotAllowed)
	chassis.Get(logServiceURI, cha.GetChassisResource)
	chassis.Get(logServiceIDURI, cha.GetChassisResource)
	chassis.Get(logServiceEntriesURI, ratelimiter.ResourceRateLimiter, cha.GetChassisResource)
	chassis.Get(logServiceEntriesIDURI, ratelimiter.ResourceRateLimiter, cha.GetChassisResource)
	chassis.Get("/{id}/Power/", cha.GetChassisResource)
	chassis.Get("/{id}/Power/#PowerControl/{id1}", cha.GetChassisResource)
	chassis.Get("/{id}/Power/#PowerSupplies/{id1}", cha.GetChassisResource)
	chassis.Get("/{id}/Power/#Redundancy/{id1}", cha.GetChassisResource)
	chassis.Any("/{id}/Power/", handle.ChassisMethodNotAllowed)
	chassis.Any("/{id}/Power/#PowerControl/{id1}", handle.ChassisMethodNotAllowed)
	chassis.Any("/{id}/Power/#PowerSupplies/{id1}", handle.ChassisMethodNotAllowed)
	chassis.Any("/{id}/Power/#Redundancy/{id1}", handle.ChassisMethodNotAllowed)
	chassis.Get("/{id}/Thermal/", cha.GetChassisResource)
	chassis.Get("/{id}/Thermal/#Fans/{id1}", cha.GetChassisResource)
	chassis.Get("/{id}/Thermal/#Temperatures/{id1}", cha.GetChassisResource)
	chassis.Any("/{id}/Thermal/", handle.ChassisMethodNotAllowed)
	chassis.Any("/{id}/Thermal/#Fans/{id1}", handle.ChassisMethodNotAllowed)
	chassis.Any("/{id}/Thermal/#Temperatures/{id1}", handle.ChassisMethodNotAllowed)
	// TODO
	// chassis.Post(logServiceActionURI, cha.GetChassisResource)
	chassis.Any(logServiceURI, handle.ChassisMethodNotAllowed)
	chassis.Any(logServiceIDURI, handle.ChassisMethodNotAllowed)
	chassis.Any(logServiceEntriesURI, handle.ChassisMethodNotAllowed)
	chassis.Any(logServiceEntriesIDURI, handle.ChassisMethodNotAllowed)
	chassis.Any("/{id}/LogServices/{rid}/Actions", handle.ChassisMethodNotAllowed)

	events := v1.Party("/EventService", middleware.SessionDelMiddleware)
	events.SetRegisterRule(iris.RouteSkip)
	events.Get("/", evt.GetEventService)
	events.Get(subscriptionURI, evt.GetEventSubscriptionsCollection)
	events.Get("/Subscriptions/{id}", evt.GetEventSubscription)
	events.Post(subscriptionURI, evt.CreateEventSubscription)
	events.Post("/Actions/EventService.SubmitTestEvent", evt.SubmitTestEvent)
	events.Delete("/Subscriptions/{id}", evt.DeleteEventSubscription)
	events.Any("/", handle.EvtMethodNotAllowed)
	events.Any("/Actions", handle.EvtMethodNotAllowed)
	events.Any("/Actions/EventService.SubmitTestEvent", handle.EvtMethodNotAllowed)
	events.Any(subscriptionURI, handle.EvtMethodNotAllowed)

	fabrics := v1.Party("/Fabrics", middleware.SessionDelMiddleware)
	fabrics.SetRegisterRule(iris.RouteSkip)
	fabrics.Get("/", fab.GetFabricCollection)
	fabrics.Get("/{id}", fab.GetFabric)
	fabrics.Get("/{id}/Switches", fab.GetFabricSwitchCollection)
	fabrics.Get("/{id}/Switches/{switchID}", fab.GetFabricSwitch)
	fabrics.Get("/{id}/Switches/{switchID}/Ports", fab.GetSwitchPortCollection)
	fabrics.Get(switchPortIDURI, fab.GetSwitchPort)
	fabrics.Get("/{id}/Zones/", fab.GetFabricZoneCollection)
	fabrics.Get("/{id}/Endpoints/", fab.GetFabricEndPointCollection)
	fabrics.Get("/{id}/AddressPools/", fab.GetFabricAddressPoolCollection)
	fabrics.Get(zoneIDURI, fab.GetFabricZone)
	fabrics.Get(endpointsIDURI, fab.GetFabricEndPoints)
	fabrics.Get(addressPoolIDURI, fab.GetFabricAddressPool)
	fabrics.Put(zoneIDURI, fab.UpdateFabricResource)
	fabrics.Put(endpointsIDURI, fab.UpdateFabricResource)
	fabrics.Put(addressPoolIDURI, fab.UpdateFabricResource)
	fabrics.Post("/{id}/Zones", fab.UpdateFabricResource)
	fabrics.Post("/{id}/Endpoints", fab.UpdateFabricResource)
	fabrics.Post("/{id}/AddressPools", fab.UpdateFabricResource)
	fabrics.Patch(zoneIDURI, fab.UpdateFabricResource)
	fabrics.Patch(endpointsIDURI, fab.UpdateFabricResource)
	fabrics.Patch(addressPoolIDURI, fab.UpdateFabricResource)
	fabrics.Patch(switchPortIDURI, fab.UpdateFabricResource)
	fabrics.Delete(zoneIDURI, fab.DeleteFabricResource)
	fabrics.Delete(endpointsIDURI, fab.DeleteFabricResource)
	fabrics.Delete(addressPoolIDURI, fab.DeleteFabricResource)
	fabrics.Any("/", handle.FabricsMethodNotAllowed)
	fabrics.Any("/{id}", handle.FabricsMethodNotAllowed)
	fabrics.Any("/{id}/Switches", handle.FabricsMethodNotAllowed)
	fabrics.Any("/{id}/Switches/{switchID}", handle.FabricsMethodNotAllowed)
	fabrics.Any("/{id}/Switches/{switchID}/Ports", handle.FabricsMethodNotAllowed)
	fabrics.Any(switchPortIDURI, handle.FabricsMethodNotAllowed)
	fabrics.Any("/{id}/Zones/", handle.FabricsMethodNotAllowed)
	fabrics.Any("/{id}/Endpoints/", handle.FabricsMethodNotAllowed)
	fabrics.Any("/{id}/AddressPools/", handle.FabricsMethodNotAllowed)
	fabrics.Any(zoneIDURI, handle.FabricsMethodNotAllowed)
	fabrics.Any(endpointsIDURI, handle.FabricsMethodNotAllowed)
	fabrics.Any(addressPoolIDURI, handle.FabricsMethodNotAllowed)

	managers := v1.Party("/Managers", middleware.SessionDelMiddleware)
	managers.SetRegisterRule(iris.RouteSkip)
	managers.Get("/", manager.GetManagersCollection)
	managers.Get("/{id}", manager.GetManager)
	managers.Get(ethernetInterfaceURI, manager.GetManagersResource)
	managers.Get(ethernetInterfaceIDURI, manager.GetManagersResource)
	managers.Any(ethernetInterfaceURI, handle.ManagersMethodNotAllowed)
	managers.Any(ethernetInterfaceIDURI, handle.ManagersMethodNotAllowed)
	managers.Get("/{id}/NetworkProtocol", manager.GetManagersResource)
	managers.Get("/{id}/NetworkProtocol/{rid}", manager.GetManagersResource)
	managers.Any("/{id}/NetworkProtocol", handle.ManagersMethodNotAllowed)
	managers.Any("/{id}/NetworkProtocol/{rid}", handle.ManagersMethodNotAllowed)
	managers.Get("/{id}/HostInterfaces", manager.GetManagersResource)
	managers.Get("/{id}/HostInterfaces/{rid}", manager.GetManagersResource)
	managers.Any("/{id}/HostInterfaces", handle.ManagersMethodNotAllowed)
	managers.Any("/{id}/HostInterfaces/{rid}", handle.ManagersMethodNotAllowed)
	managers.Get("/{id}/SerialInterfaces", manager.GetManagersResource)
	managers.Get("/{id}/SerialInterfaces/{rid}", manager.GetManagersResource)
	managers.Any("/{id}/SerialInterfaces", handle.ManagersMethodNotAllowed)
	managers.Any("/{id}/SerialInterfaces/{rid}", handle.ManagersMethodNotAllowed)
	managers.Get("/{id}/VirtualMedia", manager.GetManagersResource)
	managers.Get("/{id}/VirtualMedia/{rid}", manager.GetManagersResource)
	managers.Post("/{id}/VirtualMedia/{rid}/Actions/VirtualMedia.EjectMedia", manager.VirtualMediaEject)
	managers.Post("/{id}/VirtualMedia/{rid}/Actions/VirtualMedia.InsertMedia", manager.VirtualMediaInsert)
	managers.Get(logServiceURI, manager.GetManagersResource)
	managers.Get(logServiceIDURI, manager.GetManagersResource)
	managers.Get(logServiceEntriesURI, ratelimiter.ResourceRateLimiter, manager.GetManagersResource)
	managers.Get(logServiceEntriesIDURI, ratelimiter.ResourceRateLimiter, manager.GetManagersResource)
	managers.Post(logServiceActionURI, manager.GetManagersResource)
	managers.Get("/{id}/RemoteAccountService", manager.GetRemoteAccountService)
	managers.Get(remoteAccountServiceURI, manager.GetRemoteAccountService)
	managers.Get(remoteAccountServiceIDURI, manager.GetRemoteAccountService)
	managers.Post(remoteAccountServiceURI, manager.CreateRemoteAccountService)
	managers.Patch(remoteAccountServiceIDURI, manager.UpdateRemoteAccountService)
	managers.Delete(remoteAccountServiceIDURI, manager.DeleteRemoteAccountService)
	managers.Get("/{id}/RemoteAccountService/Roles", manager.GetRemoteAccountService)
	managers.Get("/{id}/RemoteAccountService/Roles/{rid}", manager.GetRemoteAccountService)
	managers.Any("/{id}/RemoteAccountService", handle.ManagersMethodNotAllowed)
	managers.Any(remoteAccountServiceURI, handle.ManagersMethodNotAllowed)
	managers.Any(remoteAccountServiceIDURI, handle.ManagersMethodNotAllowed)
	managers.Any("/{id}/RemoteAccountService/Roles", handle.ManagersMethodNotAllowed)
	managers.Any("/{id}/RemoteAccountService/Roles/{rid}", handle.ManagersMethodNotAllowed)
	managers.Any(logServiceURI, handle.ManagersMethodNotAllowed)
	managers.Any(logServiceIDURI, handle.ManagersMethodNotAllowed)
	managers.Any(logServiceEntriesURI, handle.ManagersMethodNotAllowed)
	managers.Any(logServiceEntriesIDURI, handle.ManagersMethodNotAllowed)
	managers.Any("/{id}/LogServices/{rid}/Actions", handle.ManagersMethodNotAllowed)
	managers.Any(logServiceActionURI, handle.ManagersMethodNotAllowed)
	managers.Any("/{id}/VirtualMedia", handle.ManagersMethodNotAllowed)
	managers.Any("/{id}/VirtualMedia/{rid}", handle.ManagersMethodNotAllowed)
	managers.Any("/{id}/VirtualMedia/{rid}/Actions/VirtualMedia.EjectMedia", handle.ManagersMethodNotAllowed)
	managers.Any("/{id}/VirtualMedia/{rid}/Actions/VirtualMedia.InsertMedia", handle.ManagersMethodNotAllowed)
	managers.Any("/", handle.ManagersMethodNotAllowed)
	managers.Any("/{id}", handle.ManagersMethodNotAllowed)

	updateService := v1.Party("/UpdateService", middleware.SessionDelMiddleware)
	updateService.SetRegisterRule(iris.RouteSkip)
	updateService.Get("/", update.GetUpdateService)
	updateService.Post("/Actions/UpdateService.SimpleUpdate", update.SimpleUpdate)
	updateService.Post("/Actions/UpdateService.StartUpdate", update.StartUpdate)
	updateService.Get("/FirmwareInventory", update.GetFirmwareInventoryCollection)
	updateService.Get("/FirmwareInventory/{firmwareInventory_id}", update.GetFirmwareInventory)
	updateService.Get("/SoftwareInventory", update.GetSoftwareInventoryCollection)
	updateService.Get("/SoftwareInventory/{softwareInventory_id}", update.GetSoftwareInventory)
	updateService.Any("/FirmwareInventory", handle.UpdateServiceMethodNotAllowed)
	updateService.Any("/FirmwareInventory/{firmwareInventory_id}", handle.UpdateServiceMethodNotAllowed)
	updateService.Any("/SoftwareInventory", handle.UpdateServiceMethodNotAllowed)
	updateService.Any("/SoftwareInventory/{softwareInventory_id}", handle.UpdateServiceMethodNotAllowed)
	updateService.Any("/Actions/UpdateService.SimpleUpdate", handle.UpdateServiceMethodNotAllowed)
	updateService.Any("/Actions/UpdateService.StartUpdate", handle.UpdateServiceMethodNotAllowed)

	telemetryService := v1.Party("/TelemetryService", middleware.SessionDelMiddleware)
	telemetryService.SetRegisterRule(iris.RouteSkip)
	telemetryService.Get("/", telemetry.GetTelemetryService)
	telemetryService.Get("/MetricDefinitions", telemetry.GetMetricDefinitionCollection)
	telemetryService.Get("/MetricReportDefinitions", telemetry.GetMetricReportDefinitionCollection)
	telemetryService.Get("/MetricReports", telemetry.GetMetricReportCollection)
	telemetryService.Get("/Triggers", telemetry.GetTriggerCollection)
	telemetryService.Get("/MetricDefinitions/{id}", telemetry.GetMetricDefinition)
	telemetryService.Get("/MetricReportDefinitions/{id}", telemetry.GetMetricReportDefinition)
	telemetryService.Get("/MetricReports/{id}", telemetry.GetMetricReport)
	telemetryService.Get(triggersIDURI, telemetry.GetTrigger)
	telemetryService.Patch(triggersIDURI, telemetry.UpdateTrigger)
	telemetryService.Any("/MetricDefinitions", handle.MethodNotAllowed)
	telemetryService.Any("/MetricReportDefinitions", handle.MethodNotAllowed)
	telemetryService.Any("/MetricReports", handle.MethodNotAllowed)
	telemetryService.Any("/Triggers", handle.MethodNotAllowed)
	telemetryService.Any("/MetricDefinitions/{id}", handle.MethodNotAllowed)
	telemetryService.Any("/MetricReportDefinitions/{id}", handle.MethodNotAllowed)
	telemetryService.Any("/MetricReports/{id}", handle.MethodNotAllowed)
	telemetryService.Any(triggersIDURI, handle.MethodNotAllowed)

	licenseService := v1.Party("/LicenseService", middleware.SessionDelMiddleware)
	licenseService.SetRegisterRule(iris.RouteSkip)
	licenseService.Get("/", licenses.GetLicenseService)
	licenseService.Get(licensesURI, licenses.GetLicenseCollection)
	licenseService.Get("/Licenses/{id}", licenses.GetLicenseResource)
	licenseService.Post(licensesURI, licenses.InstallLicenseService)
	licenseService.Any("/", handle.LicenseMethodNotAllowed)
	licenseService.Any(licensesURI, handle.LicenseMethodNotAllowed)
	licenseService.Any("/Licenses/{id}", handle.LicenseMethodNotAllowed)

	// composition service
	if isCompositionEnabled {
		compositionService := v1.Party("/CompositionService", middleware.SessionDelMiddleware)
		compositionService.SetRegisterRule(iris.RouteSkip)
		compositionService.Get("/", cs.GetCompositionService)
		compositionService.Get(resourceBlockURI, cs.GetResourceBlockCollection)
		compositionService.Get(resourceBlockIDURI, cs.GetResourceBlock)
		compositionService.Post(resourceBlockURI, cs.CreateResourceBlock)
		compositionService.Delete(resourceBlockIDURI, cs.DeleteResourceBlock)
		compositionService.Get(resourceZonesURI, cs.GetResourceZoneCollection)
		compositionService.Get(resourceZonesIDURI, cs.GetResourceZone)
		compositionService.Post(resourceZonesURI, cs.CreateResourceZone)
		compositionService.Delete(resourceZonesIDURI, cs.DeleteResourceZone)
		compositionService.Post("/Actions/CompositionService.Compose", cs.Compose)
		compositionService.Get("/ActivePool", cs.GetActivePool)
		compositionService.Get("/FreePool", cs.GetFreePool)
		compositionService.Get("/CompositionReservations", cs.GetCompositionReservations)
		compositionService.Any("/", handle.CompositionServiceMethodNotAllowed)
		compositionService.Any(resourceBlockURI, handle.CompositionServiceMethodNotAllowed)
		compositionService.Any(resourceBlockIDURI, handle.CompositionServiceMethodNotAllowed)
		compositionService.Any(resourceZonesURI, handle.CompositionServiceMethodNotAllowed)
		compositionService.Any(resourceZonesIDURI, handle.CompositionServiceMethodNotAllowed)
		compositionService.Any("/FreePool", handle.CompositionServiceMethodNotAllowed)
		compositionService.Any("/ActivePool", handle.CompositionServiceMethodNotAllowed)
	}
	return router
}
