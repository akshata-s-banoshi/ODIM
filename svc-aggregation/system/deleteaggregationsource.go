//(C) Copyright [2020] Hewlett Packard Enterprise Development LP
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

package system

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"runtime"
	"strings"

	dmtf "github.com/ODIM-Project/ODIM/lib-dmtf/model"
	"github.com/ODIM-Project/ODIM/lib-utilities/common"
	"github.com/ODIM-Project/ODIM/lib-utilities/errors"
	l "github.com/ODIM-Project/ODIM/lib-utilities/logs"
	aggregatorproto "github.com/ODIM-Project/ODIM/lib-utilities/proto/aggregator"
	"github.com/ODIM-Project/ODIM/lib-utilities/response"
	"github.com/ODIM-Project/ODIM/svc-aggregation/agmessagebus"
	"github.com/ODIM-Project/ODIM/svc-aggregation/agmodel"
)

// DeleteAggregationSources is used to delete aggregation sources
func (e *ExternalInterface) DeleteAggregationSources(ctx context.Context, taskID string, targetURI string,
	req *aggregatorproto.AggregatorRequest, sessionUserName string) error {
	var task = common.TaskData{
		TaskID:          taskID,
		TargetURI:       targetURI,
		TaskState:       common.Running,
		TaskStatus:      common.OK,
		PercentComplete: 0,
		HTTPMethod:      http.MethodDelete,
	}
	err := e.UpdateTask(ctx, task)
	if err != nil && (err.Error() == common.Cancelling) {
		// We cant do anything here as the task has done it work completely, we cant reverse it.
		//Unless if we can do opposite/reverse action for delete server which is add server.
		e.UpdateTask(ctx, common.TaskData{
			TaskID:          taskID,
			TargetURI:       targetURI,
			TaskState:       common.Cancelled,
			TaskStatus:      common.OK,
			PercentComplete: 0,
			HTTPMethod:      http.MethodDelete,
		})
		go runtime.Goexit()
	}
	l.LogWithFields(ctx).Debugf("request data for delete aggregation source: %s", string(req.RequestBody))
	data := e.DeleteAggregationSource(ctx, req, sessionUserName)
	err = e.UpdateTask(ctx, common.TaskData{
		TaskID:          taskID,
		TargetURI:       targetURI,
		TaskState:       common.Completed,
		TaskStatus:      common.OK,
		Response:        data,
		PercentComplete: 100,
		HTTPMethod:      http.MethodDelete,
	})
	if err != nil && (err.Error() == common.Cancelling) {
		e.UpdateTask(ctx, common.TaskData{
			TaskID:          taskID,
			TargetURI:       targetURI,
			TaskState:       common.Cancelled,
			TaskStatus:      common.OK,
			PercentComplete: 100,
			HTTPMethod:      http.MethodDelete,
		})
		go runtime.Goexit()
	}
	return nil
}

// DeleteAggregationSource is the handler for removing  bmc or manager
func (e *ExternalInterface) DeleteAggregationSource(ctx context.Context,
	req *aggregatorproto.AggregatorRequest, sessionUserName string) response.RPC {
	var resp response.RPC

	aggregationSource, dbErr := agmodel.GetAggregationSourceInfo(ctx, req.URL)
	if dbErr != nil {
		errorMessage := dbErr.Error()
		l.LogWithFields(ctx).Error("Unable to get AggregationSource : " + errorMessage)
		if errors.DBKeyNotFound == dbErr.ErrNo() {
			return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, errorMessage, []interface{}{"AggregationSource", req.URL}, nil)
		}
		return common.GeneralError(http.StatusInternalServerError, response.InternalError, errorMessage, nil, nil)
	}
	// check whether the aggregation source is bmc or manager
	links := aggregationSource.Links.(map[string]interface{})
	connectionMethodLink := links["ConnectionMethod"].(map[string]interface{})
	connectionMethodOdataID := connectionMethodLink["@odata.id"].(string)
	connectionMethod, err := e.GetConnectionMethod(ctx, connectionMethodOdataID)
	if err != nil {
		errorMessage := err.Error()
		l.LogWithFields(ctx).Error("Unable to get connectionmethod : " + errorMessage)
		if errors.DBKeyNotFound == err.ErrNo() {
			return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, err.Error(), []interface{}{"ConnectionMethod", connectionMethodOdataID}, nil)
		}
		return common.GeneralError(http.StatusInternalServerError, response.InternalError, errorMessage, nil, nil)
	}

	requestData := strings.SplitN(req.URL, ".", 2)
	resource := requestData[0]
	uuid := resource[strings.LastIndexByte(resource, '/')+1:]
	target, terr := agmodel.GetTarget(uuid)
	if terr != nil || target == nil {
		cmVariants := getConnectionMethodVariants(ctx, connectionMethod.ConnectionMethodVariant)
		if len(connectionMethod.Links.AggregationSources) > 1 {
			errMsg := fmt.Sprintf("Plugin " + cmVariants.PluginID + " can't be removed since it managing devices")
			l.LogWithFields(ctx).Info(errMsg)
			return common.GeneralError(http.StatusNotAcceptable, response.ResourceCannotBeDeleted, errMsg, nil, nil)
		}
		// Get the plugin
		dbPluginConn := agmodel.DBPluginDataRead{
			DBReadclient: agmodel.GetPluginDBConnection,
		}
		plugin, errs := agmodel.GetPluginData(cmVariants.PluginID, dbPluginConn)
		if errs != nil {
			errMsg := errs.Error()
			l.LogWithFields(ctx).Error(errMsg)
			return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, errMsg, []interface{}{"plugin", cmVariants.PluginID}, nil)
		}
		// delete the manager
		resp = e.deletePlugin(ctx, "/redfish/v1/Managers/"+plugin.ManagerUUID)
	} else {
		var data = strings.Split(req.URL, "/redfish/v1/AggregationService/AggregationSources/")
		systemList, dbErr := agmodel.GetAllMatchingDetails("ComputerSystem", data[1], common.InMemory)
		if dbErr != nil {
			errMsg := dbErr.Error()
			l.LogWithFields(ctx).Error(errMsg)
			if errors.DBKeyNotFound == dbErr.ErrNo() {
				return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, errMsg, []interface{}{"Systems", "everything"}, nil)
			}
			return common.GeneralError(http.StatusInternalServerError, response.InternalError, errMsg, nil, nil)
		}
		for _, systemURI := range systemList {
			index := strings.LastIndexAny(systemURI, "/")
			resp = e.deleteCompute(ctx, systemURI, index, target.PluginID, sessionUserName)
		}
		removeAggregationSourceFromAggregates(ctx, systemList)
	}
	if resp.StatusCode != http.StatusOK {
		return resp
	}

	if target != nil {
		dbPluginConn := agmodel.DBPluginDataRead{
			DBReadclient: agmodel.GetPluginDBConnection,
		}
		plugin, errs := agmodel.GetPluginData(target.PluginID, dbPluginConn)
		if errs != nil {
			l.LogWithFields(ctx).Error("failed to get " + target.PluginID + " plugin info: " + errs.Error())
			return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, errs.Error(), []interface{}{"plugin", target.PluginID}, nil)
		}
		pluginStartUpData := &agmodel.PluginStartUpData{
			RequestType: "delta",
			Devices: map[string]agmodel.DeviceData{
				target.DeviceUUID: agmodel.DeviceData{
					Operation: "del",
				},
			},
		}
		if err := PushPluginStartUpData(ctx, plugin, pluginStartUpData); err != nil {
			l.LogWithFields(ctx).Error("failed to notify device removal to " + target.PluginID + " plugin: " + err.Error())
		}
	}

	// Delete the Aggregation Source
	dbErr = agmodel.DeleteAggregationSource(req.URL)
	if dbErr != nil {
		errorMessage := "error while trying to delete AggreationSource  " + dbErr.Error()
		resp.CreateInternalErrorResponse(errorMessage)
		l.LogWithFields(ctx).Error(errorMessage)
		return resp
	}
	connectionMethod.Links.AggregationSources = removeAggregationSource(connectionMethod.Links.AggregationSources, agmodel.OdataID{OdataID: req.URL})
	dbErr = e.UpdateConnectionMethod(connectionMethod, connectionMethodOdataID)
	if dbErr != nil {
		errMsg := dbErr.Error()
		l.LogWithFields(ctx).Error(errMsg)
		return common.GeneralError(http.StatusInternalServerError, response.InternalError, errMsg, nil, nil)
	}

	resp = response.RPC{
		StatusCode:    http.StatusNoContent,
		StatusMessage: response.ResourceRemoved,
	}
	l.LogWithFields(ctx).Debugf("final response code for delete aggregation source request: %d", resp.StatusCode)
	return resp
}

// removeAggregationSourceFromAggregates will remove the element from the aggregate
// if the system is deleted from ODIM
func removeAggregationSourceFromAggregates(ctx context.Context, systemList []string) {
	l.LogWithFields(ctx).Debug("list of aggregation sources to be removed from aggregate: ", systemList)
	aggregateKeys, err := agmodel.GetAllKeysFromTable(ctx, "Aggregate")
	if err != nil {
		l.LogWithFields(ctx).Error("error getting aggregate : " + err.Error())
	}
	for _, aggregateURI := range aggregateKeys {
		aggregate, err := agmodel.GetAggregate(aggregateURI)
		if err != nil {
			l.LogWithFields(ctx).Error("error getting  Aggregate : " + err.Error())
			continue
		}
		var removeElements agmodel.Aggregate
		for _, systemURI := range systemList {
			removeElements.Elements = append(removeElements.Elements, agmodel.OdataID{OdataID: systemURI})
		}
		if checkRemovingElementsPresent(removeElements.Elements, aggregate.Elements) {
			dbErr := agmodel.RemoveElementsFromAggregate(removeElements, aggregateURI)
			if dbErr != nil {
				l.LogWithFields(ctx).Error("Error while deleting system from aggregate : " + dbErr.Error())
			}
		}
	}
}

// removeAggregationSource will remove the element from the slice return
// slice of remaining elements
func removeAggregationSource(slice []agmodel.OdataID, element agmodel.OdataID) []agmodel.OdataID {
	var elements []agmodel.OdataID
	for _, val := range slice {
		if val != element {
			elements = append(elements, val)
		}
	}
	return elements
}

// deleteplugin removes the given plugin
func (e *ExternalInterface) deletePlugin(ctx context.Context, oid string) response.RPC {
	var resp response.RPC
	// Get Manager Info
	data, derr := agmodel.GetResource(ctx, "Managers", oid)
	if derr != nil {
		errMsg := "error while getting Managers data: " + derr.Error()
		l.LogWithFields(ctx).Error(errMsg)
		if errors.DBKeyNotFound == derr.ErrNo() {
			return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, errMsg, []interface{}{"Managers", oid}, nil)
		}
		return common.GeneralError(http.StatusInternalServerError, response.InternalError, errMsg, nil, nil)
	}
	var resource map[string]interface{}
	json.Unmarshal([]byte(data), &resource)
	var pluginID = resource["Name"].(string)
	dbPluginConn := agmodel.DBPluginDataRead{
		DBReadclient: agmodel.GetPluginDBConnection,
	}
	plugin, errs := agmodel.GetPluginData(pluginID, dbPluginConn)
	if errs != nil {
		errMsg := "error while getting plugin data: " + errs.Error()
		l.LogWithFields(ctx).Error(errMsg)
		return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, errMsg, []interface{}{"Plugin", pluginID}, nil)
	}

	systems, dberr := agmodel.GetAllSystems()
	if dberr != nil {
		errMsg := derr.Error()
		l.LogWithFields(ctx).Error(errMsg)
		if errors.DBKeyNotFound == derr.ErrNo() {
			return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, errMsg, []interface{}{"Systems", "everything"}, nil)
		}
		return common.GeneralError(http.StatusInternalServerError, response.InternalError, errMsg, nil, nil)
	}
	// verifying if any device is mapped to plugin
	var systemCnt = 0
	for i := 0; i < len(systems); i++ {
		if systems[i].PluginID == pluginID {
			systemCnt++
		}
	}
	if systemCnt > 0 {
		errMsg := fmt.Sprintf("error: plugin %v can't be removed since it managing some of the devices", pluginID)
		l.LogWithFields(ctx).Error(errMsg)
		return common.GeneralError(http.StatusNotAcceptable, response.ResourceCannotBeDeleted, errMsg, nil, nil)
	}

	// verifying if plugin is up
	var pluginContactRequest getResourceRequest

	pluginContactRequest.ContactClient = e.ContactClient
	pluginContactRequest.Plugin = plugin
	pluginContactRequest.StatusPoll = false
	pluginContactRequest.HTTPMethodType = http.MethodGet
	pluginContactRequest.LoginCredentials = map[string]string{
		"UserName": plugin.Username,
		"Password": string(plugin.Password),
	}
	pluginContactRequest.OID = "/ODIM/v1/Status"
	l.LogWithFields(ctx).Debugf("plugin contact request data for %s: %s", pluginContactRequest.OID, string(pluginContactRequest.Data))
	_, _, _, err := contactPlugin(ctx, pluginContactRequest, "error while getting the details "+pluginContactRequest.OID+": ")
	if err == nil { // no err means plugin is still up, so we can't remove it
		errMsg := "error: plugin is still up, so it cannot be removed."
		l.LogWithFields(ctx).Error(errMsg)
		return common.GeneralError(http.StatusNotAcceptable, response.ResourceCannotBeDeleted, errMsg, nil, nil)
	}

	// deleting the manager info
	dberr = agmodel.DeleteManagersData(oid, ManagersTable)
	if dberr != nil {
		errMsg := derr.Error()
		l.LogWithFields(ctx).Error(errMsg)
		if errors.DBKeyNotFound == derr.ErrNo() {
			return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, errMsg, []interface{}{"Managers", oid}, nil)
		}
		return common.GeneralError(http.StatusInternalServerError, response.InternalError, errMsg, nil, nil)
	}
	//deleting logservice empty collection
	lkey := oid + "/LogServices"
	var isLogServicePresent bool
	if resource[LogServices] == nil {
		data, err := agmodel.GetResource(ctx, LogServiceCollection, lkey)
		if err != nil && errors.DBKeyNotFound != err.ErrNo() {
			errMsg := "error while getting LogService data: " + err.Error()
			l.LogWithFields(ctx).Error(errMsg)
			return common.GeneralError(http.StatusInternalServerError, response.InternalError, errMsg, nil, nil)
		}
		if data != "" {
			isLogServicePresent = true
		}
	}
	if resource[LogServices] != nil || isLogServicePresent {
		dberr = agmodel.DeleteManagersData(lkey, LogServiceCollection)
		if dberr != nil {
			errMsg := derr.Error()
			l.LogWithFields(ctx).Error(errMsg)
			if errors.DBKeyNotFound == derr.ErrNo() {
				return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, errMsg, []interface{}{"LogServiceCollection", lkey}, nil)
			}
			return common.GeneralError(http.StatusInternalServerError, response.InternalError, errMsg, nil, nil)
		}
		SLKey := oid + "/LogServices/SL"
		dberr = agmodel.DeleteManagersData(SLKey, LogServices)
		if dberr != nil {
			errMsg := derr.Error()
			l.LogWithFields(ctx).Error(errMsg)
			if errors.DBKeyNotFound == derr.ErrNo() {
				return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, errMsg, []interface{}{"LogServices", lkey}, nil)
			}
			return common.GeneralError(http.StatusInternalServerError, response.InternalError, errMsg, nil, nil)
		}
		logEntriesKey := oid + "/LogServices/SL/Entries"
		dberr = agmodel.DeleteManagersData(logEntriesKey, EntriesCollection)
		if dberr != nil {
			errMsg := derr.Error()
			l.LogWithFields(ctx).Error(errMsg)
			if errors.DBKeyNotFound == derr.ErrNo() {
				return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, errMsg, []interface{}{"EntriesCollection", lkey}, nil)
			}
			return common.GeneralError(http.StatusInternalServerError, response.InternalError, errMsg, nil, nil)
		}
	}
	// deleting the plugin if  zero devices are managed
	dberr = agmodel.DeletePluginData(pluginID, PluginTable)
	if dberr != nil {
		errMsg := derr.Error()
		l.LogWithFields(ctx).Error(errMsg)
		if errors.DBKeyNotFound == derr.ErrNo() {
			return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, errMsg, []interface{}{"Plugin", pluginID}, nil)
		}
		return common.GeneralError(http.StatusInternalServerError, response.InternalError, errMsg, nil, nil)
	}
	MQ := agmessagebus.InitMQSCom()
	e.EventNotification(ctx, oid, "ResourceRemoved", "ManagerCollection", MQ)
	resp.StatusCode = http.StatusOK
	resp.StatusMessage = response.ResourceRemoved

	args := response.Args{
		Code:    resp.StatusMessage,
		Message: "Request completed successfully",
	}
	resp.Body = args.CreateGenericErrorResponse()
	l.LogWithFields(ctx).Debugf("final response for delete plugin request: %s", string(fmt.Sprintf("%v", resp.Body)))
	return resp
}

func (e *ExternalInterface) deleteCompute(ctx context.Context, key string, index int, pluginID string,
	sessionUserName string) response.RPC {
	var resp response.RPC
	// check whether the any system operation is under progress
	systemOperation, dbErr := agmodel.GetSystemOperationInfo(ctx, strings.TrimSuffix(key, "/"))
	if dbErr != nil && errors.DBKeyNotFound != dbErr.ErrNo() {
		l.LogWithFields(ctx).Error(" Delete operation for system  " + key + " can't be processed " + dbErr.Error())
		errMsg := "error while trying to delete compute system: " + dbErr.Error()
		return common.GeneralError(http.StatusInternalServerError, response.InternalError, errMsg, nil, nil)
	}
	if systemOperation.Operation != "" {
		l.LogWithFields(ctx).Error("Delete operation or system  " + key + " can't be processed," +
			systemOperation.Operation + " operation  is under progress")
		errMsg := systemOperation.Operation + " operation  is under progress"
		return common.GeneralError(http.StatusNotAcceptable, response.ResourceCannotBeDeleted, errMsg, nil, nil)
	}
	// Get the plugin
	var managerData map[string]interface{}
	dbPluginConn := agmodel.DBPluginDataRead{
		DBReadclient: agmodel.GetPluginDBConnection,
	}
	plugin, errs := agmodel.GetPluginData(pluginID, dbPluginConn)
	if errs != nil {
		errMsg := errs.Error()
		l.LogWithFields(ctx).Error(errMsg)
		return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, errMsg, []interface{}{"plugin", pluginID}, nil)
	}

	managerURI := "/redfish/v1/Managers/" + plugin.ManagerUUID
	mgrData, jerr := agmodel.GetResource(ctx, "Managers", managerURI)
	if jerr != nil {
		errorMessage := "error while getting manager details: " + jerr.Error()
		l.LogWithFields(ctx).Error(errorMessage)
		return common.GeneralError(http.StatusInternalServerError, response.InternalError, errorMessage,
			nil, nil)
	}

	unmarshallErr := json.Unmarshal([]byte(mgrData), &managerData)
	if unmarshallErr != nil {
		errorMessage := "error unmarshalling manager details: " + unmarshallErr.Error()
		l.LogWithFields(ctx).Error(errorMessage)
		return common.GeneralError(http.StatusInternalServerError, response.InternalError, errorMessage,
			nil, nil)
	}
	systemOperation.Operation = "Delete"
	dbErr = systemOperation.AddSystemOperationInfo(strings.TrimSuffix(key, "/"))
	if dbErr != nil {
		l.LogWithFields(ctx).Error(" Delete operation for system  " + key + " can't be processed " + dbErr.Error())
		errMsg := "error while trying to delete compute system: " + dbErr.Error()
		return common.GeneralError(http.StatusInternalServerError, response.InternalError, errMsg, nil, nil)
	}
	defer func() {
		if err := agmodel.DeleteSystemOperationInfo(strings.TrimSuffix(key, "/")); err != nil {
			l.LogWithFields(ctx).Errorf("failed to delete SystemOperation info of %s:%s", key, err.Error())
		}
	}()
	// Delete Subscription on odimra and also on device
	subResponse, err := e.DeleteEventSubscription(ctx, key, sessionUserName)
	if err != nil && subResponse == nil {
		errMsg := fmt.Sprintf("error while trying to delete subscriptions: %v", err)
		l.LogWithFields(ctx).Error(errMsg)
		return common.GeneralError(http.StatusInternalServerError, response.InternalError, errMsg, nil, nil)
	}
	// If the DeleteEventSubscription call return status code other than http.StatusNoContent, http.StatusNotFound.
	//Then return with error(delete event subscription failed).
	if subResponse.StatusCode != http.StatusNoContent {
		l.LogWithFields(ctx).Error("error while deleting the event subscription for " + key + " :" + string(subResponse.Body))
	}

	keys := strings.SplitN(key[index+1:], ".", 2)
	chassisList, derr := agmodel.GetAllMatchingDetails("Chassis", keys[0], common.InMemory)
	if derr != nil {
		l.LogWithFields(ctx).Error("error while trying to collect the chassis list: " + derr.Error())
	}

	managersList, derr := agmodel.GetAllMatchingDetails("Managers", keys[0], common.InMemory)
	if derr != nil {
		l.LogWithFields(ctx).Error("error while trying to collect the manager list: " + derr.Error())
	}

	mgrResp := deleteLinkDetails(managerData, key, chassisList)
	data, marshalErr := json.Marshal(mgrResp)
	if marshalErr != nil {
		errorMessage := "unable to marshal data for updating: " + marshalErr.Error()
		l.LogWithFields(ctx).Error(errorMessage)
		return common.GeneralError(http.StatusInternalServerError, response.InternalError, errorMessage, nil, nil)
	}
	genericErr := agmodel.GenericSave([]byte(data), "Managers", managerURI)
	if genericErr != nil {
		errorMessage := "GenericSave : error while trying to add resource date to DB: " + genericErr.Error()
		l.LogWithFields(ctx).Error(errorMessage)
		return common.GeneralError(http.StatusInternalServerError, response.InternalError, errorMessage, nil, nil)
	}

	// Delete Compute System Details from InMemory
	if derr := e.DeleteComputeSystem(index, key); derr != nil {
		errMsg := "error while trying to delete compute system: " + derr.Error()
		l.LogWithFields(ctx).Error(errMsg)
		if errors.DBKeyNotFound == derr.ErrNo() {
			return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, errMsg, []interface{}{index, key}, nil)
		}
		return common.GeneralError(http.StatusInternalServerError, response.InternalError, errMsg, nil, nil)
	}

	// Split the key by : (uuid.1) so we will get [uuid 1]
	k := strings.SplitN(key[index+1:], ".", 2)
	if len(k) < 2 {
		errMsg := fmt.Sprintf("key %v doesn't have system details", key)
		l.LogWithFields(ctx).Error(errMsg)
		return common.GeneralError(http.StatusInternalServerError, response.InternalError, errMsg, nil, nil)
	}
	uuid := k[0]
	// Delete System Details from OnDisk
	if derr := e.DeleteSystem(uuid); derr != nil {
		errMsg := "error while trying to delete system: " + derr.Error()
		l.LogWithFields(ctx).Error(errMsg)
		if errors.DBKeyNotFound == derr.ErrNo() {
			return common.GeneralError(http.StatusNotFound, response.ResourceNotFound, errMsg, []interface{}{"System", uuid}, nil)
		}
		return common.GeneralError(http.StatusInternalServerError, response.InternalError, errMsg, nil, nil)
	}
	e.deleteWildCardValues(ctx, key[index+1:])

	for _, manager := range managersList {
		MQ := agmessagebus.InitMQSCom()
		e.EventNotification(ctx, manager, "ResourceRemoved", "ManagerCollection", MQ)
	}
	for _, chassis := range chassisList {
		MQ := agmessagebus.InitMQSCom()
		e.EventNotification(ctx, chassis, "ResourceRemoved", "ChassisCollection", MQ)
	}
	MQ := agmessagebus.InitMQSCom()
	e.EventNotification(ctx, key, "ResourceRemoved", "SystemsCollection", MQ)
	resp.StatusCode = http.StatusOK
	resp.StatusMessage = response.ResourceRemoved
	args := response.Args{
		Code:    resp.StatusMessage,
		Message: "Request completed successfully",
	}
	resp.Body = args.CreateGenericErrorResponse()
	l.LogWithFields(ctx).Debugf("final response for delete compute request: %s", string(fmt.Sprintf("%v", resp.Body)))
	return resp
}

func deleteLinkDetails(managerData map[string]interface{}, systemID string, chassisList []string) map[string]interface{} {
	if links, ok := managerData["Links"].(map[string]interface{}); ok {
		if managerForServers, ok := links["ManagerForServers"].([]interface{}); ok {
			for k, v := range managerForServers {
				if reflect.DeepEqual(v.(map[string]interface{})["@odata.id"], systemID) {
					managerForServers = append(managerForServers[:k], managerForServers[k+1:]...)
					if len(managerForServers) != 0 {
						links["ManagerForServers"] = managerForServers
					} else {
						delete(links, "ManagerForServers")
					}
				}
			}
		}
		for _, val := range chassisList {
			if managerForChassis, ok := links["ManagerForChassis"].([]interface{}); ok {
				for k, v := range managerForChassis {
					if reflect.DeepEqual(v.(map[string]interface{})["@odata.id"], val) {
						managerForChassis = append(managerForChassis[:k], managerForChassis[k+1:]...)
						if len(managerForChassis) != 0 {
							links["ManagerForChassis"] = managerForChassis
						} else {
							delete(links, "ManagerForChassis")
						}
					}
				}
			}
		}
	}

	return managerData
}

// deleteWildCardValues will delete the wild card values and
// if all the servers are deleted, then it will delete the telemetry information
func (e *ExternalInterface) deleteWildCardValues(ctx context.Context, systemID string) {
	telemetryList, dbErr := e.GetAllMatchingDetails("*", "TelemetryService", common.InMemory)
	if dbErr != nil {
		l.LogWithFields(ctx).Error(dbErr)
		return
	}
	for _, oid := range telemetryList {
		oID := strings.Split(oid, ":")
		if !strings.Contains(oid, "MetricReports") && !strings.Contains(oid, "Collection") {
			odataID := oID[1]
			resourceData := make(map[string]interface{})
			data, dbErr := agmodel.GetResourceDetails(ctx, odataID)
			if dbErr != nil {
				l.LogWithFields(ctx).Error("Unable to get system data : " + dbErr.Error())
				continue
			}
			// unmarshall the resourceData
			err := json.Unmarshal([]byte(data), &resourceData)
			if err != nil {
				l.LogWithFields(ctx).Error("Unable to unmarshall  the data: " + err.Error())
				continue
			}
			var wildCards []WildCard
			var wildCardPresent bool
			wCards := resourceData["Wildcards"]
			if wCards != nil {
				for _, wCard := range getWildCard(wCards.([]interface{})) {
					wCard.Values = checkAndRemoveWildCardValue(systemID, wCard.Values)
					wildCards = append(wildCards, wCard)
					if len(wCard.Values) > 0 {
						wildCardPresent = true
					}
				}
			}
			if wildCardPresent {
				resourceData["Wildcards"] = wildCards
				resourceDataByte, err := json.Marshal(resourceData)
				if err != nil {
					continue
				}
				e.GenericSave(resourceDataByte, getResourceName(odataID, false), odataID)
			} else {
				exist, dbErr := e.CheckMetricRequest(odataID)
				if exist || dbErr != nil {
					continue
				}
				if derr := e.Delete(oID[0], odataID, common.InMemory); derr != nil {
					l.LogWithFields(ctx).Error("error while trying to delete data: " + derr.Error())
					continue
				}
				e.updateMemberCollection(ctx, oID[0], odataID)
			}
		}
	}
}

// checkAndRemoveWildCardValue will check and remove the wild card value
func checkAndRemoveWildCardValue(val string, values []string) []string {
	var wildCardValues []string
	if len(values) < 1 {
		return wildCardValues
	}
	for _, v := range values {
		if v != val {
			wildCardValues = append(wildCardValues, v)
		}
	}
	return wildCardValues
}

// updateMemberCollection will remove the member from the collection and update into DB
func (e *ExternalInterface) updateMemberCollection(ctx context.Context, resName, odataID string) {
	resourceName := resName + "Collection"
	collectionOdataID := odataID[:strings.LastIndexByte(odataID, '/')]
	data, dbErr := e.GetResource(ctx, resourceName, collectionOdataID)
	if dbErr != nil {
		return
	}
	var telemetryInfo dmtf.Collection
	if err := json.Unmarshal([]byte(data), &telemetryInfo); err != nil {
		return
	}
	result := removeMemberFromCollection(odataID, telemetryInfo.Members)
	telemetryInfo.Members = result
	telemetryInfo.MembersCount = len(result)
	telemetryData, err := json.Marshal(telemetryInfo)
	if err != nil {
		return
	}
	e.GenericSave(telemetryData, resourceName, collectionOdataID)
}

// removeMemberFromCollection will remove the member from the collection
func removeMemberFromCollection(collectionOdataID string, telemetryInfo []*dmtf.Link) []*dmtf.Link {
	result := []*dmtf.Link{}
	for _, v := range telemetryInfo {
		if v.Oid != collectionOdataID {
			result = append(result, v)
		}
	}
	return result
}
