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

// Package common ...
package common

import (
	"context"
	"net/http"

	l "github.com/ODIM-Project/ODIM/lib-utilities/logs"
	"github.com/ODIM-Project/ODIM/lib-utilities/response"
	iris "github.com/kataras/iris/v12"
	"google.golang.org/grpc/metadata"
)

// commonHeaders holds the common response headers
var commonHeaders = map[string]string{
	"Connection":             "keep-alive",
	"OData-Version":          "4.0",
	"X-Frame-Options":        "sameorigin",
	"X-Content-Type-Options": "nosniff",
	"Content-type":           "application/json; charset=utf-8",
	"Cache-Control":          "no-cache, no-store, must-revalidate",
	"Transfer-Encoding":      "chunked",
}

// SetResponseHeader will add the params to the response header
func SetResponseHeader(ctx iris.Context, params map[string]string) {
	SetCommonHeaders(ctx.ResponseWriter())
	for key, value := range params {
		ctx.ResponseWriter().Header().Set(key, value)
	}
}

// SetCommonHeaders will add the common headers to the response writer
func SetCommonHeaders(w http.ResponseWriter) {
	for key, value := range commonHeaders {
		w.Header().Set(key, value)
	}
}

// GetContextData is used to fetch data from metadata and add it to context
func GetContextData(ctx context.Context) context.Context {
	md, _ := metadata.FromIncomingContext(ctx)
	ctx = metadata.NewIncomingContext(ctx, md)
	if len(md[TransactionID]) > 0 {
		ctx = context.WithValue(ctx, ProcessName, md[ProcessName][0])
		ctx = context.WithValue(ctx, TransactionID, md[TransactionID][0])
		ctx = context.WithValue(ctx, ActionID, md[ActionID][0])
		ctx = context.WithValue(ctx, ActionName, md[ActionName][0])
		ctx = context.WithValue(ctx, ThreadID, md[ThreadID][0])
		ctx = context.WithValue(ctx, ThreadName, md[ThreadName][0])
	}

	return ctx
}

// CreateMetadata is used to add metadata values in context to be used in grpc calls
func CreateMetadata(ctx context.Context) context.Context {
	if ctx.Value(TransactionID) != nil {
		md := metadata.New(map[string]string{
			ProcessName:   ctx.Value(ProcessName).(string),
			TransactionID: ctx.Value(TransactionID).(string),
			ActionName:    ctx.Value(ActionName).(string),
			ActionID:      ctx.Value(ActionID).(string),
			ThreadID:      ctx.Value(ThreadID).(string),
			ThreadName:    ctx.Value(ThreadName).(string),
		})
		ctx = metadata.NewOutgoingContext(ctx, md)
	}

	return ctx
}

// ModifyContext modify the values in the context
func ModifyContext(ctx context.Context, threadName, podName string) context.Context {
	ctx = context.WithValue(ctx, ThreadName, threadName)
	ctx = context.WithValue(ctx, ProcessName, podName)
	return ctx
}

// CreateNewRequestContext creates a new context with the values from a context passed
func CreateNewRequestContext(ctx context.Context) context.Context {
	reqCtx := context.Background()
	processName, _ := ctx.Value(ProcessName).(string)
	transactionID, _ := ctx.Value(TransactionID).(string)
	actionID, _ := ctx.Value(ActionID).(string)
	actionName, _ := ctx.Value(ActionName).(string)
	threadID, _ := ctx.Value(ThreadID).(string)
	threadName, _ := ctx.Value(ThreadName).(string)
	reqCtx = context.WithValue(reqCtx, ProcessName, processName)
	reqCtx = context.WithValue(reqCtx, TransactionID, transactionID)
	reqCtx = context.WithValue(reqCtx, ActionID, actionID)
	reqCtx = context.WithValue(reqCtx, ActionName, actionName)
	reqCtx = context.WithValue(reqCtx, ThreadID, threadID)
	reqCtx = context.WithValue(reqCtx, ThreadName, threadName)
	return reqCtx
}

// CreateContext will create and returns a new context with the values passed
func CreateContext(transactionID, actionID, actionName, threadID, threadName, processName string) context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, TransactionID, transactionID)
	ctx = context.WithValue(ctx, ActionID, actionID)
	ctx = context.WithValue(ctx, ActionName, actionName)
	ctx = context.WithValue(ctx, ThreadID, threadID)
	ctx = context.WithValue(ctx, ThreadName, threadName)
	ctx = context.WithValue(ctx, ProcessName, processName)
	return ctx
}

// SendInvalidSessionResponseToClient writes the response to client when no valid session is found
func SendInvalidSessionResponse(ctx iris.Context, errorMessage string) {
	response := GeneralError(http.StatusUnauthorized, response.NoValidSession, errorMessage, nil, nil)
	SetResponseHeader(ctx, response.Header)
	ctx.StatusCode(http.StatusUnauthorized)
	ctx.JSON(&response.Body)
	return
}

// SendFailedRPCCallResponseToClient writes the response to client when a RPC call fails
func SendFailedRPCCallResponse(ctxt context.Context, ctx iris.Context, errorMessage string) {
	l.LogWithFields(ctxt).Error(errorMessage)
	response := GeneralError(http.StatusInternalServerError, response.InternalError, errorMessage, nil, nil)
	SetResponseHeader(ctx, response.Header)
	ctx.StatusCode(http.StatusInternalServerError)
	ctx.JSON(&response.Body)
	return
}

// SendMalformedJSONRequestErrResponse writes the response to client when the request contains malformed JSON structure
func SendMalformedJSONRequestErrResponse(ctxt context.Context, ctx iris.Context, errorMessage string) {
	l.LogWithFields(ctxt).Error(errorMessage)
	response := GeneralError(http.StatusBadRequest, response.MalformedJSON, errorMessage, nil, nil)
	SetResponseHeader(ctx, response.Header)
	ctx.StatusCode(http.StatusBadRequest)
	ctx.JSON(&response.Body)
	return
}
