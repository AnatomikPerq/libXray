package libXray

import (
	"encoding/json"

	"github.com/xtls/libxray/netreport"
)

// invokeStartNetworkReport starts a network report in the background. The
// App polls networkReportState: a run takes a minute or two, and mobile
// platforms serialize libXray calls.
func invokeStartNetworkReport(payload json.RawMessage) string {
	request, err := decodePayload[StartNetworkReportRequest](payload)
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}
	id, err := netreport.Start(request)
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}
	return encodeInvokeResponse(&StartNetworkReportResponse{ID: id}, nil)
}

func invokeNetworkReportState(payload json.RawMessage) string {
	request, err := decodePayload[NetworkReportRequest](payload)
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}
	snapshot, err := netreport.State(request.ID)
	if err != nil {
		return encodeInvokeResponse(nil, err)
	}
	return encodeInvokeResponse(&snapshot, nil)
}
