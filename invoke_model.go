// libXray is an Xray wrapper focusing on improving the experience of Xray-core mobile development.
package libXray

import "encoding/json"

type LibXrayMethod string

const LibXrayAPIVersion = 2

const (
	LibXrayMethodGetFreePorts                LibXrayMethod = "getFreePorts"
	LibXrayMethodConvertShareLinksToXrayJson LibXrayMethod = "convertShareLinksToXrayJson"
	LibXrayMethodConvertXrayJsonToShareLinks LibXrayMethod = "convertXrayJsonToShareLinks"
	LibXrayMethodGenerateAgeKeyPair          LibXrayMethod = "generateAgeKeyPair"
	LibXrayMethodCountGeoData                LibXrayMethod = "countGeoData"
	LibXrayMethodPingBatch                   LibXrayMethod = "pingBatch"
	LibXrayMethodTestXray                    LibXrayMethod = "testXray"
	LibXrayMethodRunXray                     LibXrayMethod = "runXray"
	LibXrayMethodStopXray                    LibXrayMethod = "stopXray"
	LibXrayMethodXrayVersion                 LibXrayMethod = "xrayVersion"
	LibXrayMethodGetXrayState                LibXrayMethod = "getXrayState"
	LibXrayMethodStartMinewire               LibXrayMethod = "startMinewire"
	LibXrayMethodStopMinewire                LibXrayMethod = "stopMinewire"
	LibXrayMethodMinewireState               LibXrayMethod = "minewireState"
)

type LibXrayInvokeRequest struct {
	APIVersion int             `json:"apiVersion,omitempty"`
	Method     LibXrayMethod   `json:"method,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}

type GetFreePortsRequest struct {
	Count int `json:"count,omitempty"`
}

type GetFreePortsResponse struct {
	Ports []int `json:"ports,omitempty"`
}

type AgeDecryptConfig struct {
	SecretKey string `json:"secretKey,omitempty"`
}

type ConvertShareLinksToXrayJsonRequest struct {
	Text string            `json:"text,omitempty"`
	Age  *AgeDecryptConfig `json:"age,omitempty"`
}

type AgeKeyType string

const (
	AgeKeyTypeX25519 AgeKeyType = "x25519"
	AgeKeyTypeHybrid AgeKeyType = "hybrid"
)

type GenerateAgeKeyPairRequest struct {
	KeyType AgeKeyType `json:"keyType,omitempty"`
}

type GenerateAgeKeyPairResponse struct {
	SecretKey string `json:"secretKey,omitempty"`
	PublicKey string `json:"publicKey,omitempty"`
}

type ConvertXrayJsonToShareLinksRequest struct {
	XrayJson string `json:"xrayJson,omitempty"`
}

type ConvertXrayJsonToShareLinksResponse struct {
	Links string `json:"links,omitempty"`
}

type CountGeoDataRequest struct {
	Name    string `json:"name,omitempty"`
	GeoType string `json:"geoType,omitempty"`
	DatDir  string `json:"datDir,omitempty"`
}

type PingBatchRequest struct {
	Configs []PingBatchItemRequest `json:"configs,omitempty"`
	Timeout int                    `json:"timeout,omitempty"`
	URL     string                 `json:"url,omitempty"`
}

type PingBatchItemRequest struct {
	XrayJson    string `json:"xrayJson,omitempty"`
	OutboundTag string `json:"outboundTag,omitempty"`
}

type PingBatchResponse struct {
	Results []PingBatchItemResponse `json:"results,omitempty"`
}

type PingBatchItemResponse struct {
	Success bool   `json:"success"`
	Delay   int64  `json:"delay,omitempty"`
	Error   string `json:"error,omitempty"`
}

type RunXrayRequest struct {
	XrayJson string `json:"xrayJson,omitempty"`
}

// StartMinewireRequest describes one minewire node.
//
// The address should already be resolved by the caller: once the tunnel is
// up, DNS may itself depend on the tunnel that is not working yet.
type StartMinewireRequest struct {
	ServerAddress string `json:"serverAddress,omitempty"`
	Password      string `json:"password,omitempty"`
	Mode          string `json:"mode,omitempty"`
	LocalPort     int    `json:"localPort,omitempty"`
}

type StartMinewireResponse struct {
	LocalPort int `json:"localPort"`
}

type MinewireStateResponse struct {
	Running   bool   `json:"running"`
	Connected bool   `json:"connected"`
	LocalAddr string `json:"localAddr,omitempty"`
	LastError string `json:"lastError,omitempty"`
}

type TestXrayRequest struct {
	XrayJson string `json:"xrayJson,omitempty"`
}

type XrayVersionResponse struct {
	Version string `json:"version,omitempty"`
}

type GetXrayStateResponse struct {
	Running bool `json:"running"`
}
