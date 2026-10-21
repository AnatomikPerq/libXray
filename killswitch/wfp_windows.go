//go:build windows

package killswitch

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Declarations from fwpmu.h, fwpmtypes.h and fwptypes.h.

var (
	modfwpuclnt = windows.NewLazySystemDLL("fwpuclnt.dll")

	procFwpmEngineOpen0           = modfwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0          = modfwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmTransactionBegin0     = modfwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0    = modfwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0     = modfwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmProviderAdd0          = modfwpuclnt.NewProc("FwpmProviderAdd0")
	procFwpmProviderDeleteByKey0  = modfwpuclnt.NewProc("FwpmProviderDeleteByKey0")
	procFwpmSubLayerAdd0          = modfwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmSubLayerGetByKey0     = modfwpuclnt.NewProc("FwpmSubLayerGetByKey0")
	procFwpmSubLayerDeleteByKey0  = modfwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmFilterAdd0            = modfwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteByKey0    = modfwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	procFwpmGetAppIdFromFileName0 = modfwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFwpmFreeMemory0           = modfwpuclnt.NewProc("FwpmFreeMemory0")
)

const (
	rpcCAuthnWinNT = 10 // RPC_C_AUTHN_WINNT

	fwpmProviderFlagPersistent = 1 // FWPM_PROVIDER_FLAG_PERSISTENT
	fwpmSubLayerFlagPersistent = 1 // FWPM_SUBLAYER_FLAG_PERSISTENT
	fwpmFilterFlagPersistent   = 1 // FWPM_FILTER_FLAG_PERSISTENT

	fwpUint8          = 1     // FWP_UINT8
	fwpUint16         = 2     // FWP_UINT16
	fwpUint32         = 3     // FWP_UINT32
	fwpUint64         = 4     // FWP_UINT64
	fwpByteBlobType   = 12    // FWP_BYTE_BLOB_TYPE
	fwpV4AddrMask     = 0x100 // FWP_V4_ADDR_MASK
	fwpV6AddrMask     = 0x101 // FWP_V6_ADDR_MASK
	fwpMatchEqual     = 0     // FWP_MATCH_EQUAL
	fwpMatchFlagsAll  = 6     // FWP_MATCH_FLAGS_ALL_SET
	fwpFlagIsLoopback = 1     // FWP_CONDITION_FLAG_IS_LOOPBACK

	fwpActionBlock  = 0x1001 // FWP_ACTION_BLOCK
	fwpActionPermit = 0x1002 // FWP_ACTION_PERMIT

	errFilterNotFound   = windows.Errno(0x80320003) // FWP_E_FILTER_NOT_FOUND
	errProviderNotFound = windows.Errno(0x80320005) // FWP_E_PROVIDER_NOT_FOUND
	errSubLayerNotFound = windows.Errno(0x80320007) // FWP_E_SUBLAYER_NOT_FOUND
)

var (
	layerKeys = [...]windows.GUID{
		connectV4: {Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33, Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}, // FWPM_LAYER_ALE_AUTH_CONNECT_V4
		acceptV4:  {Data1: 0xe1cd9fe7, Data2: 0xf4b5, Data3: 0x4273, Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}}, // FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
		connectV6: {Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc, Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}, // FWPM_LAYER_ALE_AUTH_CONNECT_V6
		acceptV6:  {Data1: 0xa3b42c97, Data2: 0x9f04, Data3: 0x4672, Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}}, // FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
	}

	conditionALEAppID        = windows.GUID{Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5, Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}}
	conditionFlags           = windows.GUID{Data1: 0x632ce23b, Data2: 0x5167, Data3: 0x435c, Data4: [8]byte{0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}}
	conditionLocalInterface  = windows.GUID{Data1: 0x4cd62a49, Data2: 0x59c3, Data3: 0x4969, Data4: [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4}}
	conditionIPProtocol      = windows.GUID{Data1: 0x3971ef2b, Data2: 0x623e, Data3: 0x4f9a, Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}}
	conditionIPLocalPort     = windows.GUID{Data1: 0x0c1ba1af, Data2: 0x5765, Data3: 0x453f, Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b}}
	conditionIPRemotePort    = windows.GUID{Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a, Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}}
	conditionIPRemoteAddress = windows.GUID{Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8, Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
)

type fwpByteBlob struct {
	size uint32
	data *byte
}

// fwpValue0 is FWP_VALUE0 as well as FWP_CONDITION_VALUE0: a type and a union
// that holds a scalar of at most 32 bits, or a pointer to anything larger.
type fwpValue0 struct {
	typ   uint32
	value uintptr
}

type fwpV4AddrAndMask struct {
	addr uint32 // host byte order
	mask uint32
}

type fwpV6AddrAndMask struct {
	addr         [16]byte
	prefixLength uint8
}

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           int32
}

type fwpmProvider0 struct {
	providerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerData fwpByteBlob
	serviceName  *uint16
}

type fwpmSublayer0 struct {
	subLayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
}

type fwpmFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      uint32
	conditionValue fwpValue0
}

type fwpmAction0 struct {
	typ        uint32
	filterType windows.GUID
}

type fwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	_                   uint32 // C aligns the following union to 8 bytes, as it holds a UINT64
	providerContextKey  windows.GUID
	reserved            *windows.GUID
	_                   [8 - unsafe.Sizeof(uintptr(0))]byte // and filterId as well, also on 32-bit
	filterID            uint64
	effectiveWeight     fwpValue0
}

// fwpmResult converts the DWORD status the Fwpm functions return.
func fwpmResult(r1, _ uintptr, _ error) error {
	if r1 != 0 {
		return windows.Errno(r1)
	}
	return nil
}
