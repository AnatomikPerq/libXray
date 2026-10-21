//go:build windows

package killswitch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The filters live in a session that is not dynamic, so they outlive the
// Core that added them. They are found again by fixed keys: Lift runs in the
// unelevated App, which may not enumerate WFP objects, only open the ones
// whose security descriptor lets it.
type objectKeys struct {
	provider   windows.GUID
	sublayer   windows.GUID
	filterBase windows.GUID
}

var keys = objectKeys{
	provider:   windows.GUID{Data1: 0x9d339829, Data2: 0xeb1a, Data3: 0x4987, Data4: [8]byte{0xb6, 0x84, 0xb6, 0xc4, 0x8f, 0x84, 0x0e, 0xc7}},
	sublayer:   windows.GUID{Data1: 0x77a2edc6, Data2: 0x635a, Data3: 0x4053, Data4: [8]byte{0xa7, 0x65, 0x27, 0xa6, 0xc2, 0x89, 0x81, 0x39}},
	filterBase: windows.GUID{Data1: 0xbe7a2770, Data2: 0xe698, Data3: 0x0000, Data4: [8]byte{0x85, 0x2d, 0xcc, 0x92, 0x82, 0xe1, 0x79, 0x8a}},
}

// filterKey is the key of the plan's i-th filter.
func (k objectKeys) filterKey(i int) windows.GUID {
	key := k.filterBase
	key.Data3 = uint16(i)
	return key
}

// Weight of the sublayer among the others: sublayers are evaluated from the
// heaviest, and a hard permit in a heavier one would overrule the blocks
// here. Xray's own leak filters use the maximum, 0xffff; they only ever
// permit Xray itself that way.
const sublayerWeight = 0xfffe

// rightsOfUser are granted to the user who runs the Core: FWPM_ACTRL_READ, so
// that the unelevated App can tell whether the filters are in place, and
// DELETE, so that it can lift them without another UAC prompt.
const rightsOfUser = 0x10000 | 0x80

// Engage replaces the kill switch filters with the ones o describes, all at
// once: there is no moment without filters or with half of them. It needs
// administrator rights.
func Engage(o Options) error {
	rules, err := plan(o)
	if err != nil {
		return err
	}
	appIDs, err := appIDsOf(o.Apps)
	if err != nil {
		return err
	}
	defer freeAll(appIDs)
	sd, err := securityDescriptor()
	if err != nil {
		return err
	}
	engine, err := openEngine()
	if err != nil {
		return err
	}
	defer closeEngine(engine)
	return inTransaction(engine, func() error {
		if err := remove(engine); err != nil {
			return err
		}
		return install(engine, o, rules, appIDs, sd)
	})
}

// Lift removes the kill switch filters, if there are any. The user who ran
// the Core may do it without administrator rights.
func Lift() error {
	engine, err := openEngine()
	if err != nil {
		return err
	}
	defer closeEngine(engine)
	// Without administrator rights a write transaction is denied; removing
	// the filters one by one, blocks first, is allowed.
	if err := fwpmResult(procFwpmTransactionBegin0.Call(uintptr(engine), 0)); err != nil {
		return remove(engine)
	}
	if err := remove(engine); err != nil {
		procFwpmTransactionAbort0.Call(uintptr(engine))
		return err
	}
	return wrap("FwpmTransactionCommit0", fwpmResult(procFwpmTransactionCommit0.Call(uintptr(engine))))
}

// Engaged reports whether the kill switch filters are in place.
func Engaged() (bool, error) {
	engine, err := openEngine()
	if err != nil {
		return false, err
	}
	defer closeEngine(engine)
	return sublayerExists(engine)
}

func openEngine() (windows.Handle, error) {
	if err := modfwpuclnt.Load(); err != nil {
		return 0, err
	}
	name, err := windows.UTF16PtrFromString("HYPER CLIENT kill switch")
	if err != nil {
		return 0, err
	}
	// Not FWPM_SESSION_FLAG_DYNAMIC: the filters must survive the process.
	session := fwpmSession0{displayData: fwpmDisplayData0{name: name}}
	var engine windows.Handle
	err = fwpmResult(procFwpmEngineOpen0.Call(0, rpcCAuthnWinNT, 0, uintptr(unsafe.Pointer(&session)), uintptr(unsafe.Pointer(&engine))))
	return engine, wrap("FwpmEngineOpen0", err)
}

func closeEngine(engine windows.Handle) {
	procFwpmEngineClose0.Call(uintptr(engine))
}

func inTransaction(engine windows.Handle, body func() error) error {
	if err := fwpmResult(procFwpmTransactionBegin0.Call(uintptr(engine), 0)); err != nil {
		return wrap("FwpmTransactionBegin0", err)
	}
	if err := body(); err != nil {
		procFwpmTransactionAbort0.Call(uintptr(engine))
		return err
	}
	return wrap("FwpmTransactionCommit0", fwpmResult(procFwpmTransactionCommit0.Call(uintptr(engine))))
}

func sublayerExists(engine windows.Handle) (bool, error) {
	var sublayer *fwpmSublayer0
	err := fwpmResult(procFwpmSubLayerGetByKey0.Call(uintptr(engine), uintptr(unsafe.Pointer(&keys.sublayer)), uintptr(unsafe.Pointer(&sublayer))))
	if sublayer != nil {
		procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&sublayer)))
	}
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, errSubLayerNotFound):
		return false, nil
	default:
		return false, wrap("FwpmSubLayerGetByKey0", err)
	}
}

// remove deletes the filters, then the sublayer and the provider. Filters
// cannot exist without the sublayer, so its absence ends the search early:
// the common case, nothing engaged, costs two calls.
func remove(engine windows.Handle) error {
	present, err := sublayerExists(engine)
	if err != nil {
		return err
	}
	if present {
		for i := range maxRules {
			key := keys.filterKey(i)
			err := fwpmResult(procFwpmFilterDeleteByKey0.Call(uintptr(engine), uintptr(unsafe.Pointer(&key))))
			if err != nil && !errors.Is(err, errFilterNotFound) {
				return wrap("FwpmFilterDeleteByKey0", err)
			}
		}
		err := fwpmResult(procFwpmSubLayerDeleteByKey0.Call(uintptr(engine), uintptr(unsafe.Pointer(&keys.sublayer))))
		if err != nil && !errors.Is(err, errSubLayerNotFound) {
			return wrap("FwpmSubLayerDeleteByKey0", err)
		}
	}
	err = fwpmResult(procFwpmProviderDeleteByKey0.Call(uintptr(engine), uintptr(unsafe.Pointer(&keys.provider))))
	if err != nil && !errors.Is(err, errProviderNotFound) {
		return wrap("FwpmProviderDeleteByKey0", err)
	}
	return nil
}

func install(engine windows.Handle, o Options, rules []rule, appIDs []*fwpByteBlob, sd *windows.SECURITY_DESCRIPTOR) error {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	text := func(s string) *uint16 {
		p, _ := windows.UTF16PtrFromString(s)
		return p
	}
	var providerFlags, sublayerFlags, filterFlags uint32
	if o.Persistent {
		providerFlags, sublayerFlags, filterFlags = fwpmProviderFlagPersistent, fwpmSubLayerFlagPersistent, fwpmFilterFlagPersistent
	}

	provider := fwpmProvider0{
		providerKey: keys.provider,
		displayData: fwpmDisplayData0{name: text("HYPER CLIENT"), description: text("Kill switch of the HYPER CLIENT VPN")},
		flags:       providerFlags,
	}
	if err := fwpmResult(procFwpmProviderAdd0.Call(uintptr(engine), uintptr(unsafe.Pointer(&provider)), uintptr(unsafe.Pointer(sd)))); err != nil {
		return wrap("FwpmProviderAdd0", err)
	}
	providerKey := keys.provider
	sublayer := fwpmSublayer0{
		subLayerKey: keys.sublayer,
		displayData: fwpmDisplayData0{name: text("HYPER CLIENT kill switch")},
		flags:       sublayerFlags,
		providerKey: &providerKey,
		weight:      sublayerWeight,
	}
	if err := fwpmResult(procFwpmSubLayerAdd0.Call(uintptr(engine), uintptr(unsafe.Pointer(&sublayer)), uintptr(unsafe.Pointer(sd)))); err != nil {
		return wrap("FwpmSubLayerAdd0", err)
	}

	for i, r := range rules {
		conditions := make([]fwpmFilterCondition0, len(r.conditions))
		for j, c := range r.conditions {
			conditions[j] = wfpCondition(c, appIDs, &pinner)
		}
		action := uint32(fwpActionBlock)
		if r.permit {
			action = fwpActionPermit
		}
		filter := fwpmFilter0{
			filterKey:           keys.filterKey(i),
			displayData:         fwpmDisplayData0{name: text(fmt.Sprintf("HYPER CLIENT kill switch: %s (%s)", r.name, r.layer))},
			flags:               filterFlags,
			providerKey:         &providerKey,
			layerKey:            layerKeys[r.layer],
			subLayerKey:         keys.sublayer,
			weight:              fwpValue0{typ: fwpUint8, value: uintptr(r.weight)},
			numFilterConditions: uint32(len(conditions)),
			action:              fwpmAction0{typ: action},
		}
		if len(conditions) > 0 {
			filter.filterCondition = &conditions[0]
		}
		if err := fwpmResult(procFwpmFilterAdd0.Call(uintptr(engine), uintptr(unsafe.Pointer(&filter)), uintptr(unsafe.Pointer(sd)), 0)); err != nil {
			return fmt.Errorf("FwpmFilterAdd0 failed for %q (%s): %w", r.name, r.layer, err)
		}
	}
	return nil
}

// wfpCondition converts c. Values larger than 32 bits are held by pointer as
// uintptr, which the garbage collector does not see: pinner keeps them alive
// and in place until the filters are added.
func wfpCondition(c condition, appIDs []*fwpByteBlob, pinner *runtime.Pinner) fwpmFilterCondition0 {
	equal := func(field windows.GUID, typ uint32, value uintptr) fwpmFilterCondition0 {
		return fwpmFilterCondition0{fieldKey: field, matchType: fwpMatchEqual, conditionValue: fwpValue0{typ: typ, value: value}}
	}
	switch c.kind {
	case condApp:
		return equal(conditionALEAppID, fwpByteBlobType, uintptr(unsafe.Pointer(appIDs[c.number])))
	case condLoopback:
		return fwpmFilterCondition0{fieldKey: conditionFlags, matchType: fwpMatchFlagsAll, conditionValue: fwpValue0{typ: fwpUint32, value: fwpFlagIsLoopback}}
	case condInterface:
		luid := new(uint64)
		*luid = c.number
		pinner.Pin(luid)
		return equal(conditionLocalInterface, fwpUint64, uintptr(unsafe.Pointer(luid)))
	case condProtocol:
		return equal(conditionIPProtocol, fwpUint8, uintptr(c.number))
	case condLocalPort:
		return equal(conditionIPLocalPort, fwpUint16, uintptr(c.number))
	case condRemotePort:
		return equal(conditionIPRemotePort, fwpUint16, uintptr(c.number))
	case condRemotePrefix:
		if c.prefix.Addr().Is4() {
			addr := c.prefix.Addr().As4()
			v4 := &fwpV4AddrAndMask{
				addr: binary.BigEndian.Uint32(addr[:]),
				mask: ^uint32(0) << (32 - c.prefix.Bits()),
			}
			pinner.Pin(v4)
			return equal(conditionIPRemoteAddress, fwpV4AddrMask, uintptr(unsafe.Pointer(v4)))
		}
		v6 := &fwpV6AddrAndMask{addr: c.prefix.Addr().As16(), prefixLength: uint8(c.prefix.Bits())}
		pinner.Pin(v6)
		return equal(conditionIPRemoteAddress, fwpV6AddrMask, uintptr(unsafe.Pointer(v6)))
	}
	panic(fmt.Sprintf("unknown kill switch condition %d", c.kind))
}

func appIDsOf(paths []string) ([]*fwpByteBlob, error) {
	if err := modfwpuclnt.Load(); err != nil {
		return nil, err
	}
	var ids []*fwpByteBlob
	for _, path := range paths {
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			freeAll(ids)
			return nil, err
		}
		var id *fwpByteBlob
		if err := fwpmResult(procFwpmGetAppIdFromFileName0.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&id)))); err != nil {
			freeAll(ids)
			return nil, fmt.Errorf("FwpmGetAppIdFromFileName0 failed for %s: %w", path, err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func freeAll(ids []*fwpByteBlob) {
	for i := range ids {
		procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&ids[i])))
	}
}

// securityDescriptor gives administrators and the system full control, and
// the user who runs the Core rightsOfUser.
func securityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return windows.SecurityDescriptorFromString(fmt.Sprintf(
		"O:BAG:BAD:(A;;GA;;;BA)(A;;GA;;;SY)(A;;0x%x;;;%s)", rightsOfUser, user.User.Sid,
	))
}

func wrap(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s failed: %w", operation, err)
}
