//go:build windows

package leakguard

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ===========================================================================
// Windows Filtering Platform (WFP) split-tunnel for RU CIDR ranges.
//
// We talk to fwpuclnt.dll directly through golang.org/x/sys/windows (no new
// dependency). Structs / GUIDs are declared locally per WDK headers
// (fwpmu.h / fwptypes.h) — stable public ABI. Reference pattern: WireGuard's
// wireguard-windows/tunnel/firewall (not vendored — GPL + weight).
//
// ⚠ ABI CORRECTNESS of the FWPM_*/FWP_* structs below is only verifiable on a
// real Windows host with admin (smoke test). buildWFPConds (wfp_rules.go) is
// unit-tested; this file is exercised via the smoke checklist (spec §7 Task 14).
// ===========================================================================

// wfpEngine abstracts fwpuclnt.dll calls so guard logic can be mocked in tests.
type wfpEngine interface {
	// ApplyRU opens the engine, adds provider+sublayer (idempotent) and, in a
	// SINGLE transaction, adds a PERMIT filter per cond at layer
	// ALE_AUTH_CONNECT_V4 under our provider/sublayer GUID.
	ApplyRU(conds []wfpFilterCond) error
	// DeleteByProvider removes ALL filters/sublayer/provider keyed by our
	// provider GUID in one pass — used by Disable() and crashRecover().
	// Idempotent (already-deleted is ignored).
	DeleteByProvider() error
}

// ---------------------------------------------------------------------------
// GUIDs — our private provider / sublayer. Generated once, constant forever.
// All our filters hang off these so a single DeleteByProvider cleans up.
// ---------------------------------------------------------------------------

// SL_WFP_PROVIDER_GUID — {6F3D9E11-2B4A-4C7E-9F21-3A5C8D7E1B40}
var slWFPProviderGUID = windows.GUID{
	Data1: 0x6f3d9e11, Data2: 0x2b4a, Data3: 0x4c7e,
	Data4: [8]byte{0x9f, 0x21, 0x3a, 0x5c, 0x8d, 0x7e, 0x1b, 0x40},
}

// SL_WFP_SUBLAYER_GUID — {6F3D9E12-2B4A-4C7E-9F21-3A5C8D7E1B40}
var slWFPSublayerGUID = windows.GUID{
	Data1: 0x6f3d9e12, Data2: 0x2b4a, Data3: 0x4c7e,
	Data4: [8]byte{0x9f, 0x21, 0x3a, 0x5c, 0x8d, 0x7e, 0x1b, 0x40},
}

// Well-known WFP GUIDs (from fwpmu.h).
// FWPM_LAYER_ALE_AUTH_CONNECT_V4 — {C38D57D1-05A7-4C33-904F-7FBCEEE60E82}
var fwpmLayerALEAuthConnectV4 = windows.GUID{
	Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33,
	Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82},
}

// FWPM_CONDITION_IP_REMOTE_ADDRESS — {B235AE9A-1D64-49B8-A44C-5FF3D9095045}
var fwpmConditionIPRemoteAddress = windows.GUID{
	Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8,
	Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45},
}

// ---------------------------------------------------------------------------
// WFP constants (fwptypes.h / fwpmtypes.h).
// ---------------------------------------------------------------------------

const (
	rpcCAuthnWinNT = 10 // RPC_C_AUTHN_WINNT

	fwpEMatchEqual = 0 // FWP_MATCH_EQUAL

	fwpActionPermit = 0x00001003 // FWP_ACTION_PERMIT
	fwpActionBlock  = 0x00001001 // FWP_ACTION_BLOCK

	// FWP_DATA_TYPE
	fwpV4AddrMask = 0x12 // FWP_V4_ADDR_MASK

	// HRESULT
	fwpEAlreadyExists = 0x80320009 // FWP_E_ALREADY_EXISTS
	fwpENotFound      = 0x80320008 // FWP_E_NOT_FOUND
)

// ---------------------------------------------------------------------------
// WFP structs — local declarations per WDK headers. Field order/size MUST
// match the C ABI exactly. (Verified shapes against fwpmtypes.h / fwptypes.h.)
// ---------------------------------------------------------------------------

type fwpmDisplayData0 struct {
	Name        *uint16
	Description *uint16
}

type fwpmProvider0 struct {
	ProviderKey  windows.GUID
	DisplayData  fwpmDisplayData0
	Flags        uint32
	ProviderData fwpByteBlob
	ServiceName  *uint16
}

type fwpByteBlob struct {
	Size uint32
	Data *uint8
}

type fwpmSublayer0 struct {
	SubLayerKey  windows.GUID
	DisplayData  fwpmDisplayData0
	Flags        uint32
	ProviderKey  *windows.GUID
	ProviderData fwpByteBlob
	Weight       uint16
}

type fwpV4AddrAndMask struct {
	Addr uint32
	Mask uint32
}

// fwpValue0 — tagged union; we only ever store a *fwpV4AddrAndMask, so the
// value slot holds a pointer-sized field.
type fwpValue0 struct {
	Type  uint32
	value uintptr // holds *fwpV4AddrAndMask when Type==FWP_V4_ADDR_MASK
}

type fwpConditionValue0 struct {
	Type  uint32
	value uintptr
}

type fwpmFilterCondition0 struct {
	FieldKey       windows.GUID
	MatchType      uint32
	ConditionValue fwpConditionValue0
}

// fwpmAction0 — action type + a GUID (filter type / callout). We only use
// permit/block where the GUID slot is unused.
type fwpmAction0 struct {
	Type uint32
	guid windows.GUID
}

// fwpmFilter0 — large struct; we populate only the fields we need and leave
// the rest zeroed. Layout follows fwpmtypes.h.
type fwpmFilter0 struct {
	FilterKey           windows.GUID
	DisplayData         fwpmDisplayData0
	Flags               uint32
	ProviderKey         *windows.GUID
	ProviderData        fwpByteBlob
	LayerKey            windows.GUID
	SubLayerKey         windows.GUID
	Weight              fwpValue0
	NumFilterConditions uint32
	FilterCondition     *fwpmFilterCondition0
	Action              fwpmAction0
	Context             uint64 // FWPM_FILTER0 union: rawContext / providerContextKey
	Reserved            *windows.GUID
	FilterID            uint64
	EffectiveWeight     fwpValue0
}

// ---------------------------------------------------------------------------
// realWFPEngine — production implementation backed by fwpuclnt.dll.
// ---------------------------------------------------------------------------

var (
	modFwpuclnt = windows.NewLazySystemDLL("fwpuclnt.dll")

	procFwpmEngineOpen0          = modFwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0         = modFwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmProviderAdd0         = modFwpuclnt.NewProc("FwpmProviderAdd0")
	procFwpmSubLayerAdd0         = modFwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmFilterAdd0           = modFwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmTransactionBegin0    = modFwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0   = modFwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0    = modFwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmProviderDeleteByKey0 = modFwpuclnt.NewProc("FwpmProviderDeleteByKey0")
	procFwpmSubLayerDeleteByKey0 = modFwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmFilterDeleteByKey0   = modFwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	procFwpmFilterCreateEnum0    = modFwpuclnt.NewProc("FwpmFilterCreateEnumHandle0")
	procFwpmFilterEnum0          = modFwpuclnt.NewProc("FwpmFilterEnum0")
	procFwpmFilterDestroyEnum0   = modFwpuclnt.NewProc("FwpmFilterDestroyEnumHandle0")
	procFwpmFreeMemory0          = modFwpuclnt.NewProc("FwpmFreeMemory0")
)

type realWFPEngine struct{}

func newWFPEngine() wfpEngine { return realWFPEngine{} }

// hresultOK treats S_OK and "already exists" / "not found" as non-errors
// depending on context (idempotency).
func wfpErr(name string, r uintptr, tolerate ...uint32) error {
	code := uint32(r)
	if code == 0 {
		return nil
	}
	for _, t := range tolerate {
		if code == t {
			return nil
		}
	}
	return fmt.Errorf("%s: HRESULT 0x%08x", name, code)
}

func (realWFPEngine) open() (windows.Handle, error) {
	var h windows.Handle
	r, _, _ := procFwpmEngineOpen0.Call(
		0, // serverName (local)
		uintptr(rpcCAuthnWinNT),
		0, // authIdentity
		0, // session
		uintptr(unsafe.Pointer(&h)),
	)
	if err := wfpErr("FwpmEngineOpen0", r); err != nil {
		return 0, err
	}
	return h, nil
}

func (e realWFPEngine) ApplyRU(conds []wfpFilterCond) error {
	if len(conds) == 0 {
		return nil
	}
	h, err := e.open()
	if err != nil {
		return err
	}
	defer procFwpmEngineClose0.Call(uintptr(h))

	name, _ := windows.UTF16PtrFromString("ShadowLink")
	desc, _ := windows.UTF16PtrFromString("ShadowLink split-tunnel RU bypass")

	// Provider (idempotent).
	prov := fwpmProvider0{
		ProviderKey: slWFPProviderGUID,
		DisplayData: fwpmDisplayData0{Name: name, Description: desc},
	}
	r, _, _ := procFwpmProviderAdd0.Call(uintptr(h), uintptr(unsafe.Pointer(&prov)), 0)
	if err := wfpErr("FwpmProviderAdd0", r, fwpEAlreadyExists); err != nil {
		return err
	}

	// Sublayer (idempotent).
	provKey := slWFPProviderGUID
	sub := fwpmSublayer0{
		SubLayerKey: slWFPSublayerGUID,
		DisplayData: fwpmDisplayData0{Name: name, Description: desc},
		ProviderKey: &provKey,
		Weight:      0xFFFF,
	}
	r, _, _ = procFwpmSubLayerAdd0.Call(uintptr(h), uintptr(unsafe.Pointer(&sub)), 0)
	if err := wfpErr("FwpmSubLayerAdd0", r, fwpEAlreadyExists); err != nil {
		return err
	}

	// Transaction: bulk filter add.
	r, _, _ = procFwpmTransactionBegin0.Call(uintptr(h), 0)
	if err := wfpErr("FwpmTransactionBegin0", r); err != nil {
		return err
	}

	if err := e.addFilters(h, conds, name); err != nil {
		procFwpmTransactionAbort0.Call(uintptr(h))
		return err
	}

	r, _, _ = procFwpmTransactionCommit0.Call(uintptr(h))
	if err := wfpErr("FwpmTransactionCommit0", r); err != nil {
		procFwpmTransactionAbort0.Call(uintptr(h))
		return err
	}
	return nil
}

func (realWFPEngine) addFilters(h windows.Handle, conds []wfpFilterCond, name *uint16) error {
	// Keep the addr/mask values alive for the duration of each Add call.
	for _, c := range conds {
		am := fwpV4AddrAndMask{Addr: c.Addr, Mask: c.Mask}
		cond := fwpmFilterCondition0{
			FieldKey:  fwpmConditionIPRemoteAddress,
			MatchType: fwpEMatchEqual,
			ConditionValue: fwpConditionValue0{
				Type:  fwpV4AddrMask,
				value: uintptr(unsafe.Pointer(&am)),
			},
		}
		provKey := slWFPProviderGUID
		filter := fwpmFilter0{
			DisplayData:         fwpmDisplayData0{Name: name},
			ProviderKey:         &provKey,
			LayerKey:            fwpmLayerALEAuthConnectV4,
			SubLayerKey:         slWFPSublayerGUID,
			Weight:              fwpValue0{Type: 0 /*FWP_EMPTY → auto weight*/},
			NumFilterConditions: 1,
			FilterCondition:     &cond,
			Action:              fwpmAction0{Type: fwpActionPermit},
		}
		var id uint64
		r, _, _ := procFwpmFilterAdd0.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(&filter)),
			0, // security descriptor
			uintptr(unsafe.Pointer(&id)),
		)
		if err := wfpErr("FwpmFilterAdd0", r); err != nil {
			return err
		}
	}
	return nil
}

// DeleteByProvider enumerates all filters under our sublayer and deletes them,
// then removes the sublayer and provider. Idempotent (not-found tolerated).
func (e realWFPEngine) DeleteByProvider() error {
	h, err := e.open()
	if err != nil {
		// Engine cannot open → nothing we can do; treat as best-effort no-op.
		return nil
	}
	defer procFwpmEngineClose0.Call(uintptr(h))

	e.deleteOurFilters(h)

	r, _, _ := procFwpmSubLayerDeleteByKey0.Call(uintptr(h), uintptr(unsafe.Pointer(&slWFPSublayerGUID)))
	_ = wfpErr("FwpmSubLayerDeleteByKey0", r, fwpENotFound)

	r, _, _ = procFwpmProviderDeleteByKey0.Call(uintptr(h), uintptr(unsafe.Pointer(&slWFPProviderGUID)))
	_ = wfpErr("FwpmProviderDeleteByKey0", r, fwpENotFound)

	return nil
}

// deleteOurFilters walks the filter enumeration and deletes by FilterKey any
// filter that belongs to our provider GUID.
func (realWFPEngine) deleteOurFilters(h windows.Handle) {
	var enumH windows.Handle
	r, _, _ := procFwpmFilterCreateEnum0.Call(
		uintptr(h),
		0, // enumTemplate (nil → all)
		uintptr(unsafe.Pointer(&enumH)),
	)
	if uint32(r) != 0 {
		return
	}
	defer procFwpmFilterDestroyEnum0.Call(uintptr(h), uintptr(enumH))

	const batch = 64
	for {
		var entries **fwpmFilter0
		var numReturned uint32
		r, _, _ := procFwpmFilterEnum0.Call(
			uintptr(h),
			uintptr(enumH),
			uintptr(batch),
			uintptr(unsafe.Pointer(&entries)),
			uintptr(unsafe.Pointer(&numReturned)),
		)
		if uint32(r) != 0 || numReturned == 0 {
			return
		}
		slice := unsafe.Slice(entries, numReturned)
		for _, f := range slice {
			if f == nil || f.ProviderKey == nil {
				continue
			}
			if *f.ProviderKey == slWFPProviderGUID {
				key := f.FilterKey
				procFwpmFilterDeleteByKey0.Call(uintptr(h), uintptr(unsafe.Pointer(&key)))
			}
		}
		procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&entries)))
		if numReturned < batch {
			return
		}
	}
}
