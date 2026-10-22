"""
MoltenVK / Vulkan loader.

The guest is arm64, so the copy of libMoltenVK inside a .app cannot be dlopened
on an Intel Mac. dlopen of libMoltenVK.dylib (see hostsys.py) and the direct
imports below both land on the HOST Vulkan loader, which on a Mac is MoltenVK
sitting on the host's Metal driver. vkGetInstanceProcAddr returns guest stubs
whose marshalling copies the structs across the Unicorn boundary.

Set ARM2X86_MOLTENVK=/path/to/libMoltenVK.dylib if it is not on the default search path.
"""
import os, sys, ctypes, struct
from hle import fn, FUNCS, M64, s32, s64

VK_SUCCESS = 0
VK_NOT_READY = 1
VK_ERROR_INITIALIZATION_FAILED = -3
VK_ERROR_EXTENSION_NOT_PRESENT = -7
VK_WHOLE_SIZE = (1 << 64) - 1
U64 = ctypes.c_uint64
U32 = ctypes.c_uint32
I32 = ctypes.c_int32
F32 = ctypes.c_float
BOOL = ctypes.c_uint32

def _limits():
    # Field order is the Vulkan 1.0/1.3 VkPhysicalDeviceLimits. New limits live in pNext.
    u, d, s, b, f = U32, U64, ctypes.c_size_t, BOOL, F32
    fields = [
        ("maxImageDimension1D", u), ("maxImageDimension2D", u), ("maxImageDimension3D", u),
        ("maxImageDimensionCube", u), ("maxImageArrayLayers", u), ("maxTexelBufferElements", u),
        ("maxUniformBufferRange", u), ("maxStorageBufferRange", u), ("maxPushConstantsSize", u),
        ("maxMemoryAllocationCount", u), ("maxSamplerAllocationCount", u),
        ("bufferImageGranularity", d), ("sparseAddressSpaceSize", d),
        ("maxBoundDescriptorSets", u), ("maxPerStageDescriptorSamplers", u),
        ("maxPerStageDescriptorUniformBuffers", u), ("maxPerStageDescriptorStorageBuffers", u),
        ("maxPerStageDescriptorSampledImages", u), ("maxPerStageDescriptorStorageImages", u),
        ("maxPerStageDescriptorInputAttachments", u), ("maxPerStageResources", u),
        ("maxDescriptorSetSamplers", u), ("maxDescriptorSetUniformBuffers", u),
        ("maxDescriptorSetUniformBuffersDynamic", u), ("maxDescriptorSetStorageBuffers", u),
        ("maxDescriptorSetStorageBuffersDynamic", u), ("maxDescriptorSetSampledImages", u),
        ("maxDescriptorSetStorageImages", u), ("maxDescriptorSetInputAttachments", u),
        ("maxVertexInputAttributes", u), ("maxVertexInputBindings", u),
        ("maxVertexInputAttributeOffset", u), ("maxVertexInputBindingStride", u),
        ("maxVertexOutputComponents", u), ("maxTessellationGenerationLevel", u),
        ("maxTessellationPatchSize", u), ("maxTessellationControlPerVertexInputComponents", u),
        ("maxTessellationControlPerVertexOutputComponents", u),
        ("maxTessellationControlPerPatchOutputComponents", u),
        ("maxTessellationControlTotalOutputComponents", u),
        ("maxTessellationEvaluationInputComponents", u), ("maxTessellationEvaluationOutputComponents", u),
        ("maxGeometryShaderInvocations", u), ("maxGeometryInputComponents", u),
        ("maxGeometryOutputComponents", u), ("maxGeometryOutputVertices", u),
        ("maxGeometryTotalOutputComponents", u), ("maxFragmentInputComponents", u),
        ("maxFragmentOutputAttachments", u), ("maxFragmentDualSrcAttachments", u),
        ("maxFragmentCombinedOutputResources", u), ("maxComputeSharedMemorySize", u),
        ("maxComputeWorkGroupCount", u * 3), ("maxComputeWorkGroupInvocations", u),
        ("maxComputeWorkGroupSize", u * 3), ("subPixelPrecisionBits", u),
        ("subTexelPrecisionBits", u), ("mipmapPrecisionBits", u), ("maxDrawIndexedIndexValue", u),
        ("maxDrawIndirectCount", u), ("maxSamplerLodBias", f), ("maxSamplerAnisotropy", f),
        ("maxViewports", u), ("maxViewportDimensions", u * 2), ("viewportBoundsRange", f * 2),
        ("viewportSubPixelBits", u), ("minMemoryMapAlignment", s),
        ("minTexelBufferOffsetAlignment", d), ("minUniformBufferOffsetAlignment", d),
        ("minStorageBufferOffsetAlignment", d), ("minTexelOffset", I32), ("maxTexelOffset", u),
        ("minTexelGatherOffset", I32), ("maxTexelGatherOffset", u),
        ("minInterpolationOffset", f), ("maxInterpolationOffset", f),
        ("subPixelInterpolationOffsetBits", u), ("maxFramebufferWidth", u),
        ("maxFramebufferHeight", u), ("maxFramebufferLayers", u),
        ("framebufferColorSampleCounts", u), ("framebufferDepthSampleCounts", u),
        ("framebufferStencilSampleCounts", u), ("framebufferNoAttachmentsSampleCounts", u),
        ("maxColorAttachments", u), ("sampledImageColorSampleCounts", u),
        ("sampledImageIntegerSampleCounts", u), ("sampledImageDepthSampleCounts", u),
        ("sampledImageStencilSampleCounts", u), ("storageImageSampleCounts", u),
        ("maxSampleMaskWords", u), ("timestampComputeAndGraphics", b), ("timestampPeriod", f),
        ("maxClipDistances", u), ("maxCullDistances", u), ("maxCombinedClipAndCullDistances", u),
        ("discreteQueuePriorities", u), ("pointSizeRange", f * 2), ("lineWidthRange", f * 2),
        ("pointSizeGranularity", f), ("lineWidthGranularity", f), ("strictLines", b),
        ("standardSampleLocations", b), ("optimalBufferCopyOffsetAlignment", d),
        ("optimalBufferCopyRowPitchAlignment", d), ("nonCoherentAtomSize", d),
    ]
    class Limits(ctypes.Structure):
        _fields_ = fields
    return Limits
Limits = _limits()

class Sparse(ctypes.Structure):
    _fields_ = [(n, BOOL) for n in
                ("residencyStandard2DBlockShape", "residencyStandard2DMultisampleBlockShape",
                 "residencyStandard3DBlockShape", "residencyAlignedMipSize", "residencyNonResidentStrict")]
class Props(ctypes.Structure):
    _fields_ = [("apiVersion", U32), ("driverVersion", U32), ("vendorID", U32), ("deviceID", U32),
                ("deviceType", U32), ("deviceName", ctypes.c_char * 256),
                ("pipelineCacheUUID", ctypes.c_uint8 * 16), ("limits", Limits), ("sparse", Sparse)]
class MemType(ctypes.Structure):
    _fields_ = [("propertyFlags", U32), ("heapIndex", U32)]
class MemHeap(ctypes.Structure):
    _fields_ = [("size", U64), ("flags", U32), ("_pad", U32)]
class MemProps(ctypes.Structure):
    _fields_ = [("memoryTypeCount", U32), ("memoryTypes", MemType * 32),
                ("memoryHeapCount", U32), ("memoryHeaps", MemHeap * 16)]
class QFam(ctypes.Structure):
    _fields_ = [("queueFlags", U32), ("queueCount", U32), ("timestampValidBits", U32),
                ("w", U32), ("h", U32), ("d", U32)]
class MemReqs(ctypes.Structure):
    _fields_ = [("size", U64), ("alignment", U64), ("memoryTypeBits", U32), ("_pad", U32)]

# Sanity: these sizes are part of the LP64 Vulkan ABI. If they drift, marshalling is wrong.
ABI_SIZES = {
    "VkPhysicalDeviceLimits": 504,
    "VkPhysicalDeviceProperties": 824,
    "VkPhysicalDeviceMemoryProperties": 520,
    "VkQueueFamilyProperties": 24,
    "VkMemoryRequirements": 24,
    "VkPhysicalDeviceFeatures": 220,
}

_LIB = None
_TRIED = False
_SHADOWS = []          # (host_ptr, guest_ptr, length)
_MEMSIZE = {}

def lib():
    global _LIB, _TRIED
    if _TRIED: return _LIB
    _TRIED = True
    cands = [os.environ.get("ARM2X86_MOLTENVK"), os.environ.get("ARM2X86_VULKAN"),
             "libMoltenVK.dylib", "/usr/local/lib/libMoltenVK.dylib",
             os.path.expanduser("~/VulkanSDK/macOS/lib/libMoltenVK.dylib"),
             "/opt/homebrew/lib/libMoltenVK.dylib",
             "libvulkan.1.dylib", "libvulkan.so.1", "libvulkan.so", "libMoltenVK.so"]
    for c in cands:
        if not c: continue
        try:
            _LIB = ctypes.CDLL(c)
            sys.stderr.write(f"[vulkan] loaded host {c}\n")
            return _LIB
        except OSError:
            continue
    return None

def _sym(name):
    L = lib()
    if not L: return None
    try:
        return getattr(L, name)
    except AttributeError:
        return None

def _cstrs(e, ptr, n):
    out = []
    for i in range(n):
        p = int.from_bytes(e.read(ptr + 8 * i, 8), "little")
        out.append(e.cstr(p).encode() + b"\0" if p else b"\0")
    return out

def _out(e, ptr, obj):
    e.write(ptr, bytes(obj))

@fn("vkGetInstanceProcAddr")
def _gipa(e):
    name = e.cstr(e.arg(1))
    if "_" + name in FUNCS:
        return e.resolve("_" + name)
    return 0
@fn("vkGetDeviceProcAddr")
def _gdpa(e):
    name = e.cstr(e.arg(1))
    if "_" + name in FUNCS:
        return e.resolve("_" + name)
    return 0
@fn("vkEnumerateInstanceVersion")
def _eiv(e):
    fn_ = _sym("vkEnumerateInstanceVersion")
    if not fn_:
        if e.arg(0): e.write(e.arg(0), (1 << 22).to_bytes(4, "little"))  # 1.0.0
        return 0
    v = U32(0)
    fn_.restype = I32; fn_.argtypes = [ctypes.POINTER(U32)]
    r = fn_(ctypes.byref(v))
    if e.arg(0): e.write(e.arg(0), struct.pack("<I", v.value))
    return r

@fn("vkEnumerateInstanceExtensionProperties")
def _eiep(e):
    layer = e.cstr(e.arg(0)).encode() + b"\0" if e.arg(0) else None
    fn_ = _sym("vkEnumerateInstanceExtensionProperties")
    if not fn_:
        return VK_ERROR_INITIALIZATION_FAILED
    fn_.restype = I32
    # VkExtensionProperties { char name[256]; uint32_t specVersion; } = 260
    class Ext(ctypes.Structure):
        _fields_ = [("name", ctypes.c_char * 256), ("ver", U32)]
    cnt = U32(0)
    fn_.argtypes = [ctypes.c_char_p, ctypes.POINTER(U32), ctypes.c_void_p]
    r = fn_(layer, ctypes.byref(cnt), None)
    if r != 0: return r
    if e.arg(1): e.write(e.arg(1), struct.pack("<I", cnt.value))
    if e.arg(2) and cnt.value:
        arr = (Ext * cnt.value)()
        r = fn_(layer, ctypes.byref(cnt), ctypes.byref(arr))
        e.write(e.arg(2), bytes(arr))
    return r

@fn("vkCreateInstance")
def _ci(e):
    info, alloc, outp = e.arg(0), e.arg(1), e.arg(2)
    fn_ = _sym("vkCreateInstance")
    if not fn_ or not info:
        return VK_ERROR_INITIALIZATION_FAILED
    # VkInstanceCreateInfo, 64 bytes on LP64 (see loader notes).
    raw = bytes(e.read(info, 64))
    sType, pNext, flags = struct.unpack_from("<I", raw, 0)[0], struct.unpack_from("<Q", raw, 8)[0], struct.unpack_from("<I", raw, 16)[0]
    pApp = struct.unpack_from("<Q", raw, 24)[0]
    nLayer = struct.unpack_from("<I", raw, 32)[0]
    pLayer = struct.unpack_from("<Q", raw, 40)[0]
    nExt = struct.unpack_from("<I", raw, 48)[0]
    pExt = struct.unpack_from("<Q", raw, 56)[0]
    if pNext and os.environ.get("ARM2X86_VERBOSE"):
        sys.stderr.write("[vulkan] VkInstanceCreateInfo.pNext ignored\n")
    app = None
    if pApp:
        ab = bytes(e.read(pApp, 48))
        class App(ctypes.Structure):
            _fields_ = [("sType", U32), ("_p", U32), ("pNext", ctypes.c_void_p),
                        ("pApplicationName", ctypes.c_char_p), ("applicationVersion", U32),
                        ("_p2", U32), ("pEngineName", ctypes.c_char_p), ("engineVersion", U32),
                        ("apiVersion", U32)]
        # Don't trust ctypes padding for the hand-built one; call with a byte-faithful buffer
        # rebuilt field by field below.
        an = struct.unpack_from("<Q", ab, 16)[0]
        av = struct.unpack_from("<I", ab, 24)[0]
        en = struct.unpack_from("<Q", ab, 32)[0]
        ev = struct.unpack_from("<I", ab, 40)[0]
        api = struct.unpack_from("<I", ab, 44)[0]
        class AppI(ctypes.Structure):
            _fields_ = [("sType", U32), ("pad", U32), ("pNext", ctypes.c_void_p),
                        ("pApplicationName", ctypes.c_char_p), ("applicationVersion", U32),
                        ("pad2", U32), ("pEngineName", ctypes.c_char_p), ("engineVersion", U32),
                        ("apiVersion", U32), ("pad3", U32)]
        app = AppI(struct.unpack_from("<I", ab, 0)[0], 0, None,
                   e.cstr(an).encode() + b"\0" if an else None, av, 0,
                   e.cstr(en).encode() + b"\0" if en else None, ev, api, 0)
    layers = _cstrs(e, pLayer, nLayer) if pLayer and nLayer else []
    exts = _cstrs(e, pExt, nExt) if pExt and nExt else []
    LayerArr = ctypes.c_char_p * max(len(layers), 1)
    ExtArr = ctypes.c_char_p * max(len(exts), 1)
    la, ea = LayerArr(*layers), ExtArr(*exts)
    class CI(ctypes.Structure):
        _fields_ = [("sType", U32), ("pad", U32), ("pNext", ctypes.c_void_p), ("flags", U32),
                    ("pad2", U32), ("pApplicationInfo", ctypes.c_void_p),
                    ("enabledLayerCount", U32), ("pad3", U32), ("ppEnabledLayerNames", ctypes.c_void_p),
                    ("enabledExtensionCount", U32), ("pad4", U32), ("ppEnabledExtensionNames", ctypes.c_void_p)]
    ci = CI(sType, 0, None, flags, 0, ctypes.addressof(app) if app else None,
            len(layers), 0, ctypes.addressof(la) if layers else None,
            len(exts), 0, ctypes.addressof(ea) if exts else None)
    inst = ctypes.c_void_p()
    fn_.restype = I32
    fn_.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    r = fn_(ctypes.byref(ci), None, ctypes.byref(inst))
    if outp: e.write(outp, struct.pack("<Q", inst.value or 0))
    return r

def _pod(name, index_out, ctype, pre_args):
    """pre_args: list of ('i'|'p') consumed before the output pointer."""
    def f(e, name=name, index_out=index_out, ctype=ctype, pre_args=pre_args):
        fn_ = _sym(name)
        if not fn_: return VK_ERROR_INITIALIZATION_FAILED
        args = []
        types = []
        for k, kind in enumerate(pre_args):
            v = e.arg(k)
            if kind == "p":
                args.append(v or None); types.append(ctypes.c_void_p)
            else:
                args.append(v & 0xffffffff); types.append(U32)
        out = ctype()
        fn_.restype = I32
        fn_.argtypes = types + [ctypes.POINTER(ctype)]
        r = fn_(*args, ctypes.byref(out))
        p = e.arg(index_out)
        if p: e.write(p, bytes(out))
        return r
    FUNCS["_" + name] = f

_pod("vkGetPhysicalDeviceProperties", 1, Props, ["p"])
_pod("vkGetPhysicalDeviceFeatures", 1, type("F", (ctypes.Structure,), {"_fields_": [(f"b{i}", BOOL) for i in range(55)]}), ["p"])
_pod("vkGetPhysicalDeviceMemoryProperties", 1, MemProps, ["p"])

@fn("vkEnumeratePhysicalDevices")
def _epd(e):
    fn_ = _sym("vkEnumeratePhysicalDevices")
    if not fn_: return VK_ERROR_INITIALIZATION_FAILED
    inst, pcount, pdevs = e.arg(0), e.arg(1), e.arg(2)
    cnt = U32(int.from_bytes(e.read(pcount, 4), "little") if pcount else 0)
    fn_.restype = I32
    if not pdevs:
        fn_.argtypes = [ctypes.c_void_p, ctypes.POINTER(U32), ctypes.c_void_p]
        r = fn_(inst, ctypes.byref(cnt), None)
        if pcount: e.write(pcount, struct.pack("<I", cnt.value))
        return r
    n = cnt.value or int.from_bytes(e.read(pcount, 4), "little")
    arr = (ctypes.c_uint64 * max(n, 1))()
    fn_.argtypes = [ctypes.c_void_p, ctypes.POINTER(U32), ctypes.POINTER(ctypes.c_uint64)]
    r = fn_(inst, ctypes.byref(cnt), arr)
    if pcount: e.write(pcount, struct.pack("<I", cnt.value))
    if n: e.write(pdevs, bytes(bytearray(arr))[:8 * cnt.value])
    return r

@fn("vkGetPhysicalDeviceQueueFamilyProperties")
def _qfp(e):
    fn_ = _sym("vkGetPhysicalDeviceQueueFamilyProperties")
    if not fn_: return None
    pd, pcount, pprops = e.arg(0), e.arg(1), e.arg(2)
    cnt = U32(int.from_bytes(e.read(pcount, 4), "little") if pcount else 0)
    fn_.restype = None
    if not pprops:
        fn_.argtypes = [ctypes.c_void_p, ctypes.POINTER(U32), ctypes.c_void_p]
        fn_(pd, ctypes.byref(cnt), None)
        if pcount: e.write(pcount, struct.pack("<I", cnt.value)); return None
    n = max(cnt.value, 1)
    arr = (QFam * n)()
    fn_.argtypes = [ctypes.c_void_p, ctypes.POINTER(U32), ctypes.POINTER(QFam)]
    fn_(pd, ctypes.byref(cnt), arr)
    if pcount: e.write(pcount, struct.pack("<I", cnt.value))
    e.write(pprops, bytes(arr)[:ctypes.sizeof(QFam) * cnt.value])
    return None

@fn("vkCreateDevice")
def _cd(e):
    fn_ = _sym("vkCreateDevice")
    if not fn_: return VK_ERROR_INITIALIZATION_FAILED
    pd, info, alloc, outp = e.arg(0), e.arg(1), e.arg(2), e.arg(3)
    raw = bytes(e.read(info, 80))
    sType = struct.unpack_from("<I", raw, 0)[0]
    flags = struct.unpack_from("<I", raw, 16)[0]
    nq = struct.unpack_from("<I", raw, 24)[0]
    pq = struct.unpack_from("<Q", raw, 32)[0]
    nl = struct.unpack_from("<I", raw, 40)[0]
    pl = struct.unpack_from("<Q", raw, 48)[0]
    ne = struct.unpack_from("<I", raw, 56)[0]
    pe = struct.unpack_from("<Q", raw, 64)[0]
    pf = struct.unpack_from("<Q", raw, 72)[0]
    class Q(ctypes.Structure):
        _fields_ = [("sType", U32), ("pad", U32), ("pNext", ctypes.c_void_p), ("flags", U32),
                    ("pad2", U32), ("queueFamilyIndex", U32), ("queueCount", U32),
                    ("pQueuePriorities", ctypes.c_void_p)]
    qs = []
    pri_bufs = []
    for i in range(nq):
        qb = bytes(e.read(pq + 56 * i, 56))  # VkDeviceQueueCreateInfo is 40? let's use 48 to be safe — spec size is 40, align 8 => 40, stride 48? 
        # Actual LP64 size: sType 0, pNext 8, flags 16, queueFamilyIndex 20, queueCount 24, pQueuePriorities 32. sizeof 40, stride 48? 
        # Arrays of create infos are tightly sizeof, which is 40, but alignment of the struct is 8 so stride is 40.
        pass
    # re-read with stride 40
    q_list = []
    for i in range(nq):
        qb = bytes(e.read(pq + 40 * i, 40))
        fam = struct.unpack_from("<I", qb, 20)[0]
        qc = struct.unpack_from("<I", qb, 24)[0]
        pp = struct.unpack_from("<Q", qb, 32)[0]
        pris = list(struct.unpack(f"<{max(qc,1)}f", bytes(e.read(pp, 4 * max(qc, 1))))) if pp and qc else [1.0]
        buf = (F32 * len(pris))(*pris); pri_bufs.append(buf)
        q_list.append((struct.unpack_from("<I", qb, 0)[0], struct.unpack_from("<I", qb, 16)[0], fam, qc, buf))
    QArr = Q * max(len(q_list), 1)
    qobjs = QArr(*[Q(st, 0, None, fl, 0, fam, qc, ctypes.addressof(buf)) for st, fl, fam, qc, buf in q_list]) if q_list else None
    exts = _cstrs(e, pe, ne) if pe and ne else []
    ExtArr = ctypes.c_char_p * max(len(exts), 1)
    ea = ExtArr(*exts)
    feats = None
    if pf:
        feats = (BOOL * 55).from_buffer_copy(bytes(e.read(pf, 220)))
    class DI(ctypes.Structure):
        _fields_ = [("sType", U32), ("pad", U32), ("pNext", ctypes.c_void_p), ("flags", U32), ("pad2", U32),
                    ("queueCreateInfoCount", U32), ("pad3", U32), ("pQueueCreateInfos", ctypes.c_void_p),
                    ("enabledLayerCount", U32), ("pad4", U32), ("ppEnabledLayerNames", ctypes.c_void_p),
                    ("enabledExtensionCount", U32), ("pad5", U32), ("ppEnabledExtensionNames", ctypes.c_void_p),
                    ("pEnabledFeatures", ctypes.c_void_p)]
    di = DI(sType, 0, None, flags, 0, nq, 0, ctypes.addressof(qobjs) if qobjs is not None else None,
            0, 0, None, len(exts), 0, ctypes.addressof(ea) if exts else None,
            ctypes.addressof(feats) if feats is not None else None)
    dev = ctypes.c_void_p()
    fn_.restype = I32
    fn_.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    r = fn_(pd, ctypes.byref(di), None, ctypes.byref(dev))
    if outp: e.write(outp, struct.pack("<Q", dev.value or 0))
    return r

@fn("vkGetDeviceQueue")
def _gdq(e):
    fn_ = _sym("vkGetDeviceQueue")
    if not fn_: return None
    q = ctypes.c_void_p()
    fn_.restype = None
    fn_.argtypes = [ctypes.c_void_p, U32, U32, ctypes.POINTER(ctypes.c_void_p)]
    fn_(e.arg(0), e.arg(1) & 0xffffffff, e.arg(2) & 0xffffffff, ctypes.byref(q))
    if e.arg(3): e.write(e.arg(3), struct.pack("<Q", q.value or 0))
    return None

def _create1(name, info_size, fix):
    """VkResult f(parent, info*, alloc, out*). `fix(e, raw) -> ctypes object or None`."""
    def f(e, name=name, info_size=info_size, fix=fix):
        fn_ = _sym(name)
        if not fn_: return VK_ERROR_INITIALIZATION_FAILED
        parent, info, outp = e.arg(0), e.arg(1), e.arg(3)
        obj = fix(e, bytes(e.read(info, info_size)) if info else b"")
        if obj is None: return VK_ERROR_INITIALIZATION_FAILED
        handle = ctypes.c_void_p()
        fn_.restype = I32
        fn_.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        r = fn_(parent, ctypes.byref(obj), None, ctypes.byref(handle))
        if outp: e.write(outp, struct.pack("<Q", handle.value or 0))
        return r
    FUNCS["_" + name] = f

class _MetalSI(ctypes.Structure):
    _fields_ = [("sType", U32), ("pad", U32), ("pNext", ctypes.c_void_p), ("flags", U32),
                ("pad2", U32), ("pLayer", ctypes.c_void_p)]
class _MacSI(ctypes.Structure):
    _fields_ = [("sType", U32), ("pad", U32), ("pNext", ctypes.c_void_p), ("flags", U32),
                ("pad2", U32), ("pView", ctypes.c_void_p)]

def _fix_metal(e, raw):
    if len(raw) < 32: return None
    return _MetalSI(struct.unpack_from("<I", raw, 0)[0], 0, None, struct.unpack_from("<I", raw, 16)[0], 0,
                    struct.unpack_from("<Q", raw, 24)[0] or None)
def _fix_mac(e, raw):
    if len(raw) < 32: return None
    return _MacSI(struct.unpack_from("<I", raw, 0)[0], 0, None, struct.unpack_from("<I", raw, 16)[0], 0,
                  struct.unpack_from("<Q", raw, 24)[0] or None)
_create1("vkCreateMetalSurfaceEXT", 32, _fix_metal)
_create1("vkCreateMacOSSurfaceMVK", 32, _fix_mac)

@fn("vkDestroySurfaceKHR")
def _ds(e):
    fn_ = _sym("vkDestroySurfaceKHR")
    if not fn_: return None
    fn_.restype = None
    fn_.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    fn_(e.arg(0), e.arg(1) or None, None); return None

def _destroy(name):
    def f(e, name=name):
        fn_ = _sym(name)
        if not fn_: return None
        fn_.restype = None
        fn_.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        fn_(e.arg(0) or None, None); return None
    FUNCS["_" + name] = f
for _n in ("vkDestroyInstance", "vkDestroyDevice", "vkDestroySwapchainKHR", "vkDestroyBuffer",
           "vkDestroyImage", "vkDestroyImageView", "vkDestroyShaderModule", "vkDestroyPipeline",
           "vkDestroyPipelineLayout", "vkDestroyRenderPass", "vkDestroyFramebuffer",
           "vkDestroyCommandPool", "vkDestroySemaphore", "vkDestroyFence", "vkDestroyDescriptorPool",
           "vkDestroyDescriptorSetLayout", "vkDestroySampler", "vkFreeMemory"):
    _destroy(_n)

@fn("vkDeviceWaitIdle")
def _dwi(e):
    fn_ = _sym("vkDeviceWaitIdle")
    if not fn_: return VK_NOT_READY
    fn_.restype = I32; fn_.argtypes = [ctypes.c_void_p]
    _sync_shadows(e)
    return fn_(e.arg(0))
@fn("vkQueueWaitIdle")
def _qwi(e):
    fn_ = _sym("vkQueueWaitIdle")
    if not fn_: return VK_NOT_READY
    fn_.restype = I32; fn_.argtypes = [ctypes.c_void_p]
    _sync_shadows(e)
    return fn_(e.arg(0))

def _sync_shadows(e):
    for hp, gp, n in _SHADOWS:
        try:
            ctypes.memmove(hp, bytes(e.read(gp, n)), n)
        except Exception:
            pass

@fn("vkAllocateMemory")
def _am(e):
    fn_ = _sym("vkAllocateMemory")
    if not fn_: return VK_ERROR_INITIALIZATION_FAILED
    info = bytes(e.read(e.arg(1), 32))
    size = struct.unpack_from("<Q", info, 16)[0] if len(info) >= 24 else 0
    # VkMemoryAllocateInfo: sType, pNext@8, allocationSize@16, memoryTypeIndex@24. sizeof 32.
    class AI(ctypes.Structure):
        _fields_ = [("sType", U32), ("pad", U32), ("pNext", ctypes.c_void_p),
                    ("allocationSize", U64), ("memoryTypeIndex", U32), ("pad2", U32)]
    ai = AI(struct.unpack_from("<I", info, 0)[0], 0, None, size, struct.unpack_from("<I", info, 24)[0], 0)
    mem = ctypes.c_void_p()
    fn_.restype = I32
    fn_.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    r = fn_(e.arg(0), ctypes.byref(ai), None, ctypes.byref(mem))
    if e.arg(3): e.write(e.arg(3), struct.pack("<Q", mem.value or 0))
    if mem.value: _MEMSIZE[mem.value] = size
    return r

@fn("vkMapMemory")
def _mm(e):
    fn_ = _sym("vkMapMemory")
    if not fn_: return VK_ERROR_INITIALIZATION_FAILED
    dev, mem, off, size, flags, pp = e.arg(0), e.arg(1), e.arg(2), e.arg(3), e.arg(4), e.arg(5)
    if size == VK_WHOLE_SIZE: size = max(_MEMSIZE.get(mem, 0) - off, 0)
    hostp = ctypes.c_void_p()
    fn_.restype = I32
    fn_.argtypes = [ctypes.c_void_p, ctypes.c_void_p, U64, U64, U32, ctypes.POINTER(ctypes.c_void_p)]
    r = fn_(dev, mem, off, size, flags & 0xffffffff, ctypes.byref(hostp))
    if r != 0 or not hostp.value or not pp:
        return r
    g = e.malloc(max(size, 1))
    e.write(g, ctypes.string_at(hostp.value, size))
    _SHADOWS.append((hostp.value, g, size))
    e.write(pp, struct.pack("<Q", g))
    return 0

@fn("vkUnmapMemory")
def _um(e):
    _sync_shadows(e)
    fn_ = _sym("vkUnmapMemory")
    if not fn_: return None
    fn_.restype = None
    fn_.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    fn_(e.arg(0), e.arg(1)); return None

@fn("vkCreateShaderModule")
def _csm(e):
    fn_ = _sym("vkCreateShaderModule")
    if not fn_: return VK_ERROR_INITIALIZATION_FAILED
    raw = bytes(e.read(e.arg(1), 32))
    code_size = struct.unpack_from("<Q", raw, 16)[0]
    pcode = struct.unpack_from("<Q", raw, 24)[0]
    blob = ctypes.create_string_buffer(bytes(e.read(pcode, code_size)), code_size) if pcode else None
    class SM(ctypes.Structure):
        _fields_ = [("sType", U32), ("pad", U32), ("pNext", ctypes.c_void_p), ("flags", U32),
                    ("pad2", U32), ("codeSize", U64), ("pCode", ctypes.c_void_p)]
    sm = SM(struct.unpack_from("<I", raw, 0)[0], 0, None, 0, 0, code_size,
            ctypes.addressof(blob) if blob else None)
    h = ctypes.c_void_p()
    fn_.restype = I32
    fn_.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    r = fn_(e.arg(0), ctypes.byref(sm), None, ctypes.byref(h))
    if e.arg(3): e.write(e.arg(3), struct.pack("<Q", h.value or 0))
    return r

@fn("vkCreateBuffer")
def _cb(e):
    fn_ = _sym("vkCreateBuffer")
    if not fn_: return VK_ERROR_INITIALIZATION_FAILED
    # VkBufferCreateInfo is 56 bytes and pointer-free aside from pNext (ignored).
    raw = bytes(e.read(e.arg(1), 56))
    class BI(ctypes.Structure):
        _fields_ = [("sType", U32), ("pad", U32), ("pNext", ctypes.c_void_p), ("flags", U32),
                    ("pad2", U32), ("size", U64), ("usage", U32), ("sharingMode", U32),
                    ("queueFamilyIndexCount", U32), ("pad3", U32), ("pQueueFamilyIndices", ctypes.c_void_p)]
    bi = BI.from_buffer_copy(raw[:ctypes.sizeof(BI)].ljust(ctypes.sizeof(BI), b"\0"))
    bi.pNext = None
    h = ctypes.c_void_p()
    fn_.restype = I32
    fn_.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    r = fn_(e.arg(0), ctypes.byref(bi), None, ctypes.byref(h))
    if e.arg(3): e.write(e.arg(3), struct.pack("<Q", h.value or 0))
    return r

@fn("vkGetBufferMemoryRequirements", "vkGetImageMemoryRequirements")
def _gmr(e):
    name = "vkGetBufferMemoryRequirements" if "_" + "vkGetBufferMemoryRequirements" else "vkGetImageMemoryRequirements"
    # both registered to this function; pick from the return address's symbol via a closure below
    return None
def _reqs(name):
    def f(e, name=name):
        fn_ = _sym(name)
        if not fn_: return None
        out = MemReqs()
        fn_.restype = None
        fn_.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(MemReqs)]
        fn_(e.arg(0), e.arg(1), ctypes.byref(out))
        if e.arg(2): e.write(e.arg(2), bytes(out))
        return None
    FUNCS["_" + name] = f
_reqs("vkGetBufferMemoryRequirements")
_reqs("vkGetImageMemoryRequirements")

@fn("vkBindBufferMemory", "vkBindImageMemory")
def _bbm(e):
    # registered twice; split properly
    return 0
def _bindmem(name):
    def f(e, name=name):
        fn_ = _sym(name)
        if not fn_: return VK_ERROR_INITIALIZATION_FAILED
        fn_.restype = I32
        fn_.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, U64]
        return fn_(e.arg(0), e.arg(1), e.arg(2), e.arg(3))
    FUNCS["_" + name] = f
_bindmem("vkBindBufferMemory")
_bindmem("vkBindImageMemory")

def _handle_fn(name, nargs, ret_void=False):
    """Pass the first nargs register args straight through. Pointers must be host handles, not guest buffers."""
    def f(e, name=name, nargs=nargs, ret_void=ret_void):
        fn_ = _sym(name)
        if not fn_:
            return None if ret_void else VK_ERROR_INITIALIZATION_FAILED
        types = [ctypes.c_void_p if i < nargs else U32 for i in range(nargs)]
        # mixed: use void* for everything (handles are pointer-sized, small ints survive)
        fn_.argtypes = [ctypes.c_uint64] * nargs
        fn_.restype = None if ret_void else I32
        args = [e.arg(i) & M64 for i in range(nargs)]
        r = fn_(*args)
        return None if ret_void else (r or 0)
    FUNCS["_" + name] = f

for _n, _a in [("vkCmdDraw", 6), ("vkCmdDrawIndexed", 7), ("vkCmdEndRenderPass", 1),
               ("vkEndCommandBuffer", 1), ("vkQueueWaitIdle", 1), ("vkCmdSetViewport", 1),
               ("vkCmdSetScissor", 1)]:
    pass
_handle_fn("vkCmdDraw", 6, True)
_handle_fn("vkCmdDrawIndexed", 6, True)   # cmd, indexCount, instanceCount, firstIndex, vertexOffset, firstInstance — vertexOffset is signed but 64-bit slot
_handle_fn("vkCmdEndRenderPass", 1, True)
_handle_fn("vkCmdBindPipeline", 3, True)
_handle_fn("vkCmdBindIndexBuffer", 4, True)
_handle_fn("vkFreeCommandBuffers", 4, True)
_handle_fn("vkResetCommandPool", 3, False)
_handle_fn("vkResetCommandBuffer", 2, False)
_handle_fn("vkResetFences", 3, False)
_handle_fn("vkGetFenceStatus", 2, False)
_handle_fn("vkQueuePresentKHR", 2, False)  # replaced by a real wrapper below if we define one later

@fn("vkBeginCommandBuffer")
def _bcb(e):
    fn_ = _sym("vkBeginCommandBuffer")
    if not fn_: return VK_ERROR_INITIALIZATION_FAILED
    # VkCommandBufferBeginInfo is 32 bytes, pNext/pInheritance ignored when null.
    raw = bytes(e.read(e.arg(1), 32)) if e.arg(1) else b"\0" * 32
    class BI(ctypes.Structure):
        _fields_ = [("sType", U32), ("pad", U32), ("pNext", ctypes.c_void_p), ("flags", U32),
                    ("pad2", U32), ("pInheritanceInfo", ctypes.c_void_p)]
    bi = BI(struct.unpack_from("<I", raw, 0)[0] or 42, 0, None, struct.unpack_from("<I", raw, 16)[0], 0, None)
    fn_.restype = I32
    fn_.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    return fn_(e.arg(0), ctypes.byref(bi))

@fn("vkAllocateCommandBuffers")
def _acb(e):
    fn_ = _sym("vkAllocateCommandBuffers")
    if not fn_: return VK_ERROR_INITIALIZATION_FAILED
    raw = bytes(e.read(e.arg(1), 32))
    class AI(ctypes.Structure):
        _fields_ = [("sType", U32), ("pad", U32), ("pNext", ctypes.c_void_p), ("commandPool", ctypes.c_void_p),
                    ("level", U32), ("commandBufferCount", U32)]
    n = struct.unpack_from("<I", raw, 28)[0] or 1
    ai = AI(struct.unpack_from("<I", raw, 0)[0], 0, None, struct.unpack_from("<Q", raw, 16)[0],
            struct.unpack_from("<I", raw, 24)[0], n)
    arr = (ctypes.c_uint64 * n)()
    fn_.restype = I32
    fn_.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)]
    r = fn_(e.arg(0), ctypes.byref(ai), arr)
    if e.arg(2): e.write(e.arg(2), bytes(bytearray(arr)))
    return r

@fn("vkCreateCommandPool")
def _ccp(e):
    fn_ = _sym("vkCreateCommandPool")
    if not fn_: return VK_ERROR_INITIALIZATION_FAILED
    raw = bytes(e.read(e.arg(1), 24))
    class CI(ctypes.Structure):
        _fields_ = [("sType", U32), ("pad", U32), ("pNext", ctypes.c_void_p), ("flags", U32),
                    ("queueFamilyIndex", U32)]
    ci = CI(struct.unpack_from("<I", raw, 0)[0], 0, None, struct.unpack_from("<I", raw, 16)[0],
            struct.unpack_from("<I", raw, 20)[0])
    h = ctypes.c_void_p()
    fn_.restype = I32
    fn_.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    r = fn_(e.arg(0), ctypes.byref(ci), None, ctypes.byref(h))
    if e.arg(3): e.write(e.arg(3), struct.pack("<Q", h.value or 0))
    return r

@fn("vkCreateFence")
def _cfence(e):
    fn_ = _sym("vkCreateFence")
    if not fn_: return VK_ERROR_INITIALIZATION_FAILED
    raw = bytes(e.read(e.arg(1), 24))
    class FI(ctypes.Structure):
        _fields_ = [("sType", U32), ("pad", U32), ("pNext", ctypes.c_void_p), ("flags", U32), ("pad2", U32)]
    fi = FI(struct.unpack_from("<I", raw, 0)[0], 0, None, struct.unpack_from("<I", raw, 16)[0], 0)
    h = ctypes.c_void_p()
    fn_.restype = I32
    fn_.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    r = fn_(e.arg(0), ctypes.byref(fi), None, ctypes.byref(h))
    if e.arg(3): e.write(e.arg(3), struct.pack("<Q", h.value or 0))
    return r

@fn("vkCreateSemaphore")
def _csem(e):
    return _cfence(e) if False else _sem(e)
def _sem(e):
    fn_ = _sym("vkCreateSemaphore")
    if not fn_: return VK_ERROR_INITIALIZATION_FAILED
    raw = bytes(e.read(e.arg(1), 24))
    class SI(ctypes.Structure):
        _fields_ = [("sType", U32), ("pad", U32), ("pNext", ctypes.c_void_p), ("flags", U32), ("pad2", U32)]
    si = SI(struct.unpack_from("<I", raw, 0)[0], 0, None, 0, 0)
    h = ctypes.c_void_p()
    fn_.restype = I32
    fn_.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    r = fn_(e.arg(0), ctypes.byref(si), None, ctypes.byref(h))
    if e.arg(3): e.write(e.arg(3), struct.pack("<Q", h.value or 0))
    return r

@fn("vkQueueSubmit")
def _qs(e):
    _sync_shadows(e)
    fn_ = _sym("vkQueueSubmit")
    if not fn_: return VK_ERROR_INITIALIZATION_FAILED
    # Minimal: one submit, no semaphores, command buffers copied out.
    n = e.arg(1)
    psub = e.arg(2)
    if not n or not psub:
        fn_.restype = I32
        fn_.argtypes = [ctypes.c_void_p, U32, ctypes.c_void_p, ctypes.c_void_p]
        return fn_(e.arg(0), 0, None, e.arg(3) or None)
    # VkSubmitInfo: sType, pNext, waitCount, pWaitSems, pWaitStages, cmdCount, pCmd, signalCount, pSignal
    # offsets: 0, 8, 16, 24, 32, 40, 48, 56, 64. sizeof 72.
    raw = bytes(e.read(psub, 72))
    cc = struct.unpack_from("<I", raw, 40)[0]
    pc = struct.unpack_from("<Q", raw, 48)[0]
    cmds = (ctypes.c_uint64 * max(cc, 1))()
    if pc and cc:
        for i, v in enumerate(struct.unpack(f"<{cc}Q", bytes(e.read(pc, 8 * cc)))):
            cmds[i] = v
    class SI(ctypes.Structure):
        _fields_ = [("sType", U32), ("pad", U32), ("pNext", ctypes.c_void_p),
                    ("waitSemaphoreCount", U32), ("pad2", U32), ("pWaitSemaphores", ctypes.c_void_p),
                    ("pWaitDstStageMask", ctypes.c_void_p), ("commandBufferCount", U32), ("pad3", U32),
                    ("pCommandBuffers", ctypes.c_void_p), ("signalSemaphoreCount", U32), ("pad4", U32),
                    ("pSignalSemaphores", ctypes.c_void_p)]
    si = SI(struct.unpack_from("<I", raw, 0)[0], 0, None, 0, 0, None, None, cc, 0,
            ctypes.addressof(cmds) if cc else None, 0, 0, None)
    fn_.restype = I32
    fn_.argtypes = [ctypes.c_void_p, U32, ctypes.c_void_p, ctypes.c_void_p]
    return fn_(e.arg(0), 1, ctypes.byref(si), e.arg(3) or None)

# Names a guest will dlsym even when we only have a stub that returns an error.
# Keeping them in FUNCS makes vkGetInstanceProcAddr hand back a callable instead of NULL,
# which is what MoltenVK clients check before giving up.
def _missing(name, ret=VK_ERROR_EXTENSION_NOT_PRESENT):
    if "_" + name in FUNCS: return
    def f(e, name=name, ret=ret):
        if os.environ.get("ARM2X86_VERBOSE"):
            sys.stderr.write(f"[vulkan] {name} not marshalled yet\n")
        return ret
    FUNCS["_" + name] = f

for _n in """vkEnumerateDeviceExtensionProperties vkGetPhysicalDeviceSurfaceSupportKHR
vkGetPhysicalDeviceSurfaceCapabilitiesKHR vkGetPhysicalDeviceSurfaceFormatsKHR
vkGetPhysicalDeviceSurfacePresentModesKHR vkCreateSwapchainKHR vkGetSwapchainImagesKHR
vkAcquireNextImageKHR vkCreateImage vkCreateImageView vkCreateFramebuffer vkCreateRenderPass
vkCreatePipelineLayout vkCreateGraphicsPipelines vkCreateDescriptorSetLayout vkCreateDescriptorPool
vkAllocateDescriptorSets vkUpdateDescriptorSets vkCreateSampler vkCmdBeginRenderPass
vkCmdPipelineBarrier vkCmdCopyBuffer vkCmdCopyBufferToImage vkCmdBindVertexBuffers
vkCmdBindDescriptorSets vkCmdPushConstants vkCreateBufferView vkMapMemory2KHR
vkGetPhysicalDeviceProperties2 vkGetPhysicalDeviceFeatures2 vkEnumerateInstanceLayerProperties
vkEnumerateDeviceLayerProperties vkCreateComputePipelines vkCmdDispatch vkCmdDispatchIndirect
vkQueuePresentKHR vkGetPhysicalDeviceMetalFeaturesMVK vkSetDeviceMemoryPriorityEXT
""".split():
    _missing(_n)
