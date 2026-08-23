"""Location Services authorisation for macOS, over ctypes.

macOS will not reveal Wi-Fi network names to a process that has not been granted
Location Services, and an app only appears in the System Settings list once it
has *asked*. There is no way to add it by hand. So we ask: this is the smallest
possible CoreLocation client, driven through the Objective-C runtime with
ctypes, so it stays inside the standard library like the rest of nettool.

Who the prompt is attributed to depends on who launched us:

* run from Terminal or iTerm, the prompt (and the resulting Location Services
  entry) belongs to that terminal app;
* run from inside nettool.app, it belongs to nettool - the bundle carries the
  NSLocationWhenInUseUsageDescription that macOS demands before it will ask.

Either way the grant covers the `system_profiler` and `wdutil` calls we make
underneath, because macOS attributes a child process to the app responsible for
it.
"""

import ctypes
import sys

# kCLAuthorizationStatus*, from <CoreLocation/CLLocation.h>.
STATUS_NAMES = {
    0: "not determined",
    1: "restricted by policy",
    2: "denied",
    3: "authorised (always)",
    4: "authorised (when in use)",
}

GRANTED = (3, 4)


class LocationError(Exception):
    """CoreLocation could not be reached at all."""


def _runtime():
    """The Objective-C runtime plus the frameworks we need loaded."""
    if sys.platform != "darwin":
        raise LocationError("Location Services only exist on macOS")
    try:
        objc = ctypes.cdll.LoadLibrary("/usr/lib/libobjc.dylib")
        ctypes.cdll.LoadLibrary(
            "/System/Library/Frameworks/Foundation.framework/Foundation")
        ctypes.cdll.LoadLibrary(
            "/System/Library/Frameworks/CoreLocation.framework/CoreLocation")
        cf = ctypes.cdll.LoadLibrary(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    except OSError as exc:
        raise LocationError("could not load CoreLocation: %s" % exc)
    objc.objc_getClass.restype = ctypes.c_void_p
    objc.objc_getClass.argtypes = [ctypes.c_char_p]
    objc.sel_registerName.restype = ctypes.c_void_p
    objc.sel_registerName.argtypes = [ctypes.c_char_p]
    # Without an explicit prototype ctypes truncates the returned pointer to an
    # int, which would make the version check below answer at random.
    objc.class_getInstanceMethod.restype = ctypes.c_void_p
    objc.class_getInstanceMethod.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    return objc, cf


def _sender(objc, restype):
    """objc_msgSend with a real prototype.

    objc_msgSend is variadic, and on arm64 variadic and regular arguments go to
    different places - so it has to be cast to the exact signature of the call
    being made rather than called through one shared declaration.
    """
    address = ctypes.cast(objc.objc_msgSend, ctypes.c_void_p).value
    proto = ctypes.CFUNCTYPE(restype, ctypes.c_void_p, ctypes.c_void_p)
    return proto(address)


def _call(objc, obj, selector, restype=ctypes.c_void_p):
    return _sender(objc, restype)(obj, objc.sel_registerName(selector.encode()))


def _manager(objc):
    cls = objc.objc_getClass(b"CLLocationManager")
    if not cls:
        raise LocationError("CLLocationManager is unavailable")
    return _call(objc, _call(objc, cls, "alloc"), "init"), cls


def _status(objc, manager, cls):
    """Authorisation status, from whichever API this macOS version offers."""
    # Instance property since macOS 11; class method before that.
    if objc.class_getInstanceMethod(cls, objc.sel_registerName(b"authorizationStatus")):
        return int(_call(objc, manager, "authorizationStatus", ctypes.c_int32))
    return int(_call(objc, cls, "authorizationStatus", ctypes.c_int32))


def _string(objc, obj):
    """An NSString's bytes, or "" for nil."""
    if not obj:
        return ""
    address = ctypes.cast(objc.objc_msgSend, ctypes.c_void_p).value
    proto = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p)
    raw = proto(address)(obj, objc.sel_registerName(b"UTF8String"))
    return raw.decode("utf-8", "replace") if raw else ""


def bundle_id():
    """This process's bundle identifier, or "" if it is not running from a bundle."""
    objc, _cf = _runtime()
    cls = objc.objc_getClass(b"NSBundle")
    if not cls:
        return ""
    bundle = _call(objc, cls, "mainBundle")
    return _string(objc, _call(objc, bundle, "bundleIdentifier"))


def can_prompt():
    """Whether macOS will even show this process a location prompt.

    CoreLocation ignores a request from a process whose main bundle carries no
    NSLocationWhenInUseUsageDescription - no prompt, no error, nothing. A plain
    `python3 -m nettool` has no bundle at all, so it can never be asked; only
    nettool.app can, because the request has to come from inside the bundle that
    declares the string.
    """
    return bool(bundle_id())


def status():
    """(code, human readable name) for this process's Location Services grant."""
    objc, _cf = _runtime()
    manager, cls = _manager(objc)
    code = _status(objc, manager, cls)
    return code, STATUS_NAMES.get(code, "unknown (%d)" % code)


def services_enabled():
    """Whether Location Services is switched on at all, system-wide."""
    objc, _cf = _runtime()
    cls = objc.objc_getClass(b"CLLocationManager")
    return bool(_call(objc, cls, "locationServicesEnabled", ctypes.c_bool))


def request(timeout=15.0):
    """Ask for authorisation and wait for the answer.

    Returns (code, name). The prompt only appears while a run loop is turning,
    and only the first time - once macOS records a decision it stops asking, and
    changing it means visiting System Settings.
    """
    objc, cf = _runtime()
    manager, cls = _manager(objc)
    before = _status(objc, manager, cls)
    if before in GRANTED:
        return before, STATUS_NAMES[before]
    if not can_prompt():
        raise LocationError(
            "macOS will not show a location prompt to a process without an app "
            "bundle, and this one has none - use the button in nettool.app instead")

    _call(objc, manager, "requestWhenInUseAuthorization")
    # A location request is what actually makes CoreLocation surface the prompt;
    # asking for authorisation alone can sit silent.
    _call(objc, manager, "startUpdatingLocation")

    mode = ctypes.c_void_p.in_dll(cf, "kCFRunLoopDefaultMode")
    cf.CFRunLoopRunInMode.restype = ctypes.c_int32
    cf.CFRunLoopRunInMode.argtypes = [ctypes.c_void_p, ctypes.c_double, ctypes.c_bool]

    deadline = float(timeout)
    step = 0.25
    code = before
    while deadline > 0:
        cf.CFRunLoopRunInMode(mode, step, True)
        deadline -= step
        code = _status(objc, manager, cls)
        if code != before:
            break
    _call(objc, manager, "stopUpdatingLocation")
    return code, STATUS_NAMES.get(code, "unknown (%d)" % code)
