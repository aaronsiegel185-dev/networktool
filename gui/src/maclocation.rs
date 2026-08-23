//! Location Services, requested from inside this process.
//!
//! macOS will only show the location prompt to a process whose *own* main
//! bundle carries NSLocationWhenInUseUsageDescription. nettool.app carries it;
//! a `python3 -m nettool` subprocess does not, and CoreLocation answers a
//! request from one by doing nothing at all - no prompt, no error. So the ask
//! has to happen here, in the app binary, rather than by shelling out to the
//! CLI the way every other feature does.
//!
//! Nothing blocks: the prompt needs a turning run loop, and the app already has
//! one, so we fire the request and read the status back on later frames.

/// kCLAuthorizationStatus*, from <CoreLocation/CLLocation.h>.
pub const NOT_DETERMINED: i32 = 0;
pub const RESTRICTED: i32 = 1;
pub const DENIED: i32 = 2;

pub fn granted(status: i32) -> bool {
    status == 3 || status == 4
}

pub fn status_name(status: i32) -> &'static str {
    match status {
        NOT_DETERMINED => "not determined",
        RESTRICTED => "restricted by policy",
        DENIED => "denied",
        3 => "authorised (always)",
        4 => "authorised (when in use)",
        _ => "unknown",
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_void};
    use std::ptr;
    use std::sync::atomic::{AtomicPtr, Ordering};

    #[link(name = "CoreLocation", kind = "framework")]
    extern "C" {}

    extern "C" {
        fn objc_getClass(name: *const c_char) -> *mut c_void;
        fn sel_registerName(name: *const c_char) -> *mut c_void;
        fn objc_msgSend();
    }

    unsafe fn selector(name: &str) -> *mut c_void {
        let name = CString::new(name).expect("selector name has no interior nul");
        sel_registerName(name.as_ptr())
    }

    unsafe fn class(name: &str) -> *mut c_void {
        let name = CString::new(name).expect("class name has no interior nul");
        objc_getClass(name.as_ptr())
    }

    // objc_msgSend is variadic, and on arm64 that means it has to be called
    // through the exact prototype of the message being sent.
    unsafe fn send_ptr(receiver: *mut c_void, message: &str) -> *mut c_void {
        let send: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        send(receiver, selector(message))
    }

    unsafe fn send_i32(receiver: *mut c_void, message: &str) -> i32 {
        let send: unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32 =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        send(receiver, selector(message))
    }

    unsafe fn send_none(receiver: *mut c_void, message: &str) {
        let send: unsafe extern "C" fn(*mut c_void, *mut c_void) =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        send(receiver, selector(message))
    }

    /// One manager for the life of the process - CoreLocation stops caring
    /// about a released one, prompt included.
    static MANAGER: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

    unsafe fn manager() -> *mut c_void {
        let existing = MANAGER.load(Ordering::Relaxed);
        if !existing.is_null() {
            return existing;
        }
        let cls = class("CLLocationManager");
        if cls.is_null() {
            return ptr::null_mut();
        }
        let created = send_ptr(send_ptr(cls, "alloc"), "init");
        MANAGER.store(created, Ordering::Relaxed);
        created
    }

    pub fn status() -> Option<i32> {
        unsafe {
            let manager = manager();
            if manager.is_null() {
                return None;
            }
            Some(send_i32(manager, "authorizationStatus"))
        }
    }

    pub fn request() -> Option<i32> {
        unsafe {
            let manager = manager();
            if manager.is_null() {
                return None;
            }
            send_none(manager, "requestWhenInUseAuthorization");
            // Asking for authorisation can sit silent; asking for a location is
            // what actually brings the prompt up.
            send_none(manager, "startUpdatingLocation");
            Some(send_i32(manager, "authorizationStatus"))
        }
    }

    /// Whether this process is even able to prompt.
    pub fn can_prompt() -> bool {
        unsafe {
            let cls = class("NSBundle");
            if cls.is_null() {
                return false;
            }
            let bundle = send_ptr(cls, "mainBundle");
            !bundle.is_null() && !send_ptr(bundle, "bundleIdentifier").is_null()
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    pub fn status() -> Option<i32> {
        None
    }
    pub fn request() -> Option<i32> {
        None
    }
    pub fn can_prompt() -> bool {
        false
    }
}

pub use imp::{can_prompt, request, status};
