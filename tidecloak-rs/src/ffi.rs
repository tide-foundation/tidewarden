use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::sync::Mutex;

use crate::auth;
use crate::config;
use crate::dpop::DPoPProvider;
use crate::pkce;
use crate::token::TokenManager;
use crate::types::{OidcEndpoints, TideCloakConfig, TokenSet};

/// Opaque handle to a TideCloak SDK instance
pub struct TideCloakInstance {
    config: TideCloakConfig,
    endpoints: Mutex<Option<OidcEndpoints>>,
    token_manager: Option<TokenManager>,
    dpop: Option<DPoPProvider>,
    pkce_verifier: Mutex<Option<String>>,
    runtime: tokio::runtime::Runtime,
}

/// Result code for FFI functions
#[repr(C)]
pub enum TcResultCode {
    Ok = 0,
    ErrConfig = 1,
    ErrNetwork = 2,
    ErrAuth = 3,
    ErrToken = 4,
    ErrNullPtr = 5,
    ErrInternal = 6,
}

/// Initialize a TideCloak instance from a config file.
///
/// Returns a pointer to the instance, or null on failure.
/// The caller must free with `tidecloak_free_instance`.
#[no_mangle]
pub extern "C" fn tidecloak_init(config_path: *const c_char) -> *mut TideCloakInstance {
    let path_str = match unsafe { CStr::from_ptr(config_path) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let config = match config::load_config(Path::new(path_str)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[tidecloak] Config error: {e}");
            return std::ptr::null_mut();
        }
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[tidecloak] Failed to create runtime: {e}");
            return std::ptr::null_mut();
        }
    };

    let dpop = if config.use_dpop.is_some() {
        match DPoPProvider::new() {
            Ok(d) => Some(d),
            Err(e) => {
                eprintln!("[tidecloak] DPoP init warning: {e}");
                None
            }
        }
    } else {
        None
    };

    let instance = TideCloakInstance {
        config,
        endpoints: Mutex::new(None),
        token_manager: None,
        dpop,
        pkce_verifier: Mutex::new(None),
        runtime,
    };

    Box::into_raw(Box::new(instance))
}

/// Discover OIDC endpoints. Must be called before auth operations.
///
/// Returns TcResultCode::Ok on success.
#[no_mangle]
pub extern "C" fn tidecloak_discover(instance: *mut TideCloakInstance) -> TcResultCode {
    let inst = match unsafe { instance.as_mut() } {
        Some(i) => i,
        None => return TcResultCode::ErrNullPtr,
    };

    match inst.runtime.block_on(config::discover_oidc(&inst.config)) {
        Ok(endpoints) => {
            let tm = TokenManager::new(inst.config.clone(), endpoints.clone());
            inst.token_manager = Some(tm);
            *inst.endpoints.lock().unwrap() = Some(endpoints);
            TcResultCode::Ok
        }
        Err(e) => {
            eprintln!("[tidecloak] Discovery error: {e}");
            TcResultCode::ErrNetwork
        }
    }
}

/// Build the authorization URL for login.
///
/// Returns a heap-allocated C string. Caller must free with `tidecloak_free_string`.
/// Returns null on error.
#[no_mangle]
pub extern "C" fn tidecloak_build_auth_url(
    instance: *mut TideCloakInstance,
    redirect_uri: *const c_char,
) -> *mut c_char {
    let inst = match unsafe { instance.as_mut() } {
        Some(i) => i,
        None => return std::ptr::null_mut(),
    };

    let redirect = match unsafe { CStr::from_ptr(redirect_uri) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let endpoints = inst.endpoints.lock().unwrap();
    let endpoints = match endpoints.as_ref() {
        Some(e) => e,
        None => {
            eprintln!("[tidecloak] Endpoints not discovered. Call tidecloak_discover first.");
            return std::ptr::null_mut();
        }
    };

    let pkce_challenge = pkce::make_pkce();
    *inst.pkce_verifier.lock().unwrap() = Some(pkce_challenge.verifier.clone());

    match auth::build_auth_url(&inst.config, endpoints, &pkce_challenge, redirect) {
        Ok(url) => match CString::new(url) {
            Ok(cs) => cs.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(e) => {
            eprintln!("[tidecloak] build_auth_url error: {e}");
            std::ptr::null_mut()
        }
    }
}

/// Exchange an authorization code for tokens.
///
/// Returns TcResultCode::Ok on success.
#[no_mangle]
pub extern "C" fn tidecloak_exchange_code(
    instance: *mut TideCloakInstance,
    code: *const c_char,
    redirect_uri: *const c_char,
) -> TcResultCode {
    let inst = match unsafe { instance.as_mut() } {
        Some(i) => i,
        None => return TcResultCode::ErrNullPtr,
    };

    let code_str = match unsafe { CStr::from_ptr(code) }.to_str() {
        Ok(s) => s,
        Err(_) => return TcResultCode::ErrNullPtr,
    };

    let redirect = match unsafe { CStr::from_ptr(redirect_uri) }.to_str() {
        Ok(s) => s,
        Err(_) => return TcResultCode::ErrNullPtr,
    };

    let verifier = match inst.pkce_verifier.lock().unwrap().take() {
        Some(v) => v,
        None => {
            eprintln!("[tidecloak] No PKCE verifier. Call tidecloak_build_auth_url first.");
            return TcResultCode::ErrAuth;
        }
    };

    let endpoints_guard = inst.endpoints.lock().unwrap();
    let endpoints = match endpoints_guard.as_ref() {
        Some(e) => e.clone(),
        None => return TcResultCode::ErrConfig,
    };
    drop(endpoints_guard);

    let dpop_proof = inst.dpop.as_ref().and_then(|d| {
        d.generate_proof("POST", &endpoints.token_endpoint, None, d.get_auth_server_nonce().as_deref())
            .ok()
    });

    match inst.runtime.block_on(auth::exchange_code(
        &inst.config,
        &endpoints,
        code_str,
        &verifier,
        redirect,
        dpop_proof.as_deref(),
    )) {
        Ok(tokens) => {
            if let Some(ref tm) = inst.token_manager {
                tm.set_tokens(tokens);
            }
            TcResultCode::Ok
        }
        Err(e) => {
            eprintln!("[tidecloak] exchange_code error: {e}");
            TcResultCode::ErrAuth
        }
    }
}

/// Refresh the current tokens.
///
/// Returns TcResultCode::Ok on success.
#[no_mangle]
pub extern "C" fn tidecloak_refresh(instance: *mut TideCloakInstance) -> TcResultCode {
    let inst = match unsafe { instance.as_mut() } {
        Some(i) => i,
        None => return TcResultCode::ErrNullPtr,
    };

    let tm = match inst.token_manager.as_ref() {
        Some(t) => t,
        None => return TcResultCode::ErrConfig,
    };

    let dpop_proof = inst.dpop.as_ref().and_then(|d| {
        let endpoints = inst.endpoints.lock().unwrap();
        let ep = endpoints.as_ref()?;
        d.generate_proof("POST", &ep.token_endpoint, None, d.get_auth_server_nonce().as_deref())
            .ok()
    });

    match inst.runtime.block_on(tm.try_refresh(dpop_proof.as_deref())) {
        Ok(()) => TcResultCode::Ok,
        Err(e) => {
            eprintln!("[tidecloak] refresh error: {e}");
            TcResultCode::ErrToken
        }
    }
}

/// Get the current access token.
///
/// Returns a heap-allocated C string. Caller must free with `tidecloak_free_string`.
/// Returns null if no token is available.
#[no_mangle]
pub extern "C" fn tidecloak_get_access_token(
    instance: *mut TideCloakInstance,
) -> *mut c_char {
    let inst = match unsafe { instance.as_ref() } {
        Some(i) => i,
        None => return std::ptr::null_mut(),
    };

    let token = inst
        .token_manager
        .as_ref()
        .and_then(|tm| tm.access_token());

    match token {
        Some(t) => CString::new(t).map(|cs| cs.into_raw()).unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}

/// Check if the access token is expired.
#[no_mangle]
pub extern "C" fn tidecloak_is_token_expired(instance: *const TideCloakInstance) -> bool {
    let inst = match unsafe { instance.as_ref() } {
        Some(i) => i,
        None => return true,
    };

    inst.token_manager
        .as_ref()
        .map(|tm| tm.is_expired())
        .unwrap_or(true)
}

/// Get user info as a JSON string.
///
/// Returns a heap-allocated C string. Caller must free with `tidecloak_free_string`.
/// Returns null on error.
#[no_mangle]
pub extern "C" fn tidecloak_get_user_info_json(
    instance: *const TideCloakInstance,
) -> *mut c_char {
    let inst = match unsafe { instance.as_ref() } {
        Some(i) => i,
        None => return std::ptr::null_mut(),
    };

    let user_info = inst
        .token_manager
        .as_ref()
        .and_then(|tm| tm.user_info().ok());

    match user_info {
        Some(info) => {
            let json = serde_json::to_string(&info).unwrap_or_default();
            CString::new(json)
                .map(|cs| cs.into_raw())
                .unwrap_or(std::ptr::null_mut())
        }
        None => std::ptr::null_mut(),
    }
}

/// Build the logout URL.
///
/// Returns a heap-allocated C string. Caller must free with `tidecloak_free_string`.
/// Returns null on error.
#[no_mangle]
pub extern "C" fn tidecloak_logout_url(
    instance: *mut TideCloakInstance,
    redirect_uri: *const c_char,
) -> *mut c_char {
    let inst = match unsafe { instance.as_ref() } {
        Some(i) => i,
        None => return std::ptr::null_mut(),
    };

    let redirect = if redirect_uri.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(redirect_uri) }
            .to_str()
            .ok()
    };

    let endpoints = inst.endpoints.lock().unwrap();
    let endpoints = match endpoints.as_ref() {
        Some(e) => e,
        None => return std::ptr::null_mut(),
    };

    let id_token = inst
        .token_manager
        .as_ref()
        .and_then(|tm| tm.id_token());

    match auth::build_logout_url(
        &inst.config,
        endpoints,
        id_token.as_deref(),
        redirect,
    ) {
        Ok(url) => CString::new(url)
            .map(|cs| cs.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(e) => {
            eprintln!("[tidecloak] logout_url error: {e}");
            std::ptr::null_mut()
        }
    }
}

/// Get the current tokens as a JSON string (for persistence).
///
/// Returns a heap-allocated C string. Caller must free with `tidecloak_free_string`.
/// Returns null if no tokens available.
#[no_mangle]
pub extern "C" fn tidecloak_get_tokens_json(
    instance: *const TideCloakInstance,
) -> *mut c_char {
    let inst = match unsafe { instance.as_ref() } {
        Some(i) => i,
        None => return std::ptr::null_mut(),
    };

    let tokens = inst
        .token_manager
        .as_ref()
        .and_then(|tm| tm.get_tokens());

    match tokens {
        Some(t) => {
            let json = serde_json::to_string(&t).unwrap_or_default();
            CString::new(json)
                .map(|cs| cs.into_raw())
                .unwrap_or(std::ptr::null_mut())
        }
        None => std::ptr::null_mut(),
    }
}

/// Restore tokens from a JSON string (for persistence).
///
/// Returns TcResultCode::Ok on success.
#[no_mangle]
pub extern "C" fn tidecloak_set_tokens_json(
    instance: *mut TideCloakInstance,
    json: *const c_char,
) -> TcResultCode {
    let inst = match unsafe { instance.as_mut() } {
        Some(i) => i,
        None => return TcResultCode::ErrNullPtr,
    };

    let json_str = match unsafe { CStr::from_ptr(json) }.to_str() {
        Ok(s) => s,
        Err(_) => return TcResultCode::ErrNullPtr,
    };

    let tokens: TokenSet = match serde_json::from_str(json_str) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[tidecloak] set_tokens_json parse error: {e}");
            return TcResultCode::ErrInternal;
        }
    };

    if let Some(ref tm) = inst.token_manager {
        tm.set_tokens(tokens);
    }

    TcResultCode::Ok
}

/// Clear all tokens (logout).
#[no_mangle]
pub extern "C" fn tidecloak_clear_tokens(instance: *mut TideCloakInstance) {
    if let Some(inst) = unsafe { instance.as_mut() } {
        if let Some(ref tm) = inst.token_manager {
            tm.clear_tokens();
        }
    }
}

/// Check if user has a realm role.
#[no_mangle]
pub extern "C" fn tidecloak_has_realm_role(
    instance: *const TideCloakInstance,
    role: *const c_char,
) -> bool {
    let inst = match unsafe { instance.as_ref() } {
        Some(i) => i,
        None => return false,
    };

    let role_str = match unsafe { CStr::from_ptr(role) }.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };

    inst.token_manager
        .as_ref()
        .map(|tm| tm.has_realm_role(role_str))
        .unwrap_or(false)
}

/// Get seconds until token expires.
#[no_mangle]
pub extern "C" fn tidecloak_token_expires_in(instance: *const TideCloakInstance) -> i64 {
    let inst = match unsafe { instance.as_ref() } {
        Some(i) => i,
        None => return 0,
    };

    inst.token_manager
        .as_ref()
        .map(|tm| tm.expires_in_secs())
        .unwrap_or(0)
}

/// Free a string allocated by this library.
#[no_mangle]
pub extern "C" fn tidecloak_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}

/// Free a TideCloak instance.
#[no_mangle]
pub extern "C" fn tidecloak_free_instance(ptr: *mut TideCloakInstance) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr));
        }
    }
}
