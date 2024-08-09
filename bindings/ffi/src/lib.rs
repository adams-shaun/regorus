// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use anyhow::{anyhow, bail, Result};
use std::ffi::{CStr, CString};
use std::hash::Hash;
use std::hash::{DefaultHasher, Hasher};
use std::os::raw::{c_char, c_void};

#[repr(C)]
pub struct RegorusInput {
    /// Status
    status: RegorusStatus,

    /// Output produced by the call.
    /// Owned by Rust.
    output: *mut c_char,

    action: *mut c_char,
    rule: *mut c_char,

    /// Errors produced by the call.
    /// Owned by Rust.
    error_message: *mut c_char,
}

/// Status of a call on `RegorusEngine`.
#[repr(C)]
pub enum RegorusStatus {
    /// The operation was successful.
    RegorusStatusOk,

    /// The operation was unsuccessful.
    RegorusStatusError,
}

/// Result of a call on `RegorusEngine`.
///
/// Must be freed using `regorus_result_drop`.
#[repr(C)]
pub struct RegorusResult {
    /// Status
    status: RegorusStatus,

    /// Output produced by the call.
    /// Owned by Rust.
    output: *mut c_char,
    action: *mut c_char,
    rule: *mut c_char,

    input_value: *mut c_void,

    /// Errors produced by the call.
    /// Owned by Rust.
    error_message: *mut c_char,
}

fn to_c_str(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        _ => to_c_str("binding error: failed to create c-style string".to_string()),
    }
}

fn from_c_str(name: &str, s: *const c_char) -> Result<String> {
    if s.is_null() {
        bail!("null pointer");
    }
    unsafe {
        CStr::from_ptr(s)
            .to_str()
            .map_err(|e| anyhow!("`{name}`: invalid utf8.\n{e}"))
            .map(|s| s.to_string())
    }
}

fn to_ref<T>(t: &*mut T) -> Result<&mut T> {
    unsafe { t.as_mut().ok_or_else(|| anyhow!("null pointer")) }
}

fn to_regorus_result(r: Result<()>) -> RegorusResult {
    match r {
        Ok(()) => RegorusResult {
            status: RegorusStatus::RegorusStatusOk,
            output: std::ptr::null_mut(),
            action: std::ptr::null_mut(),
            rule: std::ptr::null_mut(),
            input_value: std::ptr::null_mut(),
            error_message: std::ptr::null_mut(),
        },
        Err(e) => RegorusResult {
            status: RegorusStatus::RegorusStatusError,
            output: std::ptr::null_mut(),
            action: std::ptr::null_mut(),
            rule: std::ptr::null_mut(),
            input_value: std::ptr::null_mut(),
            error_message: to_c_str(format!("{e}")),
        },
    }
}

fn to_regorus_string_result(r: Result<String>) -> RegorusResult {
    match r {
        Ok(s) => RegorusResult {
            status: RegorusStatus::RegorusStatusOk,
            output: to_c_str(s),
            action: std::ptr::null_mut(),
            rule: std::ptr::null_mut(),
            input_value: std::ptr::null_mut(),
            error_message: std::ptr::null_mut(),
        },
        Err(e) => RegorusResult {
            status: RegorusStatus::RegorusStatusError,
            output: std::ptr::null_mut(),
            action: std::ptr::null_mut(),
            rule: std::ptr::null_mut(),
            input_value: std::ptr::null_mut(),
            error_message: to_c_str(format!("{e}")),
        },
    }
}

/// Wrapper for `regorus::Engine`.
#[derive(Clone)]
pub struct RegorusEngine {
    engine: ::regorus::Engine,
}

/// Drop a `RegorusResult`.
///
/// `output` and `error_message` strings are not valid after drop.
#[no_mangle]
pub extern "C" fn regorus_result_drop(r: RegorusResult) {
    unsafe {
        if !r.error_message.is_null() {
            let _ = CString::from_raw(r.error_message);
        }
        if !r.output.is_null() {
            let _ = CString::from_raw(r.output);
        }
        if !r.action.is_null() {
            let _ = CString::from_raw(r.action);
        }
        if !r.rule.is_null() {
            let _ = CString::from_raw(r.rule);
        }
    }
}

#[no_mangle]
/// Construct a new Engine
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html
pub extern "C" fn regorus_engine_new() -> *mut RegorusEngine {
    let engine = ::regorus::Engine::new();
    Box::into_raw(Box::new(RegorusEngine { engine }))
}

/// Clone a [`RegorusEngine`]
///
/// To avoid having to parse same policy again, the engine can be cloned
/// after policies and data have been added.
///
#[no_mangle]
pub extern "C" fn regorus_engine_clone(engine: *mut RegorusEngine) -> *mut RegorusEngine {
    match to_ref(&engine) {
        Ok(e) => Box::into_raw(Box::new(e.clone())),
        _ => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn regorus_value_drop(value: *const c_void) {
    let input_obj: &mut regorus::Value = unsafe { &mut *(value as *mut regorus::Value) };

    unsafe {
        let _ = Box::from_raw(std::ptr::from_mut(input_obj));
    }
}

#[no_mangle]
pub extern "C" fn regorus_engine_drop(engine: *mut RegorusEngine) {
    if let Ok(e) = to_ref(&engine) {
        unsafe {
            let _ = Box::from_raw(std::ptr::from_mut(e));
        }
    }
}

/// Add a policy
///
/// The policy is parsed into AST.
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.add_policy
///
/// * `path`: A filename to be associated with the policy.
/// * `rego`: Rego policy.
#[no_mangle]
pub extern "C" fn regorus_engine_add_policy(
    engine: *mut RegorusEngine,
    path: *const c_char,
    rego: *const c_char,
) -> RegorusResult {
    to_regorus_string_result(|| -> Result<String> {
        to_ref(&engine)?
            .engine
            .add_policy(from_c_str("path", path)?, from_c_str("rego", rego)?)
    }())
}

#[cfg(feature = "std")]
#[no_mangle]
pub extern "C" fn regorus_engine_add_policy_from_file(
    engine: *mut RegorusEngine,
    path: *const c_char,
) -> RegorusResult {
    to_regorus_string_result(|| -> Result<String> {
        to_ref(&engine)?
            .engine
            .add_policy_from_file(from_c_str("path", path)?)
    }())
}

/// Add policy data.
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.add_data
/// * `data`: JSON encoded value to be used as policy data.
#[no_mangle]
pub extern "C" fn regorus_engine_add_data_json(
    engine: *mut RegorusEngine,
    data: *const c_char,
) -> RegorusResult {
    to_regorus_result(|| -> Result<()> {
        to_ref(&engine)?
            .engine
            .add_data(regorus::Value::from_json_str(&from_c_str("data", data)?)?)
    }())
}

/// Get list of loaded Rego packages as JSON.
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.get_packages
#[no_mangle]
pub extern "C" fn regorus_engine_get_packages(engine: *mut RegorusEngine) -> RegorusResult {
    to_regorus_string_result(|| -> Result<String> {
        serde_json::to_string_pretty(&to_ref(&engine)?.engine.get_packages()?)
            .map_err(anyhow::Error::msg)
    }())
}

/// Get list of policies as JSON.
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.get_policies
#[no_mangle]
pub extern "C" fn regorus_engine_get_policies(engine: *mut RegorusEngine) -> RegorusResult {
    to_regorus_string_result(|| -> Result<String> {
        to_ref(&engine)?.engine.get_policies_as_json()
    }())
}

#[cfg(feature = "std")]
#[no_mangle]
pub extern "C" fn regorus_engine_add_data_from_json_file(
    engine: *mut RegorusEngine,
    path: *const c_char,
) -> RegorusResult {
    to_regorus_result(|| -> Result<()> {
        to_ref(&engine)?
            .engine
            .add_data(regorus::Value::from_json_file(from_c_str("path", path)?)?)
    }())
}

/// Clear policy data.
///
/// See https://docs.rs/regorus/0.1.0-alpha.2/regorus/struct.Engine.html#method.clear_data
#[no_mangle]
pub extern "C" fn regorus_engine_clear_data(engine: *mut RegorusEngine) -> RegorusResult {
    to_regorus_result(|| -> Result<()> {
        to_ref(&engine)?.engine.clear_data();
        Ok(())
    }())
}

/// Set input.
///
/// See https://docs.rs/regorus/0.1.0-alpha.2/regorus/struct.Engine.html#method.set_input
/// * `input`: JSON encoded value to be used as input to query.
#[no_mangle]
pub extern "C" fn regorus_engine_set_input_json(
    engine: *mut RegorusEngine,
    input: *const c_char,
) -> RegorusResult {
    to_regorus_result(|| -> Result<()> {
        to_ref(&engine)?
            .engine
            .set_input(regorus::Value::from_json_str(&from_c_str("input", input)?)?);
        Ok(())
    }())
}

#[cfg(feature = "std")]
#[no_mangle]
pub extern "C" fn regorus_engine_set_input_from_json_file(
    engine: *mut RegorusEngine,
    path: *const c_char,
) -> RegorusResult {
    to_regorus_result(|| -> Result<()> {
        to_ref(&engine)?
            .engine
            .set_input(regorus::Value::from_json_file(from_c_str("path", path)?)?);
        Ok(())
    }())
}

/// Evaluate query.
///
/// See https://docs.rs/regorus/0.1.0-alpha.2/regorus/struct.Engine.html#method.eval_query
/// * `query`: Rego expression to be evaluate.
#[no_mangle]
pub extern "C" fn regorus_engine_eval_query(
    engine: *mut RegorusEngine,
    query: *const c_char,
) -> RegorusResult {
    let output = || -> Result<String> {
        let results = to_ref(&engine)?
            .engine
            .eval_query(from_c_str("query", query)?, false)?;
        Ok(serde_json::to_string_pretty(&results)?)
    }();
    match output {
        Ok(out) => RegorusResult {
            status: RegorusStatus::RegorusStatusOk,
            output: to_c_str(out),
            action: std::ptr::null_mut(),
            rule: std::ptr::null_mut(),
            input_value: std::ptr::null_mut(),
            error_message: std::ptr::null_mut(),
        },
        Err(e) => to_regorus_result(Err(e)),
    }
}

#[no_mangle]
pub extern "C" fn regorus_parse_input(input: *const c_char) -> RegorusResult {
    if let Ok(inp) = from_c_str("input", input) {
        let input_str = inp;
        let input_val = Box::into_raw(Box::new(regorus::Value::from_json_str(&input_str).unwrap()));
        // println!("{}", Box::from_raw(input_val).to_string());

        // match input_val {
        //     Ok(mut val) =>
        RegorusResult {
            status: RegorusStatus::RegorusStatusOk,
            output: std::ptr::null_mut(),
            action: std::ptr::null_mut(),
            rule: std::ptr::null_mut(),
            input_value: input_val as *mut c_void,
            error_message: std::ptr::null_mut(),
            // },
            // Err(_) => to_regorus_result(Err(anyhow::Error::msg("bad"))),
        }
    } else {
        to_regorus_result(Err(anyhow::Error::msg("bad")))
    }
}

#[no_mangle]
pub extern "C" fn regorus_engine_set_input_eval_rule2(
    engine: *mut RegorusEngine,
    input: *const c_void,
    rule: *const c_char,
) -> RegorusResult {
    // let data: &mut State = unsafe { &mut *(data as *mut State) };
    let input_obj: &mut regorus::Value = unsafe { &mut *(input as *mut regorus::Value) };
    // println!("{}", input_obj.to_string());

    // use serde_json::Serializer;
    let output = || -> Result<regorus::Value> {
        to_ref(&engine)?.engine.set_input(input_obj.clone());
        to_ref(&engine)?.engine.eval_rule(from_c_str("rule", rule)?)
    }();

    let action_: String;
    let rule_: String;

    let action_val = regorus::Value::from("action");
    let rule_val = regorus::Value::from("rule");
    let default_str = regorus::Value::from("");

    if let Ok(out) = &output {
        // println!("output {}", out.to_string());

        if let regorus::Value::Object(map) = out {
            let act = map.get(&action_val).unwrap_or(&default_str).to_string();
            if act.len() > 0 {
                action_ = act[1..act.len() - 1].to_string();
            } else {
                action_ = act
            }

            let rl = map.get(&rule_val).unwrap_or(&default_str).to_string();
            if rl.len() > 0 {
                rule_ = rl[1..rl.len() - 1].to_string();
            } else {
                rule_ = rl
            }
        } else {
            action_ = "".to_string();
            rule_ = "".to_string();
        }
    } else {
        action_ = "".to_string();
        rule_ = "".to_string();
    }

    match output {
        Ok(_) => RegorusResult {
            status: RegorusStatus::RegorusStatusOk,
            output: std::ptr::null_mut(),
            action: to_c_str(action_),
            rule: to_c_str(rule_),
            input_value: std::ptr::null_mut(),
            error_message: std::ptr::null_mut(),
        },
        Err(e) => to_regorus_result(Err(e)),
    }
}

#[no_mangle]
pub extern "C" fn regorus_engine_set_input_eval_rule(
    engine: *mut RegorusEngine,
    input: *const c_char,
    rule: *const c_char,
) -> RegorusResult {
    static mut last_hash: u64 = 0;

    let input_str = from_c_str("input", input).unwrap();
    let mut hasher = DefaultHasher::new();
    input_str.hash(&mut hasher);
    let this_hash = hasher.finish();

    let mut parse_input = false;
    unsafe {
        if last_hash == 0 || this_hash != last_hash {
            parse_input = true;
            last_hash = this_hash;
        }
    }
    // use serde_json::Serializer;
    let output = || -> Result<regorus::Value> {
        if parse_input {
            to_ref(&engine)?
                .engine
                .set_input(regorus::Value::from_json_str(&input_str)?);
        }
        to_ref(&engine)?.engine.eval_rule(from_c_str("rule", rule)?)
    }();

    let action_: String;
    let rule_: String;

    let action_val = regorus::Value::from("action");
    let rule_val = regorus::Value::from("rule");
    let default_str = regorus::Value::from("");

    if let Ok(out) = &output {
        // println!("output {}", out.to_string());

        if let regorus::Value::Object(map) = out {
            let act = map.get(&action_val).unwrap_or(&default_str).to_string();
            if act.len() > 0 {
                action_ = act[1..act.len() - 1].to_string();
            } else {
                action_ = act
            }

            let rl = map.get(&rule_val).unwrap_or(&default_str).to_string();
            if rl.len() > 0 {
                rule_ = rl[1..rl.len() - 1].to_string();
            } else {
                rule_ = rl
            }
        } else {
            action_ = "".to_string();
            rule_ = "".to_string();
        }
    } else {
        action_ = "".to_string();
        rule_ = "".to_string();
    }

    match output {
        Ok(_) => RegorusResult {
            status: RegorusStatus::RegorusStatusOk,
            output: std::ptr::null_mut(),
            action: to_c_str(action_),
            rule: to_c_str(rule_),
            input_value: std::ptr::null_mut(),
            error_message: std::ptr::null_mut(),
        },
        Err(e) => to_regorus_result(Err(e)),
    }
}

/// Evaluate specified rule.
///
/// See https://docs.rs/regorus/0.1.0-alpha.2/regorus/struct.Engine.html#method.eval_rule
/// * `rule`: Path to the rule.
#[no_mangle]
pub extern "C" fn regorus_engine_eval_rule(
    engine: *mut RegorusEngine,
    rule: *const c_char,
) -> RegorusResult {
    let output = || -> Result<String> {
        to_ref(&engine)?
            .engine
            .eval_rule(from_c_str("rule", rule)?)?
            .to_json_str()
    }();
    match output {
        Ok(out) => RegorusResult {
            status: RegorusStatus::RegorusStatusOk,
            output: to_c_str(out),
            action: std::ptr::null_mut(),
            rule: std::ptr::null_mut(),
            input_value: std::ptr::null_mut(),
            error_message: std::ptr::null_mut(),
        },
        Err(e) => to_regorus_result(Err(e)),
    }
}

/// Enable/disable coverage.
///
/// See https://docs.rs/regorus/0.1.0-alpha.2/regorus/struct.Engine.html#method.set_enable_coverage
/// * `enable`: Whether to enable or disable coverage.
#[no_mangle]
#[cfg(feature = "coverage")]
pub extern "C" fn regorus_engine_set_enable_coverage(
    engine: *mut RegorusEngine,
    enable: bool,
) -> RegorusResult {
    to_regorus_result(|| -> Result<()> {
        to_ref(&engine)?.engine.set_enable_coverage(enable);
        Ok(())
    }())
}

/// Get coverage report.
///
/// See https://docs.rs/regorus/0.1.0-alpha.2/regorus/struct.Engine.html#method.get_coverage_report
#[no_mangle]
#[cfg(feature = "coverage")]
pub extern "C" fn regorus_engine_get_coverage_report(engine: *mut RegorusEngine) -> RegorusResult {
    let output = || -> Result<String> {
        Ok(serde_json::to_string_pretty(
            &to_ref(&engine)?.engine.get_coverage_report()?,
        )?)
    }();
    match output {
        Ok(out) => RegorusResult {
            status: RegorusStatus::RegorusStatusOk,
            output: to_c_str(out),
            action: std::ptr::null_mut(),
            rule: std::ptr::null_mut(),
            input_value: std::ptr::null_mut(),
            error_message: std::ptr::null_mut(),
        },
        Err(e) => to_regorus_result(Err(e)),
    }
}

/// Get pretty printed coverage report.
///
/// See https://docs.rs/regorus/latest/regorus/coverage/struct.Report.html#method.to_string_pretty
#[no_mangle]
#[cfg(feature = "coverage")]
pub extern "C" fn regorus_engine_get_coverage_report_pretty(
    engine: *mut RegorusEngine,
) -> RegorusResult {
    let output = || -> Result<String> {
        to_ref(&engine)?
            .engine
            .get_coverage_report()?
            .to_string_pretty()
    }();
    match output {
        Ok(out) => RegorusResult {
            status: RegorusStatus::RegorusStatusOk,
            output: to_c_str(out),
            action: std::ptr::null_mut(),
            rule: std::ptr::null_mut(),
            input_value: std::ptr::null_mut(),
            error_message: std::ptr::null_mut(),
        },
        Err(e) => to_regorus_result(Err(e)),
    }
}

/// Clear coverage data.
///
/// See https://docs.rs/regorus/0.1.0-alpha.2/regorus/struct.Engine.html#method.clear_coverage_data
#[no_mangle]
#[cfg(feature = "coverage")]
pub extern "C" fn regorus_engine_clear_coverage_data(engine: *mut RegorusEngine) -> RegorusResult {
    to_regorus_result(|| -> Result<()> {
        to_ref(&engine)?.engine.clear_coverage_data();
        Ok(())
    }())
}

/// Whether to gather output of print statements.
///
/// See https://docs.rs/regorus/0.1.0-alpha.2/regorus/struct.Engine.html#method.set_gather_prints
/// * `enable`: Whether to enable or disable gathering print statements.
#[no_mangle]
pub extern "C" fn regorus_engine_set_gather_prints(
    engine: *mut RegorusEngine,
    enable: bool,
) -> RegorusResult {
    to_regorus_result(|| -> Result<()> {
        to_ref(&engine)?.engine.set_gather_prints(enable);
        Ok(())
    }())
}

/// Take all the gathered print statements.
///
/// See https://docs.rs/regorus/0.1.0-alpha.2/regorus/struct.Engine.html#method.take_prints
#[no_mangle]
pub extern "C" fn regorus_engine_take_prints(engine: *mut RegorusEngine) -> RegorusResult {
    let output = || -> Result<String> {
        Ok(serde_json::to_string_pretty(
            &to_ref(&engine)?.engine.take_prints()?,
        )?)
    }();
    match output {
        Ok(out) => RegorusResult {
            status: RegorusStatus::RegorusStatusOk,
            output: to_c_str(out),
            action: std::ptr::null_mut(),
            rule: std::ptr::null_mut(),
            input_value: std::ptr::null_mut(),
            error_message: std::ptr::null_mut(),
        },
        Err(e) => to_regorus_result(Err(e)),
    }
}

/// Get AST of policies.
///
/// See https://docs.rs/regorus/latest/regorus/coverage/struct.Engine.html#method.get_ast_as_json
#[no_mangle]
#[cfg(feature = "ast")]
pub extern "C" fn regorus_engine_get_ast_as_json(engine: *mut RegorusEngine) -> RegorusResult {
    let output = || -> Result<String> { to_ref(&engine)?.engine.get_ast_as_json() }();
    match output {
        Ok(out) => RegorusResult {
            status: RegorusStatus::RegorusStatusOk,
            output: to_c_str(out),
            action: std::ptr::null_mut(),
            rule: std::ptr::null_mut(),
            input_value: std::ptr::null_mut(),
            error_message: std::ptr::null_mut(),
        },
        Err(e) => to_regorus_result(Err(e)),
    }
}

#[cfg(feature = "custom_allocator")]
extern "C" {
    fn regorus_aligned_alloc(alignment: usize, size: usize) -> *mut u8;
    fn regorus_free(ptr: *mut u8);
}

#[cfg(feature = "custom_allocator")]
mod allocator {
    use std::alloc::{GlobalAlloc, Layout};

    struct RegorusAllocator {}

    unsafe impl GlobalAlloc for RegorusAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let size = layout.size();
            let align = layout.align();

            crate::regorus_aligned_alloc(align, size)
        }

        unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
            crate::regorus_free(ptr)
        }
    }

    #[global_allocator]
    static ALLOCATOR: RegorusAllocator = RegorusAllocator {};
}
