// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ast::{Expr, Ref};
use crate::builtins;
use crate::builtins::utils::{ensure_args_count, ensure_string};
use crate::lexer::Span;
use crate::value::Value;
use crate::*;
use atoi::atoi;
use std::net::IpAddr;
use std::str::FromStr;

use anyhow::{bail, Result};

pub fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinFcn>) {
    m.insert("net.cidr_contains", (cidr_contains, 2));
}

fn cidr_contains(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let name = "net.cidr_contains";
    ensure_args_count(span, name, params, args, 2)?;

    let cidr_net = ensure_string(name, &params[0], &args[0])?;
    let test_addr = ensure_string(name, &params[1], &args[1])?;

    let cidr_split: Vec<&str> = cidr_net.split('/').collect();

    if cidr_split.len() != 2 {
        bail!(params[1].span().error("need address and length"));
    }

    let cidr_net_addr = IpAddr::from_str(cidr_split[0]);

    if cidr_net_addr.is_err() {
        bail!(params[1].span().error("cannot parse address"));
    }

    let cidr_net_len = atoi::<u8>(cidr_split[1].as_bytes());

    if cidr_net_len.is_none() {
        bail!(params[1].span().error("cannot parse length"));
    }

    let base = cidr::AnyIpCidr::new(cidr_net_addr.unwrap(), cidr_net_len.unwrap());

    if base.is_err() {
        bail!(params[1].span().error("invalid cidr"));
    }

    let test_addr_parsed = IpAddr::from_str(&test_addr);

    if test_addr_parsed.is_err() {
        bail!(params[1].span().error("cannot parse test address"));
    }

    Ok(Value::Bool(
        base.unwrap().contains(test_addr_parsed.as_ref().unwrap()),
    ))
}
