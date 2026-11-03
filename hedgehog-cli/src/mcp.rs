// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! MCP (Model Context Protocol) server mode.
//!
//! Exposes Gorse as an MCP tool server over stdio. Any MCP-compatible agent
//! (Claude Code, Cursor, Cline, etc.) can query security checks via structured
//! JSON-RPC 2.0 messages.
//!
//! Tools:
//!   - check_command: Check a command against security packs
//!   - scan_content: Scan text for embedded secrets
//!   - explain_command: Explain why a command is blocked or allowed
//!
//! Protocol: JSON-RPC 2.0 over stdin/stdout, one message per line.

use hedgehog_packs::PackEngine;
use hedgehog_taint::content_patterns;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

/// Run the MCP server loop. Reads JSON-RPC from stdin, writes responses to stdout.
pub fn run_server() {
    let stdin = io::stdin();
    let stdout = io::stdout();

    let custom_dir = crate::config::packs_dir();
    let engine = match PackEngine::builtin_with_custom(&custom_dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to load security packs: {e}");
            std::process::exit(1);
        }
    };

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                write_response(
                    &stdout,
                    json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": {
                            "code": -32700,
                            "message": format!("Parse error: {e}")
                        }
                    }),
                );
                continue;
            }
        };

        let id = request.get("id").cloned();
        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(json!({}));

        let response = match method {
            "initialize" => handle_initialize(id.clone()),
            "initialized" => continue, // notification, no response
            "tools/list" => handle_tools_list(id.clone()),
            "tools/call" => handle_tools_call(id.clone(), &params, &engine),
            "resources/list" => handle_resources_list(id.clone()),
            "resources/read" => handle_resources_read(id.clone(), &params),
            "ping" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {}
            }),
            // Notifications (no id) — silently accept
            _ if id.is_none() => continue,
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": format!("Method not found: {method}")
                }
            }),
        };

        write_response(&stdout, response);
    }
}

fn write_response(stdout: &io::Stdout, response: Value) {
    let mut out = stdout.lock();
    let _ = serde_json::to_writer(&mut out, &response);
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

fn handle_initialize(id: Option<Value>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {},
                "resources": {}
            },
            "serverInfo": {
                "name": "gorse",
                "version": env!("CARGO_PKG_VERSION")
            }
        }
    })
}

fn handle_tools_list(id: Option<Value>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "tools": [
                {
                    "name": "check_command",
                    "description": "Check a shell command against Gorse security packs. Returns block/warn/allow status with severity, category, and safer alternatives.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "The shell command to check"
                            }
                        },
                        "required": ["command"]
                    }
                },
                {
                    "name": "scan_content",
                    "description": "Scan text content for embedded secrets (API keys, passwords, tokens, PEM keys, etc.). Returns detected secrets with confidence levels.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "content": {
                                "type": "string",
                                "description": "The text content to scan for secrets"
                            }
                        },
                        "required": ["content"]
                    }
                },
                {
                    "name": "explain_command",
                    "description": "Explain why a command is blocked or allowed, showing which security rules match and their categories.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "The shell command to explain"
                            }
                        },
                        "required": ["command"]
                    }
                },
                {
                    "name": "exposure_check",
                    "description": "Answer: if this laptop were compromised, what could an attacker reach? Inventories credentials and sessions on this machine (metadata and fingerprints only, never secret values), builds the permission graph, and reports attack paths, severities and persistence. Read-only; nothing is signed, sent, assumed or changed. Returns the same JSON as `gorse exposure --json` (schema_version 1).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "verify": {
                                "type": "boolean",
                                "description": "Confirm identities and permissions with read-only provider queries through the user's installed CLIs (aws sts/iam list, gh auth status, kubectl auth can-i, vault token lookup, gcloud auth list, az account/role list, eth_getCode). Default false. Needs a Gorse Pro or Team licence on this computer; the verified report carries an attestation stamp. Refused when the infrastructure map sets allow_remote_verification = false."
                            },
                            "map": {
                                "type": "string",
                                "description": "Path to an infrastructure map (authority.toml) to use instead of ~/.hedgehog/authority.toml"
                            },
                            "max_hops": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 12,
                                "description": "Maximum hops when searching indirect paths (default from the map, 6)"
                            }
                        }
                    }
                }
            ]
        }
    })
}

fn handle_tools_call(id: Option<Value>, params: &Value, engine: &PackEngine) -> Value {
    let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

    match tool_name {
        "check_command" => {
            let command = arguments
                .get("command")
                .and_then(|c| c.as_str())
                .unwrap_or("");
            tool_check_command(id, command, engine)
        }
        "scan_content" => {
            let content = arguments
                .get("content")
                .and_then(|c| c.as_str())
                .unwrap_or("");
            tool_scan_content(id, content)
        }
        "explain_command" => {
            let command = arguments
                .get("command")
                .and_then(|c| c.as_str())
                .unwrap_or("");
            tool_explain_command(id, command, engine)
        }
        "exposure_check" => {
            let verify = arguments
                .get("verify")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let map = arguments
                .get("map")
                .and_then(|m| m.as_str())
                .filter(|m| !m.trim().is_empty())
                .map(std::path::PathBuf::from);
            let max_hops = arguments
                .get("max_hops")
                .and_then(|h| h.as_u64())
                .map(|h| h.clamp(1, 12) as usize);
            tool_exposure_check(id, verify, map, max_hops)
        }
        _ => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32602,
                "message": format!("Unknown tool: {tool_name}")
            }
        }),
    }
}

fn tool_check_command(id: Option<Value>, command: &str, engine: &PackEngine) -> Value {
    // Use explain() to get all matching rules (check() returns only the first)
    let results = engine.explain(command);

    if results.is_empty() {
        return json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{
                    "type": "text",
                    "text": json!({
                        "status": "allowed",
                        "command": command,
                        "message": "No security rules matched. Command is allowed."
                    }).to_string()
                }]
            }
        });
    }

    let matches: Vec<Value> = results
        .iter()
        .map(|r| {
            let mut m = json!({
                "rule": r.rule_name,
                "pack": r.pack_name,
                "category": r.category,
                "severity": r.severity,
                "message": r.message,
            });
            if let Some(ref alt) = r.alternative {
                m["alternative"] = json!(alt);
            }
            if r.embedded {
                m["embedded"] = json!(true);
            }
            m
        })
        .collect();

    let has_block = results.iter().any(|r| r.severity == "block");
    let status = if has_block { "blocked" } else { "warned" };

    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{
                "type": "text",
                "text": json!({
                    "status": status,
                    "command": command,
                    "matches": matches
                }).to_string()
            }],
            "isError": has_block
        }
    })
}

fn tool_scan_content(id: Option<Value>, content: &str) -> Value {
    let mut all_findings = Vec::new();

    for (i, line) in content.lines().enumerate() {
        let line_num = i + 1;
        let findings = content_patterns::check_line_with_context(line, line_num, None);
        all_findings.extend(findings);

        let b64 = content_patterns::check_base64_content(line, line_num);
        all_findings.extend(b64);

        let unicode = content_patterns::check_unicode_obfuscated(line, line_num);
        all_findings.extend(unicode);
    }

    // Multi-line scan
    let lines: Vec<&str> = content.lines().collect();
    let multi = content_patterns::check_multi_line(&lines);
    all_findings.extend(multi);

    // Government classification markings are detected silently: never
    // returned to the agent. Any other marking carries only the fixed label
    // the detector gives it (no document text).
    all_findings.retain(|f| !crate::content_scanner::is_silent(f));

    if all_findings.is_empty() {
        return json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{
                    "type": "text",
                    "text": json!({
                        "secrets_found": 0,
                        "message": "No secrets detected in the provided content."
                    }).to_string()
                }]
            }
        });
    }

    let secrets: Vec<Value> = all_findings
        .iter()
        .map(|f| {
            json!({
                "type": f.secret_type.name(),
                "category": f.secret_type.category(),
                "confidence": f.confidence.label(),
                "context": f.context.label(),
                "line": f.line_number,
                "preview": f.redacted_preview,
                "description": f.description,
            })
        })
        .collect();

    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{
                "type": "text",
                "text": json!({
                    "secrets_found": secrets.len(),
                    "findings": secrets
                }).to_string()
            }],
            "isError": true
        }
    })
}

fn tool_explain_command(id: Option<Value>, command: &str, engine: &PackEngine) -> Value {
    let results = engine.explain(command);

    if results.is_empty() {
        return json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{
                    "type": "text",
                    "text": json!({
                        "command": command,
                        "status": "allowed",
                        "rules_checked": engine.rule_count(),
                        "message": "No security rules matched this command."
                    }).to_string()
                }]
            }
        });
    }

    let explanations: Vec<Value> = results
        .iter()
        .map(|r| {
            let mut e = json!({
                "rule": r.rule_name,
                "pack": r.pack_name,
                "category": r.category,
                "severity": r.severity,
                "message": r.message,
            });
            if let Some(ref alt) = r.alternative {
                e["alternative"] = json!(alt);
            }
            if r.embedded {
                e["embedded_command"] = json!(true);
            }
            e
        })
        .collect();

    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{
                "type": "text",
                "text": json!({
                    "command": command,
                    "status": if results.iter().any(|r| r.severity == "block") { "blocked" } else { "warned" },
                    "rules_matched": explanations.len(),
                    "explanations": explanations
                }).to_string()
            }]
        }
    })
}

// ─── MCP Resources ───────────────────────────────────────────────────────────

/// `exposure_check`: the compromised-laptop analysis as an MCP tool. The
/// result text is the full `gorse exposure --json` document, so an agent
/// or automation gets exactly what the CLI gives, including `schema_version`.
/// Secrets never appear in that document; only fingerprints and metadata.
fn tool_exposure_check(
    id: Option<Value>,
    verify: bool,
    map: Option<std::path::PathBuf>,
    max_hops: Option<usize>,
) -> Value {
    use crate::exposure;
    let tool_error = |id: Option<Value>, message: String| {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{
                    "type": "text",
                    "text": json!({"error": message}).to_string()
                }],
                "isError": true
            }
        })
    };
    // verify is the one paid part of the check: gate it before anything runs.
    let mut attestor = None;
    if verify {
        let status = crate::credential_store::status();
        if let Err(message) = exposure::verify_allowed(crate::credential_store::tier_of(&status)) {
            return tool_error(id, message);
        }
        attestor = Some(exposure::Attestor {
            holder: status.email.clone().unwrap_or_else(|| "unknown".into()),
            machine: status
                .machine_id
                .clone()
                .unwrap_or_else(|| "unknown".into()),
        });
    }
    match exposure::run(&exposure::Options {
        verify,
        declarations: map,
        max_hops,
        trufflehog: true,
    }) {
        Ok(mut report) => {
            // Stamped last, over the document exactly as returned.
            let (body, _) = exposure::finalize(&mut report, None, attestor.as_ref());
            let worst_is_high = exposure::exit_code(&report) == 1;
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{
                        "type": "text",
                        "text": body.to_string()
                    }],
                    "isError": false,
                    "_meta": {
                        "schema_version": exposure::report::SCHEMA_VERSION,
                        "findings_at_or_above_high": worst_is_high,
                        "summary": body["summary"].clone()
                    }
                }
            })
        }
        Err(e) => tool_error(id, e),
    }
}

fn handle_resources_list(id: Option<Value>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "resources": [
                {
                    "uri": "gorse://status",
                    "name": "Protection Status",
                    "description": "Current Gorse protection status: secrets found, tiers, platform info",
                    "mimeType": "application/json"
                },
                {
                    "uri": "gorse://secrets",
                    "name": "Secret Inventory",
                    "description": "List of detected secret file paths with protection status",
                    "mimeType": "application/json"
                },
                {
                    "uri": "gorse://rules",
                    "name": "Security Rules",
                    "description": "Summary of loaded security packs and rule counts by category",
                    "mimeType": "application/json"
                }
            ]
        }
    })
}

fn handle_resources_read(id: Option<Value>, params: &Value) -> Value {
    let uri = params.get("uri").and_then(|u| u.as_str()).unwrap_or("");

    match uri {
        "gorse://status" => resource_status(id),
        "gorse://secrets" => resource_secrets(id),
        "gorse://rules" => resource_rules(id),
        _ => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32602,
                "message": format!("Unknown resource: {uri}")
            }
        }),
    }
}

fn resource_status(id: Option<Value>) -> Value {
    // Same truth as `gorse status`: found = credential locations that
    // exist, protected = found only while a hook or the sensor is live.
    let protection = crate::Protection::gather();
    let total = protection.found_count();
    let protected = protection.protected_count();
    let unprotected = total - protected;

    let custom_dir = crate::config::packs_dir();
    let engine = PackEngine::builtin_with_custom(&custom_dir)
        .unwrap_or_else(|_| PackEngine::builtin().unwrap());

    let status = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "platform": crate::platform_name(),
        "arch": std::env::consts::ARCH,
        "secrets_total": total,
        "secrets_protected": protected,
        "secrets_unprotected": unprotected,
        "hooks": protection.hooks_json(),
        "sensor_running": protection.sensor_running,
        "rules_loaded": engine.rule_count(),
        "dcg_detected": crate::dcg_detected(),
    });

    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "contents": [{
                "uri": "gorse://status",
                "mimeType": "application/json",
                "text": status.to_string()
            }]
        }
    })
}

fn resource_secrets(id: Option<Value>) -> Value {
    // Only locations that exist are listed; "protected" is true for all of
    // them or none, depending on whether an enforcement layer is live.
    let protection = crate::Protection::gather();
    let enforcing = protection.enforcing();

    let secrets: Vec<Value> = protection
        .found()
        .iter()
        .map(|s| {
            json!({
                "path": s.path.display().to_string(),
                "protected": enforcing,
                "description": s.description,
                "source": "PathBased",
            })
        })
        .collect();

    let data = json!({
        "secrets_count": secrets.len(),
        "secrets": secrets,
    });

    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "contents": [{
                "uri": "gorse://secrets",
                "mimeType": "application/json",
                "text": data.to_string()
            }]
        }
    })
}

fn resource_rules(id: Option<Value>) -> Value {
    let custom_dir = crate::config::packs_dir();
    let engine = PackEngine::builtin_with_custom(&custom_dir)
        .unwrap_or_else(|_| PackEngine::builtin().unwrap());

    let data = json!({
        "total_rules": engine.rule_count(),
        "categories": [
            "destructive", "spending", "crypto", "secrets",
            "cloud", "disclosure", "subscription", "tool_aware"
        ],
        "custom_packs_dir": custom_dir.display().to_string(),
        "custom_packs_exist": custom_dir.is_dir(),
    });

    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "contents": [{
                "uri": "gorse://rules",
                "mimeType": "application/json",
                "text": data.to_string()
            }]
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_returns_capabilities() {
        let response = handle_initialize(Some(json!(1)));
        let result = response.get("result").unwrap();
        assert_eq!(result["serverInfo"]["name"].as_str().unwrap(), "gorse");
        assert!(result.get("capabilities").is_some());
    }

    #[test]
    fn tools_list_returns_four_tools() {
        let response = handle_tools_list(Some(json!(2)));
        let tools = response["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 4);
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"check_command"));
        assert!(names.contains(&"scan_content"));
        assert!(names.contains(&"explain_command"));
        assert!(names.contains(&"exposure_check"));
        let exposure = tools
            .iter()
            .find(|t| t["name"] == "exposure_check")
            .unwrap();
        // verify is opt-in: not required, documented as default false
        assert!(exposure["inputSchema"]["required"].is_null());
        assert!(
            exposure["inputSchema"]["properties"]["verify"]["description"]
                .as_str()
                .unwrap()
                .contains("Default false")
        );
    }

    #[test]
    fn check_command_blocks_rm_rf() {
        let engine = PackEngine::builtin().unwrap();
        // Pattern requires trailing space after /
        let response = tool_check_command(Some(json!(3)), "rm -rf / --no-preserve-root", &engine);
        let text: Value =
            serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(text["status"].as_str().unwrap(), "blocked");
        assert!(text.get("matches").is_some());
    }

    #[test]
    fn check_command_allows_ls() {
        let engine = PackEngine::builtin().unwrap();
        let response = tool_check_command(Some(json!(4)), "ls -la", &engine);
        let text: Value =
            serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(text["status"].as_str().unwrap(), "allowed");
    }

    #[test]
    fn scan_content_finds_aws_key() {
        let response = tool_scan_content(Some(json!(5)), "My key: AKIAIOSFODNN7EXAMPLE");
        let text: Value =
            serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert!(text["secrets_found"].as_u64().unwrap() > 0);
    }

    #[test]
    fn scan_content_clean_text() {
        let response = tool_scan_content(Some(json!(6)), "Hello, this is a normal text.");
        let text: Value =
            serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(text["secrets_found"].as_u64().unwrap(), 0);
    }

    #[test]
    fn explain_command_explains_dangerous() {
        let engine = PackEngine::builtin().unwrap();
        let response = tool_explain_command(Some(json!(7)), "rm -rf / --no-preserve-root", &engine);
        let text: Value =
            serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(text["status"].as_str().unwrap(), "blocked");
        assert!(text["rules_matched"].as_u64().unwrap() > 0);
    }

    // ── Resource tests ──────────────────────────────────────────────────

    #[test]
    fn resources_list_returns_three_resources() {
        let response = handle_resources_list(Some(json!(10)));
        let resources = response["result"]["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 3);
        let uris: Vec<&str> = resources.iter().filter_map(|r| r["uri"].as_str()).collect();
        assert!(uris.contains(&"gorse://status"));
        assert!(uris.contains(&"gorse://secrets"));
        assert!(uris.contains(&"gorse://rules"));
    }

    #[test]
    fn resource_status_returns_data() {
        let response = resource_status(Some(json!(11)));
        let contents = response["result"]["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"].as_str().unwrap(), "gorse://status");
        let data: Value = serde_json::from_str(contents[0]["text"].as_str().unwrap()).unwrap();
        assert!(data.get("version").is_some());
        assert!(data.get("secrets_total").is_some());
        assert!(data.get("rules_loaded").is_some());
    }

    #[test]
    fn resource_secrets_returns_data() {
        let response = resource_secrets(Some(json!(12)));
        let contents = response["result"]["contents"].as_array().unwrap();
        let data: Value = serde_json::from_str(contents[0]["text"].as_str().unwrap()).unwrap();
        assert!(data.get("secrets_count").is_some());
        assert!(data.get("secrets").is_some());
    }

    #[test]
    fn resource_rules_returns_data() {
        let response = resource_rules(Some(json!(13)));
        let contents = response["result"]["contents"].as_array().unwrap();
        let data: Value = serde_json::from_str(contents[0]["text"].as_str().unwrap()).unwrap();
        assert!(data["total_rules"].as_u64().unwrap() >= 80);
        assert!(data.get("categories").is_some());
    }

    #[test]
    fn resource_unknown_uri_returns_error() {
        let response = handle_resources_read(Some(json!(14)), &json!({"uri": "gorse://unknown"}));
        assert!(response.get("error").is_some());
    }

    fn scan_content_findings(content: &str) -> Value {
        let response = tool_scan_content(Some(json!(9)), content);
        serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
    }

    #[test]
    fn scan_content_never_returns_government_markings() {
        let text = scan_content_findings(
            "TOP SECRET//SI//EXAMPLECODEWORD//NOFORN\n(S//EXAMPLECODEWORD) troop movements\nCUI//SP-PRVCY\nHandling: ORCON",
        );
        assert_eq!(text["secrets_found"].as_u64().unwrap(), 0, "{text}");
        let raw = text.to_string();
        assert!(!raw.contains("EXAMPLECODEWORD"), "{raw}");
        assert!(!raw.contains("sensitive_marking"), "{raw}");
    }

    #[test]
    fn scan_content_returns_commercial_markings_with_fixed_labels() {
        let text = scan_content_findings(
            "EXAMPLECODEWORD controlled under 22 CFR 120-130\nSECRET//NOFORN",
        );
        assert_eq!(text["secrets_found"].as_u64().unwrap(), 1, "{text}");
        assert_eq!(
            text["findings"][0]["preview"],
            "[MARKING] ITAR export-control notice"
        );
        assert!(!text.to_string().contains("EXAMPLECODEWORD"));
    }
}
