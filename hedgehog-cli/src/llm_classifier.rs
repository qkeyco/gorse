// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! LLM Intent Classification — opt-in "paranoid mode" semantic analysis.
//!
//! When heuristics flag a command as suspicious AND paranoid_mode is enabled
//! in config, sends the command to an independent LLM for semantic intent
//! classification. Unlike regex, LLM classification understands novel encodings
//! and can't be easily tested against offline.
//!
//! Supported providers: Anthropic (Claude), OpenAI, Ollama (local).
//! Config in `~/.hedgehog/config.toml` under `[security]`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

/// Classification result from the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Classification {
    pub intent: String,
    pub confidence: f64,
    pub reasoning: String,
    pub should_block: bool,
}

/// Cache entry with TTL.
struct CacheEntry {
    result: Classification,
    created: Instant,
}

/// In-memory cache for LLM classifications.
pub struct ClassifierCache {
    entries: HashMap<String, CacheEntry>,
    ttl_secs: u64,
}

impl ClassifierCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            ttl_secs,
        }
    }

    pub fn get(&self, command: &str) -> Option<&Classification> {
        self.entries.get(command).and_then(|e| {
            if e.created.elapsed().as_secs() < self.ttl_secs {
                Some(&e.result)
            } else {
                None
            }
        })
    }

    pub fn insert(&mut self, command: String, result: Classification) {
        self.entries.insert(
            command,
            CacheEntry {
                result,
                created: Instant::now(),
            },
        );
        // Evict expired entries if cache gets large
        if self.entries.len() > 100 {
            self.entries
                .retain(|_, e| e.created.elapsed().as_secs() < self.ttl_secs);
        }
    }
}

/// The system prompt for LLM classification.
const SYSTEM_PROMPT: &str = r#"You are a security analyst classifying shell commands for a developer workstation protection tool called Gorse.

Classify the intent of the command as one of:
- "safe" — normal development activity
- "destructive" — deletes or corrupts data (rm -rf, format, DROP TABLE)
- "exfiltration" — sends data to external endpoints (curl upload, nc, DNS exfil)
- "financial" — spends money or transfers cryptocurrency
- "obfuscated" — deliberately obscured to hide true intent (base64 encoding, variable construction, eval chains)

Consider:
1. What the command ACTUALLY DOES, not what it looks like
2. Whether encoding/obfuscation is being used to hide intent
3. Whether the command accesses sensitive files or credentials
4. Whether data leaves the local machine

Respond with ONLY a JSON object:
{"intent": "...", "confidence": 0.0-1.0, "reasoning": "brief explanation", "should_block": true/false}

Block if intent is destructive, exfiltration, or financial with confidence > 0.6.
Block if intent is obfuscated with confidence > 0.7.
Allow if intent is safe with confidence > 0.5."#;

/// Classify a command using the configured LLM provider.
pub fn classify(
    command: &str,
    provider: &str,
    model: &str,
    cache: &mut ClassifierCache,
) -> Result<Classification, String> {
    // Check cache first
    if let Some(cached) = cache.get(command) {
        log::debug!(
            "LLM classifier cache hit for: {}",
            hedgehog_taint::content_patterns::safe_prefix(command, 50)
        );
        return Ok(cached.clone());
    }

    let result = match provider {
        "anthropic" => classify_anthropic(command, model)?,
        "openai" => classify_openai(command, model)?,
        "ollama" => classify_ollama(command, model)?,
        _ => return Err(format!("Unknown LLM provider: {provider}")),
    };

    cache.insert(command.to_string(), result.clone());
    Ok(result)
}

/// Classify using Anthropic (Claude) API.
fn classify_anthropic(command: &str, model: &str) -> Result<Classification, String> {
    let api_key = std::env::var("ANTHROPIC_API_KEY")
        .map_err(|_| "ANTHROPIC_API_KEY not set. Required for paranoid mode with Anthropic.")?;

    let body = serde_json::json!({
        "model": model,
        "max_tokens": 256,
        "system": SYSTEM_PROMPT,
        "messages": [
            {"role": "user", "content": format!("Classify this command:\n```\n{command}\n```")}
        ]
    });

    let resp = ureq::post("https://api.anthropic.com/v1/messages")
        .set("x-api-key", &api_key)
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .timeout(std::time::Duration::from_secs(5))
        .send_string(&body.to_string())
        .map_err(|e| format!("Anthropic API error: {e}"))?;

    let resp_str = resp
        .into_string()
        .map_err(|e| format!("Failed to read Anthropic response: {e}"))?;
    let resp_body: serde_json::Value = serde_json::from_str(&resp_str)
        .map_err(|e| format!("Failed to parse Anthropic response: {e}"))?;

    let text = resp_body["content"][0]["text"]
        .as_str()
        .ok_or("No text in Anthropic response")?;

    parse_classification(text)
}

/// Classify using OpenAI API.
fn classify_openai(command: &str, model: &str) -> Result<Classification, String> {
    let api_key = std::env::var("OPENAI_API_KEY")
        .map_err(|_| "OPENAI_API_KEY not set. Required for paranoid mode with OpenAI.")?;

    let body = serde_json::json!({
        "model": model,
        "max_tokens": 256,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": format!("Classify this command:\n```\n{command}\n```")}
        ]
    });

    let resp = ureq::post("https://api.openai.com/v1/chat/completions")
        .set("Authorization", &format!("Bearer {api_key}"))
        .set("content-type", "application/json")
        .timeout(std::time::Duration::from_secs(5))
        .send_string(&body.to_string())
        .map_err(|e| format!("OpenAI API error: {e}"))?;

    let resp_str = resp
        .into_string()
        .map_err(|e| format!("Failed to read OpenAI response: {e}"))?;
    let resp_body: serde_json::Value = serde_json::from_str(&resp_str)
        .map_err(|e| format!("Failed to parse OpenAI response: {e}"))?;

    let text = resp_body["choices"][0]["message"]["content"]
        .as_str()
        .ok_or("No text in OpenAI response")?;

    parse_classification(text)
}

/// Classify using local Ollama instance.
fn classify_ollama(command: &str, model: &str) -> Result<Classification, String> {
    let endpoint =
        std::env::var("OLLAMA_ENDPOINT").unwrap_or_else(|_| "http://localhost:11434".to_string());

    let body = serde_json::json!({
        "model": model,
        "stream": false,
        "system": SYSTEM_PROMPT,
        "prompt": format!("Classify this command:\n```\n{command}\n```")
    });

    let resp = ureq::post(&format!("{endpoint}/api/generate"))
        .set("content-type", "application/json")
        .timeout(std::time::Duration::from_secs(10))
        .send_string(&body.to_string())
        .map_err(|e| format!("Ollama API error: {e}"))?;

    let resp_str = resp
        .into_string()
        .map_err(|e| format!("Failed to read Ollama response: {e}"))?;
    let resp_body: serde_json::Value = serde_json::from_str(&resp_str)
        .map_err(|e| format!("Failed to parse Ollama response: {e}"))?;

    let text = resp_body["response"]
        .as_str()
        .ok_or("No response text from Ollama")?;

    parse_classification(text)
}

/// Parse the LLM's JSON response into a Classification.
fn parse_classification(text: &str) -> Result<Classification, String> {
    // Try to find JSON in the response (LLMs sometimes wrap in markdown)
    let json_str = if let Some(start) = text.find('{') {
        if let Some(end) = text.rfind('}') {
            &text[start..=end]
        } else {
            text
        }
    } else {
        text
    };

    serde_json::from_str(json_str).map_err(|e| {
        log::warn!("Failed to parse LLM classification: {e}. Raw: {text}");
        format!("Failed to parse LLM response as JSON: {e}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_classification() {
        let json = r#"{"intent": "safe", "confidence": 0.95, "reasoning": "Simple ls command", "should_block": false}"#;
        let c = parse_classification(json).unwrap();
        assert_eq!(c.intent, "safe");
        assert!(!c.should_block);
        assert!(c.confidence > 0.9);
    }

    #[test]
    fn parses_markdown_wrapped_json() {
        let text = "Here's my analysis:\n```json\n{\"intent\": \"destructive\", \"confidence\": 0.9, \"reasoning\": \"rm -rf\", \"should_block\": true}\n```";
        let c = parse_classification(text).unwrap();
        assert_eq!(c.intent, "destructive");
        assert!(c.should_block);
    }

    #[test]
    fn cache_hit_and_miss() {
        let mut cache = ClassifierCache::new(300);
        assert!(cache.get("test cmd").is_none());

        cache.insert(
            "test cmd".to_string(),
            Classification {
                intent: "safe".to_string(),
                confidence: 0.9,
                reasoning: "test".to_string(),
                should_block: false,
            },
        );

        assert!(cache.get("test cmd").is_some());
        assert_eq!(cache.get("test cmd").unwrap().intent, "safe");
        assert!(cache.get("other cmd").is_none());
    }

    #[test]
    fn system_prompt_is_valid() {
        assert!(SYSTEM_PROMPT.contains("safe"));
        assert!(SYSTEM_PROMPT.contains("destructive"));
        assert!(SYSTEM_PROMPT.contains("exfiltration"));
        assert!(SYSTEM_PROMPT.contains("should_block"));
    }
}
