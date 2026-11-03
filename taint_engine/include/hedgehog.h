/**
 * hedgehog.h — C interface for the Hedgehog Taint Engine
 *
 * This header is imported by the Swift system extension to call
 * into the Rust taint tracking engine.
 *
 * Usage from Swift:
 *   let engine = hedgehog_create()
 *   defer { hedgehog_destroy(engine) }
 *
 *   // In ESF event handler:
 *   let decision = hedgehog_on_file_open(engine, pid, path)
 *   let decision = hedgehog_on_connect(engine, pid, addr, port)
 */

#ifndef HEDGEHOG_H
#define HEDGEHOG_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opaque pointer to the taint engine.
 * Created by hedgehog_create(), freed by hedgehog_destroy().
 */
typedef struct TaintEngine TaintEngine;

/**
 * Decision values returned by event handlers:
 *   0 = Allow  — operation is permitted
 *   1 = Taint  — file open is permitted, but process is now tainted
 *   2 = Block  — network connection is denied
 */
enum {
    HEDGEHOG_ALLOW = 0,
    HEDGEHOG_TAINT = 1,
    HEDGEHOG_BLOCK = 2,
};

/* ── Tier Enum ─────────────────────────────────────────────────── */

enum HedgehogTier {
    HEDGEHOG_TIER_FREE = 0,
    HEDGEHOG_TIER_PERSONAL = 1,
    HEDGEHOG_TIER_DEVELOPER = 2,
    HEDGEHOG_TIER_TEAM = 3,
};

/* ─── Lifecycle ─── */

/** Create a new taint engine with default configuration. */
TaintEngine* hedgehog_create(void);

/** Destroy a taint engine and free all memory. */
void hedgehog_destroy(TaintEngine* engine);

/* ─── Event Handlers (called from ESF/ETW/eBPF) ─── */

/**
 * A process opened a file.
 * Returns HEDGEHOG_ALLOW if not a secret (or derived secret).
 * Returns HEDGEHOG_TAINT if process is now tainted.
 * Always allows the file open (never returns HEDGEHOG_BLOCK for file opens).
 */
int hedgehog_on_file_open(TaintEngine* engine, int pid, const char* path);

/**
 * A process wants to connect to a network address.
 * Returns HEDGEHOG_ALLOW if untainted or destination is allowlisted.
 * Returns HEDGEHOG_BLOCK if tainted and destination is not allowlisted.
 * v0.3: Localhost connections propagate taint to listener processes.
 * v0.4: Project-scoped allowlists checked before global.
 */
int hedgehog_on_connect(TaintEngine* engine, int pid, const char* addr, uint16_t port);

/** A process forked. Propagates taint and project scope from parent to child. */
void hedgehog_on_fork(TaintEngine* engine, int parent_pid, int child_pid);

/** A process exec'd a new binary. Taint is preserved. */
void hedgehog_on_exec(TaintEngine* engine, int pid, const char* new_path);

/** A process exited. Cleans up taint, process tree, listeners, and project scope. */
void hedgehog_on_exit(TaintEngine* engine, int pid);

/* ─── v0.3: Localhost Relay Detection ─── */

/** A process started listening on a local port. */
void hedgehog_on_listen(TaintEngine* engine, int pid, uint16_t port);

/** A process stopped listening on a port. */
void hedgehog_on_unlisten(TaintEngine* engine, int pid, uint16_t port);

/* ─── v0.4: Per-Project Scoping ─── */

/**
 * Set the working directory for a process.
 * This determines which project's allowlist applies.
 */
void hedgehog_set_pid_cwd(TaintEngine* engine, int pid, const char* cwd);

/**
 * Register a project with its hedgehog.toml configuration.
 * Returns the project index (>=0) on success, -1 on parse error.
 *
 * Example hedgehog.toml:
 *   name = "my-webapp"
 *   allow_domains = ["api.stripe.com", "registry.npmjs.org"]
 *   allow_suffixes = [".amazonaws.com"]
 */
int hedgehog_add_project(TaintEngine* engine, const char* root, const char* config_toml);

/* ─── v0.5: Write Taint Propagation ─── */

/**
 * A process wrote to a file. If the process is tainted, the file becomes
 * a "derived secret" — future reads by ANY process will trigger taint.
 * Returns 1 if the file was newly marked as derived, 0 otherwise.
 * Writes to /dev, /proc, /var/log, etc. are excluded.
 */
int hedgehog_on_file_write(TaintEngine* engine, int pid, const char* path);

/** Get the number of currently tracked derived secrets. */
int hedgehog_derived_count(const TaintEngine* engine);

/** Clean up expired derived secrets (call periodically from Swift host). */
void hedgehog_cleanup_derived(TaintEngine* engine);

/* ─── Queries ─── */

/** Check if a process is currently tainted. Returns 1 if yes, 0 if no. */
int hedgehog_is_tainted(const TaintEngine* engine, int pid);

/** Get the number of currently tainted processes. */
int hedgehog_tainted_count(const TaintEngine* engine);

/** Get total number of blocked connections since engine creation. */
uint64_t hedgehog_total_blocks(const TaintEngine* engine);

/* ─── Configuration ─── */

/** Deny all network destinations for tainted processes, including local relays and DNS. */
void hedgehog_set_deny_tainted_network(TaintEngine* engine, bool enabled);

/** Trusted host only: apply an already verified lease to its owner's engine. */
void hedgehog_set_verified_lease(TaintEngine* engine, int tier, uint64_t expires_at);

/** Add a file path to the secret file registry. */
void hedgehog_add_secret_path(TaintEngine* engine, const char* path);

/**
 * Register the default secret locations (~/.ssh, ~/.aws/credentials, ...)
 * for the user whose home directory is `home`. The extension runs as root
 * (HOME=/var/root), so call this once for every real user under /Users.
 * Returns 0 on success, -1 if `home` is NULL, empty, or not valid UTF-8.
 */
int hedgehog_add_user_home(TaintEngine* engine, const char* home);

/** Add a domain to the network allowlist (exact match). */
void hedgehog_add_allowed_domain(TaintEngine* engine, const char* domain);

/** Add a domain suffix to the allowlist (matches all subdomains). */
void hedgehog_add_allowed_suffix(TaintEngine* engine, const char* suffix);

/**
 * Add a DNS resolver IP address. When resolvers are configured,
 * only these IPs are allowed on port 53 (prevents DNS exfiltration).
 */
void hedgehog_add_dns_resolver(TaintEngine* engine, const char* ip);

/* ─── Licensing ─── */

/** Get the current license tier. Returns: 0=Free, 1=Personal, 2=Developer, 3=Team. */
int hedgehog_get_tier(const TaintEngine* engine);

/** Activate a license. tier: 0=Free, 1=Personal, 2=Developer, 3=Team. */
void hedgehog_activate_license(TaintEngine* engine, int tier, const char* key, uint64_t valid_days);

/** Get the number of protected secrets (within tier limit). */
int hedgehog_protected_count(const TaintEngine* engine);

/** Get the number of unprotected secrets (over tier limit). */
int hedgehog_unprotected_count(const TaintEngine* engine);

#ifdef __cplusplus
}
#endif

#endif /* HEDGEHOG_H */
