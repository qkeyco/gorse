// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Content-based secret and risk pattern matching.
//!
//! Pure matching logic — no file I/O, no external dependencies.
//! Detects secrets embedded in file contents: API keys, seed phrases,
//! PEM keys, credit cards, connection strings, passwords, and more.
//!
//! All detection uses only `std` library types. Pattern matching is
//! organized into four confidence tiers:
//!   - Definitive: zero false positives (PEM headers, API key prefixes)
//!   - High: strong structural match (seed phrases, JWT, credit cards)
//!   - ContextDependent: keyword + value patterns (passwords, SSN)
//!   - Heuristic: filename-based suspicion (photos of recovery keys)

/// Confidence level of a content finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Definitive,
    High,
    ContextDependent,
    Heuristic,
}

impl Confidence {
    pub fn label(&self) -> &'static str {
        match self {
            Confidence::Definitive => "definitive",
            Confidence::High => "high",
            Confidence::ContextDependent => "context",
            Confidence::Heuristic => "heuristic",
        }
    }

    pub fn priority(&self) -> &'static str {
        match self {
            Confidence::Definitive => "critical",
            Confidence::High => "high",
            Confidence::ContextDependent => "medium",
            Confidence::Heuristic => "medium",
        }
    }

    /// Downgrade confidence by one tier (used when finding is in a comment).
    pub fn downgrade(&self) -> Confidence {
        match self {
            Confidence::Definitive => Confidence::High,
            Confidence::High => Confidence::ContextDependent,
            Confidence::ContextDependent => Confidence::Heuristic,
            Confidence::Heuristic => Confidence::Heuristic,
        }
    }
}

/// Context in which a finding was detected. Affects effective risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineContext {
    /// Pattern found in code or data (default).
    Code,
    /// Pattern found inside a code comment (lower risk — may be documentation).
    Comment,
    /// Pattern found in shell history or executed command (higher risk).
    Executed,
    /// Pattern found inside base64-encoded content.
    Base64Encoded,
}

impl LineContext {
    pub fn label(&self) -> &'static str {
        match self {
            LineContext::Code => "code",
            LineContext::Comment => "comment",
            LineContext::Executed => "executed",
            LineContext::Base64Encoded => "base64",
        }
    }
}

/// Type of content secret detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentSecretType {
    PemPrivateKey,
    AwsAccessKey,
    ApiKey { service: &'static str },
    GoogleServiceAccount,
    SeedPhrase,
    WifPrivateKey,
    EthHexKey,
    JwtToken,
    CreditCard,
    DbConnectionString,
    PasswordPattern,
    SsnPattern,
    TwoFactorBackupCodes,
    SuspiciousImage,
    IbanPattern,
    SensitiveMarking { marking: &'static str },
}

/// Severity level based on the *type* of secret, not match confidence.
///
/// Confidence answers "how sure are we this is a match?"
/// Severity answers "how dangerous is this type of secret?"
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Direct credentials that enable immediate exploitation.
    Critical,
    /// Sensitive material: financial data, identity info, auth tokens, classified docs.
    High,
    /// Policy/regulatory concerns: corporate labels, export control, dissemination markings.
    Medium,
    /// Heuristic suspicion — e.g. image filenames that might contain photographed keys.
    Low,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }
}

impl ContentSecretType {
    /// Severity based on the danger of this secret type — independent of match confidence.
    pub fn severity(&self) -> Severity {
        match self {
            // Direct credentials — immediate exploit
            ContentSecretType::PemPrivateKey
            | ContentSecretType::AwsAccessKey
            | ContentSecretType::ApiKey { .. }
            | ContentSecretType::GoogleServiceAccount
            | ContentSecretType::WifPrivateKey
            | ContentSecretType::EthHexKey
            | ContentSecretType::DbConnectionString
            | ContentSecretType::PasswordPattern => Severity::Critical,

            // Financial, identity, auth material
            ContentSecretType::SeedPhrase
            | ContentSecretType::CreditCard
            | ContentSecretType::IbanPattern
            | ContentSecretType::SsnPattern
            | ContentSecretType::JwtToken
            | ContentSecretType::TwoFactorBackupCodes => Severity::High,

            // Sensitivity markings — classify by sub-type
            ContentSecretType::SensitiveMarking { marking } => {
                match *marking {
                    // Government classification banners are high severity
                    "TOP SECRET" | "SECRET" | "CONFIDENTIAL" | "(TS)" | "(S)" | "(C)" => {
                        Severity::High
                    }
                    // Regulatory/policy markings are medium severity
                    _ => Severity::Medium,
                }
            }

            // Heuristic image suspicion
            ContentSecretType::SuspiciousImage => Severity::Low,
        }
    }

    /// True for government classification and dissemination markings
    /// (TOP SECRET, SECRET, CONFIDENTIAL, CUI, NOFORN, ORCON, REL TO and the
    /// portion marks). Policy since 2026-02-11: these are detected so the
    /// guard protects the file, but they are never shown to the user, written
    /// to JSON or uploaded. Commercial and export-control markings
    /// (Proprietary, Trade Secret, NDA, ITAR, EAR) stay visible.
    pub fn is_government_classification(&self) -> bool {
        match self {
            ContentSecretType::SensitiveMarking { marking } => is_government_marking(marking),
            _ => false,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ContentSecretType::PemPrivateKey => "pem_private_key",
            ContentSecretType::AwsAccessKey => "aws_access_key",
            ContentSecretType::ApiKey { .. } => "api_key",
            ContentSecretType::GoogleServiceAccount => "google_service_account",
            ContentSecretType::SeedPhrase => "seed_phrase",
            ContentSecretType::WifPrivateKey => "wif_private_key",
            ContentSecretType::EthHexKey => "eth_hex_key",
            ContentSecretType::JwtToken => "jwt_token",
            ContentSecretType::CreditCard => "credit_card",
            ContentSecretType::DbConnectionString => "db_connection_string",
            ContentSecretType::PasswordPattern => "password_pattern",
            ContentSecretType::SsnPattern => "ssn_pattern",
            ContentSecretType::TwoFactorBackupCodes => "two_factor_backup_codes",
            ContentSecretType::SuspiciousImage => "suspicious_image",
            ContentSecretType::IbanPattern => "iban_pattern",
            ContentSecretType::SensitiveMarking { .. } => "sensitive_marking",
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            ContentSecretType::PemPrivateKey
            | ContentSecretType::WifPrivateKey
            | ContentSecretType::EthHexKey => "Crypto Keys",
            ContentSecretType::AwsAccessKey
            | ContentSecretType::ApiKey { .. }
            | ContentSecretType::GoogleServiceAccount => "API Keys",
            ContentSecretType::SeedPhrase => "Seed Phrases",
            ContentSecretType::JwtToken => "Auth Tokens",
            ContentSecretType::CreditCard | ContentSecretType::IbanPattern => "Financial",
            ContentSecretType::DbConnectionString => "DB Credentials",
            ContentSecretType::PasswordPattern => "Passwords",
            ContentSecretType::SsnPattern => "Identity (SSN)",
            ContentSecretType::TwoFactorBackupCodes => "2FA Codes",
            ContentSecretType::SuspiciousImage => "Suspicious Images",
            ContentSecretType::SensitiveMarking { .. } => "Sensitivity Labels",
        }
    }
}

/// Government classification/dissemination marking names, as stored in
/// `ContentSecretType::SensitiveMarking { marking }`. See
/// [`ContentSecretType::is_government_classification`].
pub fn is_government_marking(marking: &str) -> bool {
    matches!(
        marking,
        "TOP SECRET"
            | "SECRET"
            | "CONFIDENTIAL"
            | "CUI"
            | "(TS)"
            | "(S)"
            | "(C)"
            | "(CUI)"
            | "NOFORN"
            | "ORCON"
            | "REL TO"
    )
}

/// A single content-based finding within a file.
#[derive(Debug, Clone)]
pub struct ContentFinding {
    pub secret_type: ContentSecretType,
    pub confidence: Confidence,
    pub context: LineContext,
    pub line_number: usize,
    pub redacted_preview: String,
    pub description: &'static str,
}

// ─── API Key Prefix Table (~70+ services) ────────────────────────────────────

/// (prefix, min_total_length, service_name)
const API_KEY_PREFIXES: &[(&str, usize, &str)] = &[
    // GitHub
    ("ghp_", 40, "GitHub Personal Access Token"),
    ("gho_", 40, "GitHub OAuth Token"),
    ("ghu_", 40, "GitHub User-to-Server Token"),
    ("ghs_", 40, "GitHub Server-to-Server Token"),
    ("github_pat_", 40, "GitHub Fine-Grained PAT"),
    // Stripe
    ("sk_live_", 30, "Stripe Secret Key (Live)"),
    ("sk_test_", 30, "Stripe Secret Key (Test)"),
    ("rk_live_", 30, "Stripe Restricted Key"),
    ("pk_live_", 30, "Stripe Publishable Key (Live)"),
    ("whsec_", 30, "Stripe Webhook Secret"),
    // Anthropic
    ("sk-ant-api03-", 40, "Anthropic API Key"),
    // Slack
    ("xoxb-", 40, "Slack Bot Token"),
    ("xoxp-", 40, "Slack User Token"),
    ("xoxs-", 40, "Slack Session Token"),
    ("xoxa-", 40, "Slack App Token"),
    // npm
    ("npm_", 30, "npm Access Token"),
    // Google
    ("AIza", 35, "Google API Key"),
    // SendGrid
    ("SG.", 50, "SendGrid API Key"),
    // OpenAI
    ("sk-proj-", 40, "OpenAI API Key"),
    // Square
    ("sq0csp-", 40, "Square Client Secret"),
    ("sq0atp-", 40, "Square Access Token"),
    // Facebook / Meta
    ("EAAG", 40, "Facebook Access Token"),
    ("EAABw", 40, "Meta Access Token"),
    // Google OAuth
    ("ya29.", 30, "Google OAuth Token"),
    // age encryption
    ("AGE-SECRET-KEY-", 50, "age Encryption Secret Key"),
    // DigitalOcean
    ("dop_v1_", 40, "DigitalOcean Personal Token"),
    ("doo_v1_", 40, "DigitalOcean OAuth Token"),
    // GitLab
    ("glpat-", 26, "GitLab Personal Access Token"),
    // PyPI
    ("pypi-", 40, "PyPI API Token"),
    // Notion
    ("napi_", 40, "Notion API Key"),
    // Hugging Face
    ("hf_", 30, "Hugging Face Token"),
    // Slack (legacy)
    ("slack-", 40, "Slack Legacy Token"),
    // Flutterwave
    ("FLWSECK-", 30, "Flutterwave Secret Key"),
    ("FLWPUBK-", 30, "Flutterwave Public Key"),
    // Twilio
    ("AC", 34, "Twilio Account SID"),
    // Shopify
    ("shpat_", 30, "Shopify Admin API Token"),
    ("shpss_", 30, "Shopify Shared Secret"),
    ("shpca_", 30, "Shopify Custom App Token"),
    ("shppa_", 30, "Shopify Partner API Token"),
    // Resend
    ("re_", 30, "Resend API Key"),
    // Sentry
    ("sntrys_", 40, "Sentry Auth Token"),
    // Optic
    ("od_", 30, "Optic API Key"),
    // Clojars
    ("CLOJARS_", 30, "Clojars Deploy Token"),
    // RubyGems
    ("rubygems_", 30, "RubyGems API Key"),
    // Coinbase
    ("NhqPtmd", 30, "Coinbase API Key"),
    // Databricks
    ("dapi", 30, "Databricks API Token"),
    // Confluent
    ("CONFLUENT_", 30, "Confluent API Key"),
    // Postman
    ("PMAK-", 40, "Postman API Key"),
    // Linear
    ("lin_api_", 30, "Linear API Key"),
    // Supabase
    ("sbp_", 30, "Supabase Service Key"),
    // Vercel
    ("vercel_", 30, "Vercel API Token"),
    // Railway
    ("railway_", 30, "Railway API Token"),
    // Planetscale
    ("pscale_tkn_", 30, "PlanetScale Token"),
    // Hashicorp Vault
    ("hvs.", 20, "HashiCorp Vault Token"),
    // Pulumi
    ("pul-", 30, "Pulumi Access Token"),
    // Doppler
    ("dp.st.", 30, "Doppler Service Token"),
    // Buildkite
    ("bkua_", 30, "Buildkite Agent Token"),
    // Netlify
    ("nfp_", 30, "Netlify Personal Access Token"),
    // Airtable
    ("pat", 30, "Airtable Personal Access Token"),
    // Mapbox
    ("sk.", 60, "Mapbox Secret Token"),
    // Algolia
    ("ALGOLIA_", 30, "Algolia API Key"),
    // Figma
    ("figd_", 30, "Figma Personal Access Token"),
    // CircleCI
    ("circle-", 30, "CircleCI API Token"),
    // D-27: AI Provider Token Prefixes
    // DeepSeek
    ("dsk-", 40, "DeepSeek API Key"),
    // Groq
    ("gsk_", 40, "Groq API Key"),
    // Replicate
    ("r8_", 40, "Replicate API Token"),
    // ElevenLabs
    ("el_", 30, "ElevenLabs API Key"),
    // Cohere
    ("co_", 30, "Cohere API Key"),
    // Mistral
    ("mist_", 30, "Mistral API Key"),
    // Perplexity
    ("pplx-", 40, "Perplexity API Key"),
    // Together AI
    ("tog_", 30, "Together AI API Key"),
    // Fireworks AI
    ("fw_", 30, "Fireworks AI API Key"),
    // Stability AI
    ("sk-", 40, "Stability AI API Key"),
];

// ─── BIP-39 Wordlist Prefixes (4-char prefixes of the 2048 BIP-39 words) ─────
//
// We store sorted 4-char prefixes for O(log n) binary search.
// This catches seed phrases without embedding the full wordlist.
// A word matches if its first 4 chars are in this list.

const BIP39_PREFIXES: &[&str] = &[
    "aban", "abil", "able", "abou", "abov", "abse", "abso", "abst", "absu", "abus", "acce", "acci",
    "acco", "accu", "ache", "acid", "acou", "acqu", "acre", "acro", "act", "acti", "acto", "actu",
    "adap", "add", "addi", "addr", "adju", "admi", "adop", "adul", "adva", "advi", "aero", "affa",
    "affo", "afra", "agai", "age", "agen", "agre", "ahea", "aim", "air", "airp", "aisl", "alar",
    "albu", "alco", "aler", "alie", "all", "alle", "allo", "almo", "alph", "alre", "also", "alte",
    "alum", "alwa", "amat", "amaz", "amon", "amou", "amus", "anal", "anch", "anci", "ange", "angr",
    "anim", "ankl", "anno", "annu", "anot", "answ", "ante", "anti", "anxi", "any", "apar", "apol",
    "appa", "appl", "appr", "aqua", "arch", "arct", "area", "aren", "argu", "aria", "arm", "arme",
    "armo", "army", "arra", "arre", "arri", "arro", "art", "arte", "arti", "artw", "ask", "aspe",
    "assa", "asse", "assi", "assu", "asth", "atom", "atta", "atte", "attr", "auct", "audi", "augu",
    "aunt", "auto", "autu", "aver", "avoc", "avoi", "awak", "awar", "awes", "awfu", "awkw", "axis",
    "baby", "bach", "back", "badg", "bag", "bala", "balc", "ball", "bamb", "bana", "band", "bank",
    "bar", "bare", "barg", "barn", "barr", "base", "basi", "bask", "batc", "bath", "batt", "be",
    "beac", "bean", "bear", "beat", "beau", "beca", "beco", "beef", "befo", "begi", "beha", "behi",
    "beli", "bell", "belo", "belt", "benc", "bene", "best", "betr", "bett", "betw", "beyo", "bicy",
    "bid", "bike", "bill", "bird", "birt", "bitt", "blac", "blad", "blam", "blan", "blas", "blea",
    "bles", "blin", "bloo", "blos", "blow", "blue", "blur", "blus", "boar", "boat", "body", "boil",
    "bomb", "bond", "bone", "bonu", "book", "boos", "boot", "bord", "bore", "borr", "boss", "bott",
    "boun", "bowl", "box", "boy", "brac", "brai", "bran", "bras", "brav", "brea", "bree", "bric",
    "brid", "brie", "brig", "brin", "bris", "broa", "broc", "brok", "bron", "broo", "brot", "brow",
    "brus", "bubb", "budd", "budg", "buff", "buil", "bulb", "bulk", "bull", "bund", "bunk", "burd",
    "burg", "burn", "bus", "busi", "busy", "butt", "buye", "buzz", "cabb", "cabi", "cabl", "cact",
    "cage", "cake", "call", "calm", "came", "camp", "can", "cana", "canc", "cand", "cann", "cano",
    "canv", "cany", "capa", "capi", "capt", "car", "carb", "card", "carg", "carp", "carr", "cart",
    "case", "cash", "casi", "cast", "casu", "cat", "cata", "catc", "cate", "catt", "caug", "caus",
    "caut", "cave", "ceil", "cele", "ceme", "cens", "cent", "cere", "cert", "chai", "cham", "chan",
    "chao", "chap", "char", "chas", "chea", "chec", "chee", "cher", "ches", "chic", "chie", "chil",
    "chim", "choi", "choo", "chro", "chuc", "chun", "chur", "ciga", "cinn", "circ", "citi", "city",
    "civi", "clai", "clam", "clap", "clar", "clas", "claw", "clay", "clea", "cler", "clev", "clif",
    "clim", "clin", "clip", "cloa", "cloc", "clog", "clos", "clot", "clou", "clow", "club", "clum",
    "clus", "clut", "coac", "coas", "coco", "code", "coff", "coil", "coin", "coll", "colo", "colu",
    "comb", "come", "comf", "comi", "comm", "comp", "conc", "cond", "conf", "cong", "conn", "cons",
    "cont", "conv", "cook", "cool", "copp", "copy", "cora", "core", "corn", "corr", "cost", "cott",
    "couc", "coun", "coup", "cour", "cous", "cove", "coyó", "crab", "crac", "crad", "craf", "cram",
    "cran", "cras", "crat", "craw", "craz", "crea", "cred", "crew", "cric", "crim", "cris", "crit",
    "crop", "cros", "crow", "cruc", "crue", "crui", "crum", "crun", "crus", "cry", "crys", "cube",
    "cult", "cup", "cupb", "curi", "curr", "curt", "curv", "cush", "cust", "cute", "cycl", "dad",
    "dail", "dama", "damp", "danc", "dang", "dare", "dark", "dash", "daug", "dawn", "day", "dead",
    "deal", "dear", "deba", "debr", "deca", "dece", "deci", "decl", "deco", "decr", "deer", "defe",
    "defi", "defy", "degr", "dela", "deli", "dema", "demo", "deni", "dent", "deny", "depa", "depe",
    "depl", "depo", "dept", "depu", "deri", "desc", "dese", "desi", "desk", "desp", "dest", "deta",
    "dete", "deve", "devi", "devo", "diag", "dial", "diam", "diar", "dice", "dies", "diet", "diff",
    "digi", "dign", "dile", "dilu", "dime", "dini", "dinn", "dino", "dire", "dirt", "disa", "disc",
    "dise", "dish", "dism", "diso", "disp", "dist", "ditc", "dive", "divo", "dizz", "doct", "docu",
    "dog", "doll", "dolp", "doma", "dona", "donk", "dono", "door", "dose", "doub", "dove", "draf",
    "drag", "dram", "dras", "draw", "drea", "dres", "drif", "dril", "drin", "drip", "driv", "drop",
    "drum", "dry", "duck", "dumb", "dune", "duri", "dust", "duty", "dwar", "dyna", "eage", "earl",
    "earn", "eart", "easi", "east", "easy", "echo", "ecol", "econ", "edge", "edit", "educ", "effo",
    "egg", "eigh", "eith", "elbo", "elde", "elec", "eleg", "elem", "elep", "elev", "elit", "else",
    "emba", "embr", "emer", "emis", "emot", "empl", "empo", "empt", "enab", "enac", "enem", "ener",
    "enfo", "enga", "engi", "enha", "enjo", "enli", "enou", "enri", "enro", "ensu", "ente", "enti",
    "entr", "enve", "epis", "equa", "equi", "era", "eros", "erro", "erup", "esca", "essa", "esta",
    "etat", "eter", "ethi", "evid", "evil", "evok", "evol", "exac", "exam", "exce", "exch", "exci",
    "excl", "excu", "exec", "exer", "exha", "exhi", "exil", "exit", "exot", "expa", "expe", "expi",
    "expo", "expr", "exte", "extr", "eye", "eyeb", "fabr", "face", "facu", "fade", "fain", "fait",
    "fall", "fals", "fame", "fami", "famo", "fan", "fanc", "fant", "farm", "fasc", "fash", "fat",
    "fata", "fath", "fati", "faul", "favo", "fawn", "fear", "feat", "febr", "fede", "fee", "feed",
    "feel", "fema", "fenc", "fest", "fetc", "feve", "few", "fibe", "fict", "fiel", "figu", "file",
    "film", "filt", "fina", "find", "fine", "fing", "fini", "fire", "firm", "firs", "fisc", "fish",
    "fit", "fitn", "fix", "flag", "flam", "flas", "flat", "flav", "flee", "flig", "flip", "floa",
    "floc", "floo", "flow", "flui", "flus", "fly", "foam", "focu", "fog", "foil", "fold", "foll",
    "food", "foot", "forc", "fore", "forg", "form", "fort", "foss", "fost", "foun", "fox", "frag",
    "fram", "freq", "fres", "frie", "frin", "frog", "fron", "fros", "frow", "froz", "frui", "fuel",
    "fun", "funn", "furn", "fury", "futu", "gadg", "gain", "gala", "gall", "game", "gap", "gara",
    "garb", "gard", "garl", "garm", "gas", "gasp", "gate", "gath", "gaug", "gaze", "gene", "geni",
    "genr", "gent", "genu", "gest", "ghos", "gian", "gift", "gigg", "ging", "gira", "girl", "give",
    "glad", "glan", "glar", "glas", "glea", "glob", "gloo", "glov", "glow", "glue", "goat", "godd",
    "gold", "good", "goos", "gori", "gosp", "goss", "gove", "gown", "grab", "grac", "grad", "grai",
    "gran", "grap", "gras", "grat", "grav", "gray", "grea", "gree", "grid", "grie", "grin", "grip",
    "groc", "grou", "grow", "grue", "grun", "guar", "gues", "guid", "guil", "guit", "gun", "gym",
    "habi", "hair", "half", "hamm", "hams", "hand", "happ", "harb", "hard", "hars", "harv", "hast",
    "hat", "have", "hawk", "haza", "head", "heal", "hear", "heav", "hedg", "heig", "hell", "help",
    "hen", "hero", "hid", "high", "hill", "hint", "hip", "hire", "hist", "hobb", "hock", "hold",
    "hole", "holi", "holl", "home", "hone", "hood", "hope", "horn", "horr", "hors", "hosp", "host",
    "hot", "hote", "hour", "hove", "hub", "huge", "huma", "humb", "humo", "hund", "hung", "hunt",
    "hurd", "hurr", "hurt", "husb", "hybr", "ice", "icon", "idea", "iden", "igno", "ill", "ille",
    "illn", "imag", "imit", "imme", "immu", "impa", "impo", "impr", "impu", "inab", "inch", "incl",
    "incr", "inde", "indi", "indo", "indu", "infa", "infl", "info", "inhe", "init", "inje", "inma",
    "inne", "inno", "inpu", "inqu", "insa", "inse", "insi", "insp", "inst", "insu", "inta", "inte",
    "into", "inva", "inve", "invi", "invo", "inwa", "iron", "isla", "isol", "issu", "item", "ivor",
    "jack", "jagu", "jar", "jazz", "jeal", "jean", "jell", "jerk", "jet", "jewe", "job", "jock",
    "join", "joke", "jour", "joy", "judg", "juic", "jump", "jung", "juni", "junk", "jury", "just",
    "juven", "kang", "keen", "keep", "ketc", "key", "kick", "kid", "kidn", "kind", "king", "kiss",
    "kit", "kitc", "kite", "kitt", "knee", "knif", "knoc", "know", "lab", "labe", "labo", "ladd",
    "lady", "lake", "lamp", "lang", "lapt", "larg", "late", "lati", "laug", "lava", "law", "lawn",
    "laws", "laye", "lazy", "lead", "leaf", "lean", "lear", "leas", "leat", "leav", "lect", "left",
    "leg", "lega", "lege", "leis", "lemo", "lend", "leng", "lens", "leop", "less", "lett", "leve",
    "liar", "libe", "libr", "lice", "life", "lift", "ligh", "like", "limb", "limi", "line", "link",
    "lion", "liqu", "list", "lite", "litt", "live", "liza", "load", "loan", "lobs", "loca", "lock",
    "logi", "lone", "long", "loop", "lott", "loud", "loun", "love", "loya", "luck", "lugg", "lumb",
    "luna", "lunc", "lung", "luxu", "lyri", "mach", "mad", "magi", "magn", "maid", "mail", "main",
    "majo", "make", "male", "mall", "mamm", "man", "mana", "mand", "mang", "mans", "manu", "mapl",
    "marb", "marc", "marg", "mari", "mark", "marr", "mask", "mass", "mast", "matc", "mate", "math",
    "matr", "matt", "maxi", "maze", "mead", "mean", "meas", "meat", "mech", "meda", "medi", "melo",
    "melt", "memb", "memo", "ment", "menu", "merc", "merg", "meri", "merr", "mesh", "mess", "meta",
    "meth", "midd", "midn", "milk", "mill", "mime", "mind", "mine", "mini", "mino", "minu", "mira",
    "mirr", "mise", "miss", "mist", "mix", "mixe", "mixt", "mobi", "mode", "modi", "mom", "mome",
    "mona", "monk", "mons", "mont", "mood", "moon", "mora", "more", "morn", "mosq", "moth", "moti",
    "moto", "moun", "mous", "move", "movi", "much", "muff", "mule", "mult", "musc", "muse", "mush",
    "musi", "must", "mutu", "myse", "myst", "myth", "naiv", "name", "napk", "narr", "nast", "nati",
    "natu", "near", "neat", "nece", "neck", "nega", "negl", "neit", "neph", "nerv", "nest", "net",
    "netw", "neut", "neve", "news", "next", "nice", "nigh", "nitr", "nobl", "nois", "nomi", "noon",
    "norm", "nort", "nose", "nota", "note", "noth", "noti", "nove", "now", "nucl", "numb", "nurs",
    "nut", "oak", "obey", "obje", "obli", "obsc", "obse", "obta", "obvi", "occu", "ocur", "ocea",
    "octo", "odd", "off", "offe", "offi", "offs", "oliv", "olym", "omit", "once", "one", "onio",
    "onli", "open", "oper", "opin", "oppo", "opti", "oral", "oran", "orbi", "orch", "orde", "ordi",
    "orga", "orie", "orig", "orna", "orph", "ostr", "othe", "outd", "oute", "outp", "oval", "oven",
    "over", "own", "owne", "oxyg", "oyst", "ozon", "pact", "padd", "page", "pair", "pala", "palm",
    "pand", "pane", "pani", "pant", "pape", "para", "pare", "park", "parr", "part", "pass", "patc",
    "path", "patr", "patt", "paus", "pave", "paym", "peac", "pean", "pear", "peas", "peda", "peel",
    "peer", "pelt", "pen", "pena", "pend", "peng", "peop", "pepp", "perf", "perm", "pers", "pet",
    "phon", "phot", "phra", "phys", "pian", "pick", "pict", "piec", "pig", "pige", "pill", "pilo",
    "pink", "pion", "pipe", "pist", "pitc", "pizz", "plac", "plan", "plas", "plat", "play", "plea",
    "pled", "pluc", "plug", "plun", "pock", "poem", "poet", "poin", "pola", "pole", "poli", "polo",
    "pond", "pony", "pool", "popu", "porc", "port", "pose", "posi", "poss", "post", "pota", "pott",
    "poul", "pour", "pove", "powe", "prac", "prai", "pray", "pred", "pref", "prep", "pres", "pret",
    "prev", "pric", "prid", "prim", "prin", "prio", "pris", "priv", "priz", "prob", "proc", "prod",
    "prof", "prog", "proj", "prom", "proo", "prop", "pros", "prot", "prou", "prov", "prox", "prud",
    "publ", "pudl", "pull", "pulp", "puls", "pump", "punc", "pung", "pupi", "pupp", "purc", "puri",
    "purp", "purs", "push", "put", "puzz", "pyra", "qual", "quan", "quar", "quer", "ques", "quic",
    "quit", "quiz", "quot", "rabb", "racc", "race", "rack", "rada", "radi", "raft", "rage", "rail",
    "rain", "rais", "rall", "ramp", "ranc", "rand", "rang", "rapi", "rare", "rate", "rath", "rave",
    "razo", "read", "real", "reas", "rebe", "rebu", "reca", "rece", "reci", "reco", "recy", "redu",
    "reef", "refe", "refl", "refo", "refu", "rega", "regi", "regr", "regu", "rein", "reje", "rela",
    "rele", "reli", "relu", "rema", "reme", "remi", "remo", "rene", "rent", "reop", "repa", "repe",
    "repl", "repo", "repr", "repu", "requ", "resc", "rese", "resi", "reso", "resp", "rest", "resu",
    "reta", "reti", "retr", "retu", "reun", "reve", "revi", "revo", "rewa", "rhyt", "rib", "ribb",
    "rice", "rich", "ride", "ridg", "rifl", "righ", "rigi", "ring", "riot", "ripp", "risk", "ritu",
    "riva", "rive", "road", "roas", "robo", "robu", "rock", "rode", "role", "roll", "roma", "roof",
    "rook", "room", "rose", "rota", "roug", "roun", "rout", "roya", "rubb", "rude", "rug", "rule",
    "run", "runa", "rura", "rush", "rust", "ruth", "rye", "sadd", "safe", "sail", "sala", "salm",
    "salo", "salt", "salu", "same", "samp", "sand", "sane", "sant", "sati", "satu", "sauc", "saus",
    "sava", "save", "say", "scal", "scan", "scar", "scat", "scen", "sche", "scho", "scie", "scis",
    "scoo", "scor", "scou", "scra", "scre", "scri", "sea", "sear", "seas", "seat", "seco", "secr",
    "sect", "secu", "seed", "seek", "segm", "sele", "sell", "semi", "sena", "seni", "sens", "sent",
    "seri", "serv", "sess", "sett", "seve", "shad", "shal", "sham", "shar", "shee", "shel", "sher",
    "shie", "shif", "shin", "ship", "shiv", "shoc", "shoe", "shoo", "shop", "shor", "shou", "shov",
    "shri", "shru", "shuf", "shy", "sibl", "sick", "side", "sieg", "sigh", "sign", "sile", "silk",
    "sill", "silv", "simi", "simp", "sinc", "sing", "sire", "sist", "sit", "situ", "six", "size",
    "skat", "skel", "ski", "skil", "skin", "skir", "skul", "slab", "slam", "slav", "slee", "slen",
    "slic", "slid", "slig", "slim", "slog", "slot", "slow", "slug", "slus", "smal", "smar", "smil",
    "smit", "smog", "smoo", "snac", "snai", "snak", "snap", "snif", "snow", "soap", "socc", "soci",
    "sock", "soda", "sofa", "soft", "sola", "sold", "soli", "solo", "solu", "some", "son", "song",
    "soon", "sorr", "sort", "soul", "soun", "soup", "sour", "sout", "spac", "spar", "spat", "spaw",
    "spec", "spee", "spel", "spen", "sphe", "spic", "spid", "spik", "spin", "spir", "spli", "spon",
    "spoo", "spor", "spot", "spra", "spre", "spri", "spur", "spy", "squa", "stab", "stac", "staf",
    "stag", "stai", "stak", "stal", "stam", "stan", "star", "stat", "stay", "stea", "stee", "stem",
    "step", "ster", "stew", "stic", "stil", "stin", "stir", "stoc", "stom", "ston", "stoo", "stor",
    "stov", "stra", "stre", "stri", "stro", "stru", "stud", "stuf", "stum", "styl", "subj", "subm",
    "subs", "subt", "such", "sudd", "suff", "suga", "sugg", "suit", "sulp", "summ", "sun", "sunn",
    "suns", "supe", "supp", "sure", "surf", "surg", "surp", "surr", "surv", "susp", "sust", "swal",
    "swam", "swan", "swap", "swar", "swea", "swee", "swim", "swin", "swir", "swit", "swor", "symb",
    "symp", "synd", "syru", "syst", "tabl", "tack", "tact", "tag", "tail", "tale", "talk", "tank",
    "tape", "targ", "task", "tast", "taxi", "teac", "team", "tell", "temp", "tena", "tend", "tenn",
    "tens", "term", "terr", "test", "text", "than", "that", "them", "then", "theo", "ther", "thic",
    "thin", "thir", "this", "thou", "thre", "thri", "thro", "thum", "thun", "tick", "tide", "tidy",
    "tie", "tige", "tigh", "tilt", "timb", "time", "tiny", "tip", "tire", "tiss", "titl", "toas",
    "toba", "toda", "todd", "toe", "toge", "toil", "toke", "toma", "tomo", "tone", "toni", "tool",
    "top", "topi", "topp", "torc", "torn", "tort", "toss", "tota", "tour", "towa", "town", "toy",
    "trac", "trad", "traf", "trag", "trai", "tran", "trap", "tras", "trav", "tray", "trea", "tree",
    "trem", "tria", "trib", "tric", "trig", "trim", "trip", "trop", "trou", "truc", "true", "trul",
    "trus", "tube", "tuna", "tunn", "ture", "turn", "turt", "twin", "twis", "two", "type", "typi",
    "ugly", "umbr", "unab", "unaw", "uncl", "unco", "unde", "undo", "undr", "unfa", "unfo", "unha",
    "unif", "unio", "uniq", "unit", "univ", "unkn", "unle", "unli", "unlo", "unpa", "unti", "unus",
    "unve", "upda", "upgi", "upon", "uppe", "upse", "urba", "urge", "usag", "use", "used", "usef",
    "usua", "util", "vaca", "vacu", "vagu", "vali", "vall", "valu", "valv", "van", "vani", "vapo",
    "vari", "vast", "vaul", "vehi", "velv", "vend", "vent", "venu", "verb", "veri", "vers", "very",
    "vest", "vete", "viab", "vibr", "vici", "vict", "vide", "view", "vill", "vint", "viol", "virt",
    "viru", "visa", "visi", "vita", "vivi", "voca", "voic", "void", "vola", "volu", "vote", "voya",
    "vulc", "vuln", "wage", "wago", "wait", "walk", "wall", "waln", "want", "ward", "warn", "warr",
    "wash", "wasp", "wast", "wate", "wave", "way", "weal", "weap", "wear", "weas", "weat", "web",
    "wedd", "week", "weig", "weir", "welc", "well", "west", "wet", "whal", "what", "whea", "whee",
    "wher", "whip", "whis", "wide", "widt", "wife", "wild", "will", "win", "wind", "wine", "wing",
    "wink", "winn", "wint", "wire", "wisd", "wise", "wish", "witn", "wolf", "woma", "wond", "wood",
    "wool", "word", "work", "worl", "worr", "wors", "wort", "woun", "wrap", "wrec", "wres", "wris",
    "writ", "wron", "yard", "year", "yell", "you", "youn", "yout", "zebr", "zero", "zone", "zoo",
];

/// Base58 character set (Bitcoin).
const BASE58_CHARS: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// PEM header suffixes that indicate private keys.
const PEM_PRIVATE_SUFFIXES: &[&str] = &[
    "RSA PRIVATE KEY-----",
    "EC PRIVATE KEY-----",
    "PRIVATE KEY-----",
    "DSA PRIVATE KEY-----",
    "OPENSSH PRIVATE KEY-----",
    "ENCRYPTED PRIVATE KEY-----",
    "PGP PRIVATE KEY BLOCK-----",
];

/// Database connection string prefixes with embedded credentials.
const DB_PREFIXES: &[&str] = &[
    "postgres://",
    "postgresql://",
    "mysql://",
    "mongodb://",
    "mongodb+srv://",
    "redis://",
    "rediss://",
    "amqp://",
    "amqps://",
    "mssql://",
];

/// Keywords that indicate a password or secret assignment.
const PASSWORD_KEYWORDS: &[&str] = &[
    "password",
    "passwd",
    "pass",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "access_key",
    "secret_key",
    "auth_token",
    "auth_key",
    "private_key",
    "encryption_key",
    "master_key",
    "session_secret",
    "jwt_secret",
    "signing_key",
    "client_secret",
];

/// Assignment operators to look for after password keywords.
const ASSIGNMENT_OPS: &[&str] = &["=", ":", "=>", ":="];

/// Placeholder values that should NOT trigger a finding.
const PLACEHOLDER_VALUES: &[&str] = &[
    "xxx",
    "XXX",
    "your-",
    "your_",
    "YOUR_",
    "TODO",
    "todo",
    "CHANGE",
    "change_me",
    "changeme",
    "example",
    "EXAMPLE",
    "placeholder",
    "replace",
    "REPLACE",
    "insert",
    "INSERT",
    "<",
    "${",
    "{{",
    "null",
    "nil",
    "none",
    "false",
    "true",
    "0",
    "1",
    "\"\"",
    "''",
    "empty",
    "EMPTY",
    "test",
    "TEST",
    "dummy",
    "DUMMY",
    "fake",
    "FAKE",
    "sample",
    "SAMPLE",
];

/// Image extensions (filename-only heuristic).
const IMAGE_EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "heic", "webp", "gif", "bmp", "tiff"];

/// Keywords in image filenames that suggest photographed secrets.
/// Must be specific enough to avoid matching normal filenames like "keyboard.png".
const IMAGE_SECRET_KEYWORDS: &[&str] = &[
    "recovery",
    "seed phrase",
    "mnemonic",
    "2fa",
    "backup code",
    "password",
    "wallet",
    "authenticator",
    "totp",
    "passphrase",
    "private key",
    "credential",
    "secret key",
    "recovery key",
    "seed-phrase",
    "backup-code",
    "private-key",
    "secret-key",
    "recovery-key",
    "seed_phrase",
    "backup_code",
    "private_key",
    "secret_key",
    "recovery_key",
];

// ─── Context Detection ──────────────────────────────────────────────────────

/// Detect whether a line is a code comment. Uses common comment syntax markers.
/// The longest prefix of `s` that is at most `max_bytes` long and ends on a
/// character boundary. Byte-offset slicing of scanned text panics when the
/// cut lands inside a multi-byte character (an em dash, an accented letter),
/// and a scanner must never crash on the content it is scanning.
pub fn safe_prefix(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

pub fn detect_line_context(line: &str) -> LineContext {
    let trimmed = line.trim();

    // Single-line comment styles
    if trimmed.starts_with("//")  // Rust, C, C++, Go, Java, JS, TS, Swift
        || trimmed.starts_with('#')   // Python, Ruby, Shell, YAML, TOML
            && !trimmed.starts_with("#!")  // Shebangs are executable, not comments
            && !trimmed.starts_with("#[") // Rust attributes
        || trimmed.starts_with("--")  // SQL, Haskell, Lua
        || trimmed.starts_with("/*")  // C-style block comment start
        || trimmed.starts_with("* ")  // Middle of a block comment
        || trimmed.starts_with("*/")  // End of block comment
        || trimmed.starts_with(';')   // INI, Assembly, Lisp
        || trimmed.starts_with("REM ") // Batch files
        || trimmed.starts_with("rem ")
    // Batch files (lowercase)
    {
        // But "#!" shebangs are executable
        if trimmed.starts_with("#!") || trimmed.starts_with("#[") {
            return LineContext::Code;
        }
        return LineContext::Comment;
    }

    LineContext::Code
}

// ─── Single-Line Checks ──────────────────────────────────────────────────────

/// Check a single line of text for secrets. Returns all findings on this line.
/// Findings default to `LineContext::Code`. Use `check_line_with_context` for
/// context-aware scanning that adjusts confidence based on comment detection.
pub fn check_line(line: &str, line_number: usize) -> Vec<ContentFinding> {
    let mut findings = Vec::new();

    // Skip very short lines
    if line.len() < 4 {
        return findings;
    }

    // Tier 1: Definitive
    check_pem_header(line, line_number, &mut findings);
    check_aws_access_key(line, line_number, &mut findings);
    check_api_key_prefixes(line, line_number, &mut findings);
    check_google_service_account(line, line_number, &mut findings);
    check_webhook_urls(line, line_number, &mut findings);
    check_azure_patterns(line, line_number, &mut findings);

    // Tier 2: High confidence
    check_jwt_token(line, line_number, &mut findings);
    check_credit_card(line, line_number, &mut findings);
    check_db_connection_string(line, line_number, &mut findings);
    check_wif_key(line, line_number, &mut findings);
    check_eth_hex_key(line, line_number, &mut findings);
    check_uri_credentials(line, line_number, &mut findings);

    // Tier 3: Context-dependent
    check_password_pattern(line, line_number, &mut findings);
    check_ssn(line, line_number, &mut findings);
    check_iban(line, line_number, &mut findings);

    // Tier 4: Sensitive document markings
    check_sensitive_markings(line, line_number, &mut findings);

    findings
}

/// Check a line with context-aware confidence adjustment.
///
/// Detects whether the line is a comment and downgrades confidence for
/// findings in comments. For Executed context (shell history), upgrades
/// context-dependent findings.
pub fn check_line_with_context(
    line: &str,
    line_number: usize,
    override_context: Option<LineContext>,
) -> Vec<ContentFinding> {
    let mut findings = check_line(line, line_number);

    if findings.is_empty() {
        return findings;
    }

    let ctx = override_context.unwrap_or_else(|| detect_line_context(line));

    for finding in &mut findings {
        finding.context = ctx;
        match ctx {
            LineContext::Comment => {
                // Secrets in comments are lower risk — may be documentation/examples
                finding.confidence = finding.confidence.downgrade();
            }
            LineContext::Executed => {
                // Secrets in executed commands are higher risk — no downgrade
            }
            LineContext::Base64Encoded => {
                // Secrets hidden in base64 are deliberate evasion — no downgrade
            }
            LineContext::Code => {}
        }
    }

    findings
}

/// Scan a line for base64-encoded secrets. Extracts base64-looking tokens,
/// decodes them, and scans the decoded content for secrets.
///
/// Returns findings with `LineContext::Base64Encoded` context.
pub fn check_base64_content(line: &str, line_number: usize) -> Vec<ContentFinding> {
    let mut findings = Vec::new();

    // Find base64-looking tokens in the line (space/quote delimited, 20+ chars)
    for token in extract_base64_tokens(line) {
        if let Some(decoded_bytes) = base64_decode(token) {
            // Must decode to valid UTF-8
            if let Ok(decoded) = core::str::from_utf8(&decoded_bytes) {
                // Scan the decoded content
                let mut inner = check_line(decoded, line_number);
                for finding in &mut inner {
                    finding.context = LineContext::Base64Encoded;
                    finding.redacted_preview = format!("[base64] {}", finding.redacted_preview);
                }
                findings.extend(inner);
            }
        }
    }

    findings
}

/// Extract potential base64-encoded tokens from a line.
/// Splits on whitespace, quotes, and common assignment operators, then checks
/// each token for valid base64 format (20+ chars, valid alphabet, padding).
fn extract_base64_tokens(line: &str) -> Vec<&str> {
    let mut tokens = Vec::new();

    // Split on common delimiters: whitespace, quotes, semicolons, commas, backticks
    for token in line.split(|c: char| {
        c.is_whitespace() || c == '"' || c == '\'' || c == ';' || c == ',' || c == '`'
    }) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }

        // If token contains '=' that looks like assignment (key=value), split on it
        // But preserve trailing '=' which is base64 padding
        if let Some(eq_pos) = token.find('=') {
            // Check if the part before '=' is a key (contains non-base64 chars like letters only)
            let before = &token[..eq_pos];
            let after = &token[eq_pos + 1..];

            // If there's content after '=', the '=' is likely an assignment
            if !after.is_empty() && !after.chars().all(|c| c == '=') {
                // Check the value part (after '=')
                if after.len() >= 20 && is_likely_base64(after) {
                    tokens.push(after);
                }
                // Also check the key part (unlikely but possible)
                if before.len() >= 20 && is_likely_base64(before) {
                    tokens.push(before);
                }
                continue;
            }
        }

        // Check the whole token
        if token.len() >= 20 && is_likely_base64(token) {
            tokens.push(token);
        }
    }

    tokens
}

/// Check multiple lines for patterns that span across lines (seed phrases, 2FA codes).
pub fn check_multi_line(lines: &[&str]) -> Vec<ContentFinding> {
    let mut findings = Vec::new();
    check_seed_phrase(lines, &mut findings);
    check_2fa_backup_codes(lines, &mut findings);
    findings
}

/// Check an image filename for suspicious keywords.
pub fn check_image_filename(filename: &str) -> Option<ContentFinding> {
    let lower = filename.to_lowercase();

    // Check extension
    let is_image = IMAGE_EXTENSIONS.iter().any(|ext| lower.ends_with(ext));
    if !is_image {
        return None;
    }

    // Check for secret-related keywords in filename
    for keyword in IMAGE_SECRET_KEYWORDS {
        if contains_word(&lower, keyword) {
            return Some(ContentFinding {
                secret_type: ContentSecretType::SuspiciousImage,
                confidence: Confidence::Heuristic,
                context: LineContext::Code,
                line_number: 0,
                redacted_preview: format!("Image: {filename}"),
                description: "Image filename suggests photographed recovery key or credentials \
                              — may sync to cloud photo libraries",
            });
        }
    }

    None
}

/// Check if `haystack` contains `keyword` as a whole word, not embedded in a
/// hex string or UUID. A word boundary is any non-alphanumeric character or
/// start/end of string.
fn contains_word(haystack: &str, keyword: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(keyword) {
        let abs_pos = start + pos;
        let before_ok = abs_pos == 0 || !haystack.as_bytes()[abs_pos - 1].is_ascii_alphanumeric();
        let after_pos = abs_pos + keyword.len();
        let after_ok =
            after_pos >= haystack.len() || !haystack.as_bytes()[after_pos].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        start = abs_pos + 1;
    }
    false
}

// ─── Tier 1: Definitive ──────────────────────────────────────────────────────

fn check_pem_header(line: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    if !line.contains("-----BEGIN ") {
        return;
    }
    for suffix in PEM_PRIVATE_SUFFIXES {
        if line.contains(suffix) {
            findings.push(ContentFinding {
                secret_type: ContentSecretType::PemPrivateKey,
                confidence: Confidence::Definitive,
                context: LineContext::Code,
                line_number,
                redacted_preview: "-----BEGIN ****-----".to_string(),
                description: "PEM-encoded private key — grants access to encrypted \
                              communications or code signing",
            });
            return;
        }
    }
}

fn check_aws_access_key(line: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    // AWS access keys start with AKIA followed by 16 alphanumeric chars [A-Z2-7]
    let mut start = 0;
    while let Some(pos) = line[start..].find("AKIA") {
        let abs_pos = start + pos;
        let after = &line[abs_pos + 4..];
        if let Some(candidate) = after.get(..16) {
            if candidate
                .chars()
                .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c))
            {
                let preview = format!("AKIA{}****", &candidate[..4]);
                findings.push(ContentFinding {
                    secret_type: ContentSecretType::AwsAccessKey,
                    confidence: Confidence::Definitive,
                    context: LineContext::Code,
                    line_number,
                    redacted_preview: preview,
                    description: "AWS Access Key — grants access to AWS services and billing",
                });
                return;
            }
        }
        start = abs_pos + 4;
    }
}

fn check_api_key_prefixes(line: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    for &(prefix, min_len, service) in API_KEY_PREFIXES {
        if let Some(pos) = line.find(prefix) {
            // Extract the token: run forward until whitespace, quote, or end
            let token_start = pos;
            let rest = &line[token_start..];
            let token_end = rest
                .find(|c: char| {
                    c.is_whitespace()
                        || c == '"'
                        || c == '\''
                        || c == ','
                        || c == ';'
                        || c == ')'
                        || c == '}'
                })
                .unwrap_or(rest.len());
            let token = &rest[..token_end];

            if token.len() >= min_len {
                // For Twilio "AC" prefix, require exactly 32 hex chars after
                if prefix == "AC" && token.len() != 34 {
                    continue;
                }
                if prefix == "AC" && !token[2..].chars().all(|c| c.is_ascii_hexdigit()) {
                    continue;
                }
                // For "pat" prefix (Airtable), be more strict — require alphanumeric after
                if prefix == "pat" && (token.len() < 40 || !token[3..].starts_with('.')) {
                    continue;
                }

                // Entropy check: the suffix after the prefix should have real randomness
                let suffix = &token[prefix.len()..];
                if suffix.len() >= 8 && shannon_entropy(suffix) < ENTROPY_THRESHOLD_API_KEY {
                    continue;
                }

                // D-23: False positive filter
                if is_false_positive(token) || is_false_positive(suffix) {
                    continue;
                }

                let preview_len = prefix.len().min(8);
                let preview = format!("{}****", &token[..preview_len]);
                findings.push(ContentFinding {
                    secret_type: ContentSecretType::ApiKey { service },
                    confidence: Confidence::Definitive,
                    context: LineContext::Code,
                    line_number,
                    redacted_preview: preview,
                    description: match service {
                        "Stripe Secret Key (Live)" => {
                            "Stripe live secret key — can process payments"
                        }
                        "Anthropic API Key" => "Anthropic API key — access to Claude models",
                        "OpenAI API Key" => "OpenAI API key — access to GPT models and billing",
                        "GitHub Personal Access Token" => {
                            "GitHub PAT — repository and account access"
                        }
                        "Slack Bot Token" => "Slack bot token — can read/post messages",
                        "SendGrid API Key" => "SendGrid API key — can send email as your domain",
                        "Google API Key" => "Google API key — access to Google Cloud services",
                        _ => "API key or access token for external service",
                    },
                });
                return;
            }
        }
    }
}

fn check_google_service_account(
    line: &str,
    line_number: usize,
    findings: &mut Vec<ContentFinding>,
) {
    // Google service account JSON has both "type" and "service_account"
    let lower = line.to_lowercase();
    if lower.contains("\"type\"") && lower.contains("service_account") {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::GoogleServiceAccount,
            confidence: Confidence::Definitive,
            context: LineContext::Code,
            line_number,
            redacted_preview: "Google service account JSON".to_string(),
            description: "Google Cloud service account key — full API access to GCP project",
        });
    }
}

// ─── Tier 2: High Confidence ─────────────────────────────────────────────────

fn check_jwt_token(line: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    // JWT: eyJ + base64url + . + base64url + . + base64url
    let mut start = 0;
    while let Some(pos) = line[start..].find("eyJ") {
        let abs_pos = start + pos;
        let rest = &line[abs_pos..];

        // Find the end of the token
        let token_end = rest
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == ';')
            .unwrap_or(rest.len());
        let token = &rest[..token_end];

        // Must have exactly 2 dots (3 parts)
        let dot_count = token.chars().filter(|&c| c == '.').count();
        if dot_count == 2 {
            let parts: Vec<&str> = token.splitn(3, '.').collect();
            if parts.len() == 3
                && parts[0].len() >= 4
                && parts[1].len() >= 4
                && parts[2].len() >= 4
                && is_base64url(parts[0])
                && is_base64url(parts[1])
            {
                findings.push(ContentFinding {
                    secret_type: ContentSecretType::JwtToken,
                    confidence: Confidence::High,
                    context: LineContext::Code,
                    line_number,
                    redacted_preview: format!("eyJ****...({} chars)", token.len()),
                    description: "JWT token — may contain session credentials or API access",
                });
                return;
            }
        }
        start = abs_pos + 3;
    }
}

fn check_credit_card(line: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    // Extract sequences of 13-19 digits (ignoring spaces and dashes)
    let digits: String = line
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == ' ' || *c == '-')
        .collect();

    // Try to find card number patterns
    let pure_digits: String = digits.chars().filter(|c| c.is_ascii_digit()).collect();
    if pure_digits.len() < 13 || pure_digits.len() > 19 {
        return;
    }

    // Check BIN prefix (first 1-2 digits)
    let card_type = match pure_digits.as_bytes()[0] {
        b'4' if pure_digits.len() == 16 => "Visa",
        b'5' if pure_digits.len() == 16 && (b'1'..=b'5').contains(&pure_digits.as_bytes()[1]) => {
            "Mastercard"
        }
        b'3' if pure_digits.len() == 15
            && (pure_digits.as_bytes()[1] == b'4' || pure_digits.as_bytes()[1] == b'7') =>
        {
            "Amex"
        }
        b'6' if pure_digits.len() == 16 && pure_digits.starts_with("6011") => "Discover",
        _ => return,
    };

    if luhn_check(&pure_digits) {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::CreditCard,
            confidence: Confidence::High,
            context: LineContext::Code,
            line_number,
            redacted_preview: format!(
                "{}****{}",
                &pure_digits[..4],
                &pure_digits[pure_digits.len() - 4..]
            ),
            description: match card_type {
                "Visa" => "Credit card number (Visa, Luhn valid)",
                "Mastercard" => "Credit card number (Mastercard, Luhn valid)",
                "Amex" => "Credit card number (American Express, Luhn valid)",
                "Discover" => "Credit card number (Discover, Luhn valid)",
                _ => "Credit card number (Luhn valid)",
            },
        });
    }
}

fn check_db_connection_string(line: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    let lower = line.to_lowercase();
    for prefix in DB_PREFIXES {
        if let Some(pos) = lower.find(prefix) {
            let rest = &line[pos..];
            // Must contain @ (embedded credentials)
            if rest.contains('@') {
                let scheme = prefix.trim_end_matches("://");
                findings.push(ContentFinding {
                    secret_type: ContentSecretType::DbConnectionString,
                    confidence: Confidence::High,
                    context: LineContext::Code,
                    line_number,
                    redacted_preview: format!("{scheme}://****@****"),
                    description: "Database connection string with embedded credentials",
                });
                return;
            }
        }
    }
}

fn check_wif_key(line: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    // WIF private keys: start with '5' (len 51) or 'K'/'L' (len 52)
    for word in line.split_whitespace() {
        let trimmed = word.trim_matches(|c: char| !c.is_alphanumeric());
        let valid = match trimmed.as_bytes().first() {
            Some(b'5') if trimmed.len() == 51 => true,
            Some(b'K') | Some(b'L') if trimmed.len() == 52 => true,
            _ => false,
        };
        if valid && is_base58(trimmed) {
            findings.push(ContentFinding {
                secret_type: ContentSecretType::WifPrivateKey,
                confidence: Confidence::High,
                context: LineContext::Code,
                line_number,
                redacted_preview: format!("{}****", &trimmed[..4]),
                description: "Bitcoin WIF private key — grants full control of crypto wallet",
            });
            return;
        }
    }
}

fn check_eth_hex_key(line: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    // 0x + 64 hex chars. Use .get() to avoid panicking on multi-byte UTF-8.
    if let Some(pos) = line.find("0x") {
        let after = &line[pos + 2..];
        if let Some(candidate) = after.get(..64) {
            if candidate.chars().all(|c| c.is_ascii_hexdigit()) {
                // Reject EVM bytecode: if hex continues well past 64 chars, it's
                // contract bytecode (often thousands of hex chars), not a private key.
                let remaining = &after[64..];
                let extra_hex = remaining
                    .chars()
                    .take_while(|c| c.is_ascii_hexdigit())
                    .count();
                if extra_hex > 16 {
                    return; // bytecode, not a key
                }
                // Entropy check: reject repeated patterns like "aabbccdd" x 8
                if shannon_entropy(candidate) < ENTROPY_THRESHOLD_HEX_KEY {
                    return;
                }
                // D-23: False positive filter
                if is_false_positive(candidate) {
                    return;
                }
                let preview_end = &candidate[..8]; // safe: all ASCII hex
                findings.push(ContentFinding {
                    secret_type: ContentSecretType::EthHexKey,
                    confidence: Confidence::High,
                    context: LineContext::Code,
                    line_number,
                    redacted_preview: format!("0x{preview_end}****"),
                    description:
                        "Ethereum/EVM hex private key — grants full control of crypto wallet",
                });
                return;
            }
        }
    }

    // 64 hex chars near a keyword
    let lower = line.to_lowercase();
    let has_keyword = lower.contains("private")
        || lower.contains("key")
        || lower.contains("wallet")
        || lower.contains("secret")
        || lower.contains("hex");
    if has_keyword {
        for word in line.split_whitespace() {
            let trimmed = word.trim_matches(|c: char| !c.is_ascii_hexdigit());
            if trimmed.len() == 64
                && trimmed.chars().all(|c| c.is_ascii_hexdigit())
                && shannon_entropy(trimmed) >= ENTROPY_THRESHOLD_HEX_KEY
            {
                findings.push(ContentFinding {
                    secret_type: ContentSecretType::EthHexKey,
                    confidence: Confidence::High,
                    context: LineContext::Code,
                    line_number,
                    redacted_preview: format!("{}****", safe_prefix(trimmed, 8)),
                    description: "Possible Ethereum/EVM hex private key near crypto keyword",
                });
                return;
            }
        }
    }
}

// ─── Tier 3: Context-Dependent ───────────────────────────────────────────────

fn check_password_pattern(line: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    let lower = line.to_lowercase();
    for keyword in PASSWORD_KEYWORDS {
        if let Some(kw_pos) = lower.find(keyword) {
            // Look for assignment after the keyword
            let after_kw = &line[kw_pos + keyword.len()..];
            let trimmed = after_kw.trim_start();

            for op in ASSIGNMENT_OPS {
                if trimmed.starts_with(op) {
                    let value_part = trimmed[op.len()..].trim();
                    // Strip surrounding quotes
                    let value = value_part
                        .trim_start_matches('"')
                        .trim_start_matches('\'')
                        .trim_end_matches('"')
                        .trim_end_matches('\'')
                        .trim();

                    if value.is_empty() || value.len() < 4 {
                        break;
                    }

                    // Check it's not a placeholder
                    let is_placeholder = PLACEHOLDER_VALUES
                        .iter()
                        .any(|p| value.starts_with(p) || value == *p);
                    if is_placeholder {
                        break;
                    }

                    // D-23: False positive filter
                    if is_false_positive(value) {
                        break;
                    }

                    // Entropy check: reject low-entropy values (repeated chars, simple sequences)
                    let entropy = shannon_entropy(value);
                    if entropy < ENTROPY_THRESHOLD_PASSWORD {
                        break;
                    }

                    let redacted_kw = &line[kw_pos..kw_pos + keyword.len()];
                    findings.push(ContentFinding {
                        secret_type: ContentSecretType::PasswordPattern,
                        confidence: Confidence::ContextDependent,
                        context: LineContext::Code,
                        line_number,
                        redacted_preview: format!("{redacted_kw} {op} ****"),
                        description: "Password or secret value assigned in plain text",
                    });
                    return;
                }
            }
        }
    }
}

fn check_ssn(line: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    // SSN: NNN-NN-NNNN with SSA validation
    let bytes = line.as_bytes();
    if bytes.len() < 11 {
        return;
    }
    for i in 0..=bytes.len().saturating_sub(11) {
        // Check pattern: D D D - D D - D D D D
        if i + 10 < bytes.len()
            && bytes[i].is_ascii_digit()
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3] == b'-'
            && bytes[i + 4].is_ascii_digit()
            && bytes[i + 5].is_ascii_digit()
            && bytes[i + 6] == b'-'
            && bytes[i + 7].is_ascii_digit()
            && bytes[i + 8].is_ascii_digit()
            && bytes[i + 9].is_ascii_digit()
            && bytes[i + 10].is_ascii_digit()
        {
            // Make sure it's not embedded in a longer number
            if i > 0 && (bytes[i - 1].is_ascii_digit() || bytes[i - 1] == b'-') {
                continue;
            }
            if i + 11 < bytes.len() && (bytes[i + 11].is_ascii_digit() || bytes[i + 11] == b'-') {
                continue;
            }

            let area: u16 = (bytes[i] - b'0') as u16 * 100
                + (bytes[i + 1] - b'0') as u16 * 10
                + (bytes[i + 2] - b'0') as u16;
            let group: u8 = (bytes[i + 4] - b'0') * 10 + (bytes[i + 5] - b'0');
            let serial: u16 = (bytes[i + 7] - b'0') as u16 * 1000
                + (bytes[i + 8] - b'0') as u16 * 100
                + (bytes[i + 9] - b'0') as u16 * 10
                + (bytes[i + 10] - b'0') as u16;

            // SSA validation: area not 000, 666, or 900-999; group not 00; serial not 0000
            if area == 0 || area == 666 || area >= 900 {
                continue;
            }
            if group == 0 || serial == 0 {
                continue;
            }

            findings.push(ContentFinding {
                secret_type: ContentSecretType::SsnPattern,
                confidence: Confidence::ContextDependent,
                context: LineContext::Code,
                line_number,
                redacted_preview: format!("***-**-{serial:04}"),
                description: "Possible Social Security Number (SSA-valid format)",
            });
            return;
        }
    }
}

fn check_iban(line: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    // IBAN: 2 uppercase letters + 2 digits + 4-30 alphanumeric
    for word in line.split_whitespace() {
        let trimmed = word.trim_matches(|c: char| !c.is_alphanumeric());
        if trimmed.len() < 8 || trimmed.len() > 34 {
            continue;
        }
        let bytes = trimmed.as_bytes();
        if bytes[0].is_ascii_uppercase()
            && bytes[1].is_ascii_uppercase()
            && bytes[2].is_ascii_digit()
            && bytes[3].is_ascii_digit()
            && bytes[4..].iter().all(|b| b.is_ascii_alphanumeric())
        {
            // Quick country code validation (common IBAN countries)
            let country = &trimmed[..2];
            let valid_countries = [
                "AL", "AD", "AT", "AZ", "BH", "BY", "BE", "BA", "BR", "BG", "CR", "HR", "CY", "CZ",
                "DK", "DO", "EG", "EE", "FI", "FR", "GE", "DE", "GI", "GR", "GT", "HU", "IS", "IQ",
                "IE", "IL", "IT", "JO", "KZ", "KW", "LV", "LB", "LI", "LT", "LU", "MT", "MR", "MU",
                "MD", "MC", "ME", "NL", "MK", "NO", "PK", "PS", "PL", "PT", "QA", "RO", "LC", "SM",
                "SA", "RS", "SC", "SK", "SI", "ES", "SE", "CH", "TL", "TN", "TR", "UA", "AE", "GB",
            ];
            if valid_countries.contains(&country) {
                findings.push(ContentFinding {
                    secret_type: ContentSecretType::IbanPattern,
                    confidence: Confidence::ContextDependent,
                    context: LineContext::Code,
                    line_number,
                    redacted_preview: format!(
                        "{}****{}",
                        &trimmed[..4],
                        &trimmed[trimmed.len() - 4..]
                    ),
                    description: "International Bank Account Number (IBAN)",
                });
                return;
            }
        }
    }
}

// ─── Tier 4: Sensitive Document Markings ──────────────────────────────────────

/// Check if a keyword on this line appears inside string literal quotes.
/// Catches pattern definitions like `("NOFORN", "NOFORN")` in source code,
/// preventing false positives when scanning gorse's own source or similar
/// rule-definition files.
fn keyword_in_string_literal(line: &str, keyword: &str) -> bool {
    // Case-insensitive search for the keyword
    let upper_line = line.to_uppercase();
    let upper_keyword = keyword.to_uppercase();
    if let Some(pos) = upper_line.find(&upper_keyword) {
        let before = &line[..pos];
        let after_start = pos + keyword.len();
        let after = if after_start <= line.len() {
            &line[after_start..]
        } else {
            ""
        };
        // Check if there's a quote character before AND after the keyword
        let has_open_quote = before.contains('"') || before.contains('\'');
        let has_close_quote = after.contains('"') || after.contains('\'');
        has_open_quote && has_close_quote
    } else {
        false
    }
}

fn check_sensitive_markings(line: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    let trimmed = line.trim();
    let upper = trimmed.to_uppercase();

    // Skip lines where markings appear inside string literals (code pattern definitions).
    // This prevents false positives when scanning source code that defines detection rules.
    // We check the whole line once — if ANY marking keyword is inside quotes, skip entirely.
    // Real classified documents don't wrap markings in programming quotes.
    let likely_code_definition = trimmed.contains('"')
        && (keyword_in_string_literal(line, "TOP SECRET")
            || keyword_in_string_literal(line, "SECRET")
            || keyword_in_string_literal(line, "CONFIDENTIAL")
            || keyword_in_string_literal(line, "NOFORN")
            || keyword_in_string_literal(line, "ORCON")
            || keyword_in_string_literal(line, "REL TO")
            || keyword_in_string_literal(line, "PROPRIETARY")
            || keyword_in_string_literal(line, "TRADE SECRET")
            || keyword_in_string_literal(line, "ITAR")
            || keyword_in_string_literal(line, "EXPORT CONTROLLED"));
    if likely_code_definition {
        return;
    }

    // 1. Classification banners — standalone lines
    //    "TOP SECRET", "TOP SECRET//SCI", "TOP SECRET//SCI//NOFORN", etc.
    if upper.starts_with("TOP SECRET") {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking {
                marking: "TOP SECRET",
            },
            confidence: Confidence::Definitive,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[MARKING] classification banner (TOP SECRET level)".to_string(),
            description: "Government classification banner — TOP SECRET",
        });
        return;
    }

    // "SECRET//" with compartment markers (not bare "SECRET")
    if upper.starts_with("SECRET//") {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking { marking: "SECRET" },
            confidence: Confidence::Definitive,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[MARKING] classification banner (SECRET level)".to_string(),
            description: "Government classification banner — SECRET with controls",
        });
        return;
    }

    // Bare "SECRET" or "CONFIDENTIAL" — only if line is exactly that word
    if trimmed == "SECRET" || trimmed == "CONFIDENTIAL" {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking {
                marking: if trimmed == "SECRET" {
                    "SECRET"
                } else {
                    "CONFIDENTIAL"
                },
            },
            confidence: Confidence::High,
            context: LineContext::Code,
            line_number,
            redacted_preview: if trimmed == "SECRET" {
                "[MARKING] classification banner (SECRET level)".to_string()
            } else {
                "[MARKING] classification banner (CONFIDENTIAL level)".to_string()
            },
            description: "Government classification banner — standalone marking",
        });
        return;
    }

    // "CONFIDENTIAL" with decorator: "CONFIDENTIAL//", "CONFIDENTIAL –", "CONFIDENTIAL -"
    if upper.starts_with("CONFIDENTIAL//")
        || upper.starts_with("CONFIDENTIAL \u{2013}")
        || upper.starts_with("CONFIDENTIAL -")
    {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking {
                marking: "CONFIDENTIAL",
            },
            confidence: Confidence::High,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[MARKING] classification banner (CONFIDENTIAL level)".to_string(),
            description: "Government classification banner — CONFIDENTIAL with controls",
        });
        return;
    }

    // CUI banners
    if trimmed == "CUI" || upper.starts_with("CUI//") {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking { marking: "CUI" },
            confidence: Confidence::High,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[MARKING] CUI designation".to_string(),
            description: "Controlled Unclassified Information (CUI) banner",
        });
        return;
    }

    // 2. Portion markings — at start of line
    if trimmed.starts_with("(TS)") || trimmed.starts_with("(TS//") {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking { marking: "(TS)" },
            confidence: Confidence::Definitive,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[PORTION] portion mark (TS)".to_string(),
            description: "TOP SECRET portion marking",
        });
        return;
    }
    if trimmed.starts_with("(S)") || trimmed.starts_with("(S//") {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking { marking: "(S)" },
            confidence: Confidence::Definitive,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[PORTION] portion mark (S)".to_string(),
            description: "SECRET portion marking",
        });
        return;
    }
    if trimmed.starts_with("(C)") && trimmed.len() > 3 {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking { marking: "(C)" },
            confidence: Confidence::High,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[PORTION] portion mark (C)".to_string(),
            description: "CONFIDENTIAL portion marking",
        });
        return;
    }
    if trimmed.starts_with("(CUI)") {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking { marking: "(CUI)" },
            confidence: Confidence::High,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[PORTION] portion mark (CUI)".to_string(),
            description: "CUI portion marking",
        });
        return;
    }

    // 3. Dissemination controls — anywhere in line, case-insensitive
    for &(keyword, marking) in &[
        ("NOFORN", "NOFORN"),
        ("ORCON", "ORCON"),
        ("REL TO", "REL TO"),
        ("EXPORT CONTROLLED", "EXPORT CONTROLLED"),
    ] {
        if upper.contains(keyword) {
            findings.push(ContentFinding {
                secret_type: ContentSecretType::SensitiveMarking { marking },
                confidence: Confidence::Definitive,
                context: LineContext::Code,
                line_number,
                redacted_preview: format!("[MARKING] dissemination control {}", marking),
                description: "Dissemination control marking",
            });
            return;
        }
    }

    // 4. Export control regulatory citations
    if upper.contains("22 CFR 12") || upper.contains("22 CFR 13") {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking { marking: "ITAR" },
            confidence: Confidence::High,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[MARKING] ITAR export-control notice".to_string(),
            description: "ITAR export control regulatory citation (22 CFR)",
        });
        return;
    }
    if upper.contains("15 CFR 73") || upper.contains("15 CFR 74") {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::SensitiveMarking { marking: "EAR" },
            confidence: Confidence::High,
            context: LineContext::Code,
            line_number,
            redacted_preview: "[MARKING] EAR export-control notice".to_string(),
            description: "EAR export control regulatory citation (15 CFR)",
        });
        return;
    }

    // 5. Corporate sensitivity — case-insensitive multi-word phrases
    for &(phrase, marking) in &[
        ("PROPRIETARY INFORMATION", "PROPRIETARY"),
        ("TRADE SECRET", "TRADE SECRET"),
        ("INTERNAL USE ONLY", "INTERNAL USE ONLY"),
        ("NOT FOR DISTRIBUTION", "NOT FOR DISTRIBUTION"),
        ("NDA PROTECTED", "NDA PROTECTED"),
    ] {
        if upper.contains(phrase) {
            findings.push(ContentFinding {
                secret_type: ContentSecretType::SensitiveMarking { marking },
                confidence: Confidence::ContextDependent,
                context: LineContext::Code,
                line_number,
                redacted_preview: format!("[MARKING] corporate sensitivity label {}", marking),
                description: "Corporate sensitivity marking",
            });
            return;
        }
    }
}

// ─── Multi-Line Checks ───────────────────────────────────────────────────────

fn check_seed_phrase(lines: &[&str], findings: &mut Vec<ContentFinding>) {
    // Fixed: require purely alphabetic words with only spaces between them.
    // Words with attached punctuation (commas, periods, etc.) break the run,
    // preventing false positives on normal English prose where ~40% of common
    // words happen to match BIP-39 4-char prefixes.
    let mut all_words: Vec<(usize, &str)> = Vec::new(); // (line_number, word)

    for (line_idx, line) in lines.iter().enumerate() {
        for word in line.split_whitespace() {
            // Punctuation gate: word must be purely alphabetic.
            // Real seed phrases are clean space-separated words.
            if word.chars().all(|c| c.is_alphabetic()) && !word.is_empty() {
                all_words.push((line_idx + 1, word));
            } else {
                // Non-alpha token acts as a run-breaker sentinel
                all_words.push((line_idx + 1, ""));
            }
        }
    }

    // Check for runs of 12+ consecutive BIP-39 words
    let mut run_start = 0;
    let mut run_len = 0;

    for (i, (_line_num, word)) in all_words.iter().enumerate() {
        if !word.is_empty() && is_bip39_word(word) {
            if run_len == 0 {
                run_start = i;
            }
            run_len += 1;
        } else {
            if run_len >= 12 {
                emit_seed_finding(&all_words, run_start, run_len, findings);
            }
            run_len = 0;
        }
    }

    // Check trailing run
    if run_len >= 12 {
        emit_seed_finding(&all_words, run_start, run_len, findings);
    }
}

fn emit_seed_finding(
    all_words: &[(usize, &str)],
    run_start: usize,
    run_len: usize,
    findings: &mut Vec<ContentFinding>,
) {
    let start_line = all_words[run_start].0;
    let end_line = all_words[run_start + run_len - 1].0;
    let word_count = run_len;
    findings.push(ContentFinding {
        secret_type: ContentSecretType::SeedPhrase,
        confidence: Confidence::High,
        context: LineContext::Code,
        line_number: start_line,
        redacted_preview: format!(
            "BIP-39 seed phrase ({word_count} words, lines {start_line}-{end_line})"
        ),
        description: "BIP-39 mnemonic seed phrase — crypto wallet recovery key, \
                      grants full control of all funds",
    });
}

fn check_2fa_backup_codes(lines: &[&str], findings: &mut Vec<ContentFinding>) {
    // 5+ consecutive lines of 6-8 char alphanumeric codes
    let mut run_start = 0;
    let mut run_len = 0;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        // Allow codes with optional dashes (e.g., "1234-5678")
        let clean: String = trimmed
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        let is_code = (6..=12).contains(&clean.len())
            && clean.chars().all(|c| c.is_ascii_alphanumeric())
            && !clean.chars().all(|c| c.is_alphabetic()); // Must have at least some digits

        if is_code {
            if run_len == 0 {
                run_start = i;
            }
            run_len += 1;
        } else {
            if run_len >= 5 {
                findings.push(ContentFinding {
                    secret_type: ContentSecretType::TwoFactorBackupCodes,
                    confidence: Confidence::ContextDependent,
                    context: LineContext::Code,
                    line_number: run_start + 1,
                    redacted_preview: format!(
                        "2FA backup codes ({run_len} codes, lines {}-{})",
                        run_start + 1,
                        run_start + run_len
                    ),
                    description:
                        "Two-factor authentication backup codes — can bypass 2FA protection",
                });
            }
            run_len = 0;
        }
    }

    // Check trailing run
    if run_len >= 5 {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::TwoFactorBackupCodes,
            confidence: Confidence::ContextDependent,
            context: LineContext::Code,
            line_number: run_start + 1,
            redacted_preview: format!(
                "2FA backup codes ({run_len} codes, lines {}-{})",
                run_start + 1,
                run_start + run_len
            ),
            description: "Two-factor authentication backup codes — can bypass 2FA protection",
        });
    }
}

// ─── Helper Functions ────────────────────────────────────────────────────────

/// Shannon entropy of a byte string (bits per byte).
///
/// Real secrets have high entropy (3.5+ for hex, 4.0+ for alphanumeric).
/// Placeholders, repeated patterns, and sequential strings have low entropy.
/// Used to reduce false positives on password patterns and API key validation.
///
/// Returns entropy in bits per byte (0.0 to 8.0). Pure Rust, no deps.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    // Count byte frequencies
    let mut freq = [0u32; 256];
    let len = s.len() as f64;
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }

    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * log2_approx(p);
        }
    }

    entropy
}

/// Fast log2 approximation using integer math. Good enough for entropy scoring.
/// Uses the identity: log2(x) = ln(x) / ln(2), with a polynomial approximation.
fn log2_approx(x: f64) -> f64 {
    // For x in (0, 1], log2 is negative. We use bit manipulation for speed.
    // This is accurate to ~0.01 bits which is fine for entropy thresholds.
    let bits = x.to_bits();
    let exponent = ((bits >> 52) & 0x7FF) as i64 - 1023;
    let mantissa = f64::from_bits((bits & 0x000FFFFFFFFFFFFF) | 0x3FF0000000000000);
    // Polynomial approximation of log2(mantissa) for mantissa in [1, 2)
    let m = mantissa - 1.0;
    let log2_mantissa = m * (1.4426950408889634 - m * 0.7213475204444817);
    exponent as f64 + log2_mantissa
}

/// Entropy thresholds for different secret types.
/// These were calibrated against known real keys vs. common false positives.
const ENTROPY_THRESHOLD_PASSWORD: f64 = 2.5; // "password123" = ~2.8, "aaaa" = 0.0
const ENTROPY_THRESHOLD_API_KEY: f64 = 3.0; // Real API keys are 3.5+
const ENTROPY_THRESHOLD_HEX_KEY: f64 = 3.0; // Real hex keys are 3.5+

// ─── D-23: False Positive Wordlist ──────────────────────────────────────────
//
// Programming keywords, function names, hex color codes, and common constants
// that structurally resemble secrets but are not. Used to filter out false
// positives from API key prefix matching, hex key detection, and password
// pattern matching.

/// Known false positive tokens that match secret patterns but are not secrets.
/// These are checked against the extracted token value (case-insensitive).
const FALSE_POSITIVE_WORDS: &[&str] = &[
    // Programming / crypto function names
    "sha256",
    "sha384",
    "sha512",
    "sha1",
    "md5",
    "hmac",
    "encrypt",
    "decrypt",
    "cipher",
    "hash",
    "digest",
    "base64",
    "base32",
    "hex2bin",
    "bin2hex",
    "buffer",
    "stream",
    "socket",
    "handle",
    "callback",
    "promise",
    "async",
    "await",
    "function",
    "method",
    "class",
    "struct",
    "interface",
    "abstract",
    "extends",
    "implements",
    // Common variable/constant names
    "undefined",
    "null",
    "none",
    "true",
    "false",
    "default",
    "config",
    "options",
    "settings",
    "localhost",
    "hostname",
    "username",
    "password",
    "timestamp",
    "datetime",
    "timeout",
    "interval",
    "encoding",
    "charset",
    "utf8",
    "ascii",
    "content_type",
    "content-type",
    "application/json",
    "authorization",
    "bearer",
    "basic",
    // Color codes and common hex constants
    "ffffff",
    "000000",
    "ff0000",
    "00ff00",
    "0000ff",
    "ffff00",
    "ff00ff",
    "00ffff",
    "c0c0c0",
    "808080",
    "deadbeef",
    "cafebabe",
    "feedface",
    "baadf00d",
    "abcdef",
    "0123456789abcdef",
    // Common test/fixture strings
    "lorem ipsum",
    "hello world",
    "foo bar",
    "the quick brown fox",
];

/// Check if a token is a known false positive.
fn is_false_positive(token: &str) -> bool {
    let lower = token.to_lowercase();
    // Check exact matches and prefix matches
    for &fp in FALSE_POSITIVE_WORDS {
        if lower == fp || lower.starts_with(fp) && lower.len() < fp.len() + 8 {
            return true;
        }
    }
    // 6-char hex strings that look like CSS colors (#aabbcc)
    if token.len() == 6 && token.chars().all(|c| c.is_ascii_hexdigit()) {
        // Low entropy hex = likely a color code, not a secret
        if shannon_entropy(token) < 2.0 {
            return true;
        }
    }
    false
}

// ─── D-24: URI-Embedded Credential Detection ────────────────────────────────

/// Detect credentials embedded in URIs: https://user:password@host
fn check_uri_credentials(line: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    // Look for ://user:pass@host patterns in any scheme
    let schemes = [
        "http://", "https://", "ftp://", "ftps://", "ssh://", "svn://", "git://", "ldap://",
        "ldaps://", "smb://",
    ];
    let lower = line.to_lowercase();
    for scheme in &schemes {
        if let Some(pos) = lower.find(scheme) {
            let after_scheme = &line[pos + scheme.len()..];
            // Look for user:pass@host pattern
            if let Some(at_pos) = after_scheme.find('@') {
                let userinfo = &after_scheme[..at_pos];
                if let Some(colon_pos) = userinfo.find(':') {
                    let password = &userinfo[colon_pos + 1..];
                    // Must have a non-empty password that isn't a placeholder
                    if password.len() >= 4
                        && !PLACEHOLDER_VALUES.iter().any(|p| password.starts_with(p))
                    {
                        findings.push(ContentFinding {
                            secret_type: ContentSecretType::DbConnectionString,
                            confidence: Confidence::High,
                            context: LineContext::Code,
                            line_number,
                            redacted_preview: format!("{scheme}****:****@****"),
                            description: "URI with embedded credentials (user:password@host)",
                        });
                        return;
                    }
                }
            }
        }
    }
}

// ─── D-25: Webhook URL Detection ────────────────────────────────────────────

/// Webhook URL patterns — these URLs are secrets themselves because they allow
/// posting messages or triggering actions without additional authentication.
const WEBHOOK_PATTERNS: &[(&str, &str)] = &[
    ("hooks.slack.com/services/", "Slack Incoming Webhook"),
    ("hooks.slack.com/workflows/", "Slack Workflow Webhook"),
    ("discord.com/api/webhooks/", "Discord Webhook"),
    ("discordapp.com/api/webhooks/", "Discord Webhook"),
    ("outlook.office.com/webhook/", "Microsoft Teams Webhook"),
    (".webhook.office.com/", "Microsoft Teams Webhook"),
    ("hooks.zapier.com/hooks/", "Zapier Webhook"),
    ("maker.ifttt.com/trigger/", "IFTTT Webhook"),
    ("api.telegram.org/bot", "Telegram Bot Token"),
];

fn check_webhook_urls(line: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    let lower = line.to_lowercase();
    for &(pattern, service) in WEBHOOK_PATTERNS {
        if lower.contains(pattern) {
            // Extract a redacted preview
            let preview = if let Some(pos) = lower.find(pattern) {
                let end = (pos + pattern.len() + 8).min(line.len());
                format!("{}****", &line[pos..end.min(pos + 20)])
            } else {
                format!("{pattern}****")
            };
            findings.push(ContentFinding {
                secret_type: ContentSecretType::ApiKey { service },
                confidence: Confidence::Definitive,
                context: LineContext::Code,
                line_number,
                redacted_preview: preview,
                description: "Webhook URL — allows posting messages or triggering actions without authentication",
            });
            return;
        }
    }
}

// ─── D-26: Azure Cloud Patterns ─────────────────────────────────────────────

fn check_azure_patterns(line: &str, line_number: usize, findings: &mut Vec<ContentFinding>) {
    // Azure Storage connection strings
    if line.contains("DefaultEndpointsProtocol=") && line.contains("AccountKey=") {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::ApiKey {
                service: "Azure Storage",
            },
            confidence: Confidence::Definitive,
            context: LineContext::Code,
            line_number,
            redacted_preview: "DefaultEndpointsProtocol=...AccountKey=****".to_string(),
            description: "Azure Storage connection string with account key",
        });
        return;
    }

    // Azure SAS tokens
    if (line.contains("sig=") || line.contains("&sig="))
        && (line.contains("sv=") || line.contains("&sv="))
        && (line.contains("se=") || line.contains("&se="))
    {
        findings.push(ContentFinding {
            secret_type: ContentSecretType::ApiKey {
                service: "Azure SAS Token",
            },
            confidence: Confidence::High,
            context: LineContext::Code,
            line_number,
            redacted_preview: "?sv=...&sig=****".to_string(),
            description: "Azure Shared Access Signature (SAS) token",
        });
        return;
    }

    // Azure Function keys
    let lower = line.to_lowercase();
    if lower.contains("x-functions-key")
        || lower.contains("code=") && lower.contains(".azurewebsites.net")
    {
        if let Some(_) = line.find(|c: char| c == '=' || c == ':') {
            let after = line
                .split(|c: char| c == '=' || c == ':')
                .nth(1)
                .unwrap_or("");
            let value = after.trim().trim_matches('"').trim_matches('\'');
            if value.len() >= 20 && shannon_entropy(value) >= ENTROPY_THRESHOLD_API_KEY {
                findings.push(ContentFinding {
                    secret_type: ContentSecretType::ApiKey {
                        service: "Azure Function Key",
                    },
                    confidence: Confidence::High,
                    context: LineContext::Code,
                    line_number,
                    redacted_preview: "x-functions-key: ****".to_string(),
                    description: "Azure Function host or master key",
                });
            }
        }
    }
}

/// Luhn checksum validation for credit card numbers.
fn luhn_check(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;

    for ch in digits.chars().rev() {
        let d = match ch.to_digit(10) {
            Some(d) => d,
            None => return false,
        };
        let val = if double {
            let doubled = d * 2;
            if doubled > 9 {
                doubled - 9
            } else {
                doubled
            }
        } else {
            d
        };
        sum += val;
        double = !double;
    }

    sum % 10 == 0
}

/// Check if a string is valid base58 (Bitcoin alphabet).
fn is_base58(s: &str) -> bool {
    s.bytes().all(|b| BASE58_CHARS.contains(&b))
}

/// Check if a string is valid base64url encoding.
fn is_base64url(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
}

/// Check if a string looks like standard base64 (A-Za-z0-9+/= with optional whitespace).
fn is_likely_base64(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.len() < 20 {
        return false;
    }
    // Must have valid length (multiple of 4 after stripping whitespace)
    let clean: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 4 != 0 {
        return false;
    }
    // All chars must be base64 alphabet
    clean
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// Pure Rust base64 decoder. No external dependencies.
/// Returns None if input is not valid base64.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();

    if clean.is_empty() || clean.len() % 4 != 0 {
        return None;
    }

    let mut output = Vec::with_capacity(clean.len() * 3 / 4);

    for chunk in clean.chunks(4) {
        let mut buf = [0u8; 4];
        let mut pad = 0u8;

        for (i, &byte) in chunk.iter().enumerate() {
            buf[i] = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => {
                    pad += 1;
                    0
                }
                _ => return None,
            };
        }

        let combined =
            (buf[0] as u32) << 18 | (buf[1] as u32) << 12 | (buf[2] as u32) << 6 | buf[3] as u32;

        output.push((combined >> 16) as u8);
        if pad < 2 {
            output.push((combined >> 8) as u8);
        }
        if pad < 1 {
            output.push(combined as u8);
        }
    }

    Some(output)
}

// ─── D-28: UTF-16 / Unicode Escape Decoding ─────────────────────────────────
//
// Agents can obfuscate secrets using Unicode escape sequences:
//   \u0041 (JS/JSON), \x41 (hex byte), %41 (URL encoding)
// This decoder handles all three forms, then rescans the decoded string.

/// Scan a line for Unicode-obfuscated secrets. Extracts escape sequences,
/// decodes them, and scans the decoded content for secrets.
///
/// Returns findings with `[unicode]` prefix in the redacted preview.
pub fn check_unicode_obfuscated(line: &str, line_number: usize) -> Vec<ContentFinding> {
    // Quick check: does this line contain any escape sequences worth decoding?
    if !has_unicode_escapes(line) {
        return Vec::new();
    }

    let decoded = decode_unicode_escapes(line);

    // Only rescan if decoding actually changed something
    if decoded == line {
        return Vec::new();
    }

    // Must be valid printable text after decoding
    if decoded
        .chars()
        .any(|c| c.is_control() && c != '\t' && c != '\n')
    {
        return Vec::new();
    }

    let mut findings = check_line(&decoded, line_number);
    for finding in &mut findings {
        finding.context = LineContext::Base64Encoded; // reuse "encoded" context
        finding.redacted_preview = format!("[unicode] {}", finding.redacted_preview);
    }
    findings
}

/// Quick check whether a line contains Unicode escape sequences worth decoding.
fn has_unicode_escapes(line: &str) -> bool {
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        if bytes[i] == b'\\' && i + 1 < len {
            match bytes[i + 1] {
                b'u' if i + 5 < len => return true, // \uXXXX
                b'x' if i + 3 < len => return true, // \xHH
                _ => {}
            }
        } else if bytes[i] == b'%' && i + 2 < len {
            // %XX URL encoding — need at least 2 hex digits after
            if bytes[i + 1].is_ascii_hexdigit() && bytes[i + 2].is_ascii_hexdigit() {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Decode Unicode escape sequences in a string.
///
/// Handles:
///   - `\uXXXX` — JavaScript/JSON Unicode escapes
///   - `\xHH`   — Hex byte escapes
///   - `%XX`    — URL percent-encoding
///
/// Literal characters pass through unchanged.
fn decode_unicode_escapes(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut result = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        if bytes[i] == b'\\' && i + 1 < len {
            match bytes[i + 1] {
                b'u' if i + 5 < len => {
                    // \uXXXX
                    let hex = &input[i + 2..i + 6];
                    if hex.len() == 4 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                        if let Ok(cp) = u32::from_str_radix(hex, 16) {
                            if let Some(ch) = char::from_u32(cp) {
                                result.push(ch);
                                i += 6;
                                continue;
                            }
                        }
                    }
                    result.push('\\');
                    i += 1;
                }
                b'x' if i + 3 < len => {
                    // \xHH
                    let hex = &input[i + 2..i + 4];
                    if hex.len() == 2 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                        if let Ok(byte_val) = u8::from_str_radix(hex, 16) {
                            result.push(byte_val as char);
                            i += 4;
                            continue;
                        }
                    }
                    result.push('\\');
                    i += 1;
                }
                _ => {
                    result.push('\\');
                    i += 1;
                }
            }
        } else if bytes[i] == b'%'
            && i + 2 < len
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            // %XX URL encoding
            let hex = &input[i + 1..i + 3];
            if let Ok(byte_val) = u8::from_str_radix(hex, 16) {
                result.push(byte_val as char);
                i += 3;
                continue;
            }
            result.push('%');
            i += 1;
        } else {
            // Safe to push byte-by-byte for ASCII; for multi-byte UTF-8 we need char boundaries
            let ch = input[i..].chars().next().unwrap();
            result.push(ch);
            i += ch.len_utf8();
        }
    }

    result
}

/// Decode UTF-16 LE or BE bytes to a UTF-8 String.
///
/// Detects BOM to determine byte order. Returns None if the bytes
/// don't start with a UTF-16 BOM or contain invalid code units.
pub fn decode_utf16(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 {
        return None;
    }

    let (is_le, start) = if bytes[0] == 0xFF && bytes[1] == 0xFE {
        (true, 2) // UTF-16 LE BOM
    } else if bytes[0] == 0xFE && bytes[1] == 0xFF {
        (false, 2) // UTF-16 BE BOM
    } else {
        return None; // No BOM — not UTF-16
    };

    let data = &bytes[start..];
    // Must have an even number of bytes
    if data.len() % 2 != 0 {
        return None;
    }

    let code_units: Vec<u16> = data
        .chunks_exact(2)
        .map(|pair| {
            if is_le {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect();

    String::from_utf16(&code_units).ok()
}

/// Check if a word is in the BIP-39 wordlist (using 4-char prefix binary search).
fn is_bip39_word(word: &str) -> bool {
    let lower = word.to_lowercase();
    // BIP-39 words are ASCII only, skip non-ASCII
    if !lower.is_ascii() || lower.len() < 3 {
        return false;
    }
    let prefix_len = lower.len().min(4);
    let prefix = &lower[..prefix_len];
    BIP39_PREFIXES.binary_search(&prefix).is_ok()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Tier 1 tests ─────────────────────────────────────────────────────

    #[test]
    fn detect_pem_private_key() {
        let findings = check_line("-----BEGIN RSA PRIVATE KEY-----", 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret_type, ContentSecretType::PemPrivateKey);
        assert_eq!(findings[0].confidence, Confidence::Definitive);
    }

    #[test]
    fn detect_ec_private_key() {
        let findings = check_line("-----BEGIN EC PRIVATE KEY-----", 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret_type, ContentSecretType::PemPrivateKey);
    }

    #[test]
    fn no_detect_pem_public_key() {
        let findings = check_line("-----BEGIN PUBLIC KEY-----", 1);
        assert!(findings
            .iter()
            .all(|f| f.secret_type != ContentSecretType::PemPrivateKey));
    }

    #[test]
    fn detect_aws_access_key() {
        let findings = check_line("aws_access_key = AKIAIOSFODNN7EXAMPLE", 1);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::AwsAccessKey));
        assert!(findings
            .iter()
            .any(|f| f.confidence == Confidence::Definitive));
    }

    #[test]
    fn detect_github_pat() {
        // Use realistic mixed-char token (real PATs have high entropy)
        let token = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8W9";
        let findings = check_line(token, 1);
        assert!(findings.iter().any(|f| matches!(f.secret_type, ContentSecretType::ApiKey { service } if service.contains("GitHub"))));
    }

    #[test]
    fn detect_stripe_live_key() {
        let key = "sk_live_51TESTFIXTUREdoNotUseThisIsNotARealKey000000";
        let findings = check_line(key, 1);
        assert!(findings.iter().any(|f| matches!(f.secret_type, ContentSecretType::ApiKey { service } if service.contains("Stripe"))));
    }

    #[test]
    fn detect_anthropic_key() {
        let key = "sk-ant-api03-Kx9mP2nQ7rW8sT3uV6wY1zA4bC5dE6fG7hI8jK9lM0nO1pQ";
        let findings = check_line(key, 1);
        assert!(findings.iter().any(|f| matches!(f.secret_type, ContentSecretType::ApiKey { service } if service.contains("Anthropic"))));
    }

    #[test]
    fn no_detect_api_key_low_entropy_suffix() {
        // Repeated chars after prefix — likely a placeholder, not a real key
        let fake_key = format!("ghp_{}", "a".repeat(36));
        let findings = check_line(&fake_key, 1);
        assert!(
            findings
                .iter()
                .all(|f| !matches!(f.secret_type, ContentSecretType::ApiKey { .. })),
            "Repeated-char API key suffix should be rejected by entropy check"
        );
    }

    #[test]
    fn detect_google_service_account() {
        let line = r#"{ "type": "service_account", "project_id": "test" }"#;
        let findings = check_line(line, 1);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::GoogleServiceAccount));
    }

    // ── Tier 2 tests ─────────────────────────────────────────────────────

    #[test]
    fn detect_jwt_token() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A";
        let findings = check_line(jwt, 1);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::JwtToken));
    }

    #[test]
    fn detect_credit_card_visa() {
        let findings = check_line("4532015112830366", 1);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::CreditCard));
    }

    #[test]
    fn no_detect_invalid_luhn() {
        let findings = check_line("4532015112830367", 1);
        assert!(findings
            .iter()
            .all(|f| f.secret_type != ContentSecretType::CreditCard));
    }

    #[test]
    fn detect_postgres_connection() {
        let findings = check_line("postgres://user:password@localhost:5432/db", 1);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::DbConnectionString));
    }

    #[test]
    fn no_detect_db_without_creds() {
        let findings = check_line("postgres://localhost:5432/db", 1);
        assert!(findings
            .iter()
            .all(|f| f.secret_type != ContentSecretType::DbConnectionString));
    }

    #[test]
    fn detect_eth_hex_key() {
        // Realistic hex key with high entropy (all 16 hex chars represented)
        let key = "0xa1b2c3d4e5f678901234567890abcdef1a2b3c4d5e6f7890fedcba9876543210";
        let findings = check_line(key, 1);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::EthHexKey));
    }

    #[test]
    fn no_detect_eth_hex_low_entropy() {
        // Repeated hex pattern — likely not a real key
        let key = format!("0x{}", "aa".repeat(32));
        let findings = check_line(&key, 1);
        assert!(
            findings
                .iter()
                .all(|f| f.secret_type != ContentSecretType::EthHexKey),
            "Low-entropy hex should be rejected by entropy check"
        );
    }

    #[test]
    fn no_detect_evm_bytecode() {
        // Solidity compiled bytecode: 0x + hundreds of hex chars. Not a private key.
        let bytecode = format!("0x{}", "60806040".repeat(50));
        let findings = check_line(&bytecode, 1);
        assert!(
            findings
                .iter()
                .all(|f| f.secret_type != ContentSecretType::EthHexKey),
            "EVM bytecode should not be detected as an Ethereum hex key"
        );
    }

    // ── Tier 3 tests ─────────────────────────────────────────────────────

    #[test]
    fn detect_password_assignment() {
        let findings = check_line("password = supersecretvalue123", 1);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::PasswordPattern));
    }

    #[test]
    fn no_detect_password_placeholder() {
        let findings = check_line("password = your-password-here", 1);
        assert!(findings
            .iter()
            .all(|f| f.secret_type != ContentSecretType::PasswordPattern));
    }

    #[test]
    fn no_detect_password_empty() {
        let findings = check_line("password = \"\"", 1);
        assert!(findings
            .iter()
            .all(|f| f.secret_type != ContentSecretType::PasswordPattern));
    }

    #[test]
    fn detect_ssn() {
        let findings = check_line("SSN: 123-45-6789", 1);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::SsnPattern));
    }

    #[test]
    fn no_detect_invalid_ssn_area() {
        // Area 000 is invalid
        let findings = check_line("000-45-6789", 1);
        assert!(findings
            .iter()
            .all(|f| f.secret_type != ContentSecretType::SsnPattern));
        // Area 666 is invalid
        let findings = check_line("666-45-6789", 1);
        assert!(findings
            .iter()
            .all(|f| f.secret_type != ContentSecretType::SsnPattern));
        // Area 900+ is invalid
        let findings = check_line("900-45-6789", 1);
        assert!(findings
            .iter()
            .all(|f| f.secret_type != ContentSecretType::SsnPattern));
    }

    // ── Multi-line tests ─────────────────────────────────────────────────

    #[test]
    fn detect_seed_phrase_12_words() {
        let lines = vec![
            "abandon ability able about above absent absorb abstract absurd abuse access accident",
        ];
        let findings = check_multi_line(&lines);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::SeedPhrase));
    }

    #[test]
    fn no_detect_short_word_run() {
        let lines = vec!["abandon ability able about above absent"];
        let findings = check_multi_line(&lines);
        assert!(findings
            .iter()
            .all(|f| f.secret_type != ContentSecretType::SeedPhrase));
    }

    #[test]
    fn no_detect_english_prose_as_seed() {
        // Normal English prose — many words match BIP-39 prefixes but have punctuation
        let lines = vec![
            "About the project, we also need to action these items above all else.",
            "The primary call was about making a change, because the actual cost below",
            "the budget allows us to close the deal and carry forward with the plan.",
        ];
        let findings = check_multi_line(&lines);
        assert!(
            findings
                .iter()
                .all(|f| f.secret_type != ContentSecretType::SeedPhrase),
            "Normal English prose should not trigger seed phrase detection"
        );
    }

    #[test]
    fn no_detect_prose_with_punctuation() {
        // Every word here is BIP-39, but commas/periods break runs
        let lines = vec![
            "abandon, ability, able, about, above, absent, absorb, abstract, absurd, abuse, access, accident",
        ];
        let findings = check_multi_line(&lines);
        assert!(
            findings
                .iter()
                .all(|f| f.secret_type != ContentSecretType::SeedPhrase),
            "Punctuated word lists should not trigger seed phrase detection"
        );
    }

    #[test]
    fn category_method() {
        assert_eq!(ContentSecretType::PemPrivateKey.category(), "Crypto Keys");
        assert_eq!(ContentSecretType::AwsAccessKey.category(), "API Keys");
        assert_eq!(ContentSecretType::SeedPhrase.category(), "Seed Phrases");
        assert_eq!(ContentSecretType::JwtToken.category(), "Auth Tokens");
        assert_eq!(ContentSecretType::CreditCard.category(), "Financial");
        assert_eq!(ContentSecretType::PasswordPattern.category(), "Passwords");
        assert_eq!(
            ContentSecretType::SuspiciousImage.category(),
            "Suspicious Images"
        );
    }

    #[test]
    fn detect_2fa_backup_codes() {
        let lines = vec!["12345678", "87654321", "11223344", "55667788", "99001122"];
        let findings = check_multi_line(&lines);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::TwoFactorBackupCodes));
    }

    // ── Image filename tests ─────────────────────────────────────────────

    #[test]
    fn detect_recovery_key_image() {
        let finding = check_image_filename("recovery-key-photo.heic");
        assert!(finding.is_some());
        assert_eq!(
            finding.unwrap().secret_type,
            ContentSecretType::SuspiciousImage
        );
    }

    #[test]
    fn detect_seed_phrase_image() {
        let finding = check_image_filename("seed-phrase-backup.png");
        assert!(finding.is_some());
    }

    #[test]
    fn no_detect_screenshot() {
        // Generic screenshots should NOT trigger — too noisy
        let finding = check_image_filename("Screenshot 2024-01-15.png");
        assert!(finding.is_none());
    }

    #[test]
    fn no_detect_normal_image() {
        let finding = check_image_filename("vacation-beach.jpg");
        assert!(finding.is_none());
    }

    #[test]
    fn no_detect_keyboard_image() {
        // "key" alone should not match — "keyboard" is not suspicious
        let finding = check_image_filename("keyboard-layout.png");
        assert!(finding.is_none());
    }

    // ── Helper tests ─────────────────────────────────────────────────────

    #[test]
    fn luhn_valid() {
        assert!(luhn_check("4532015112830366"));
        assert!(luhn_check("79927398713"));
    }

    #[test]
    fn luhn_invalid() {
        assert!(!luhn_check("4532015112830367"));
        assert!(!luhn_check("1234567890"));
    }

    #[test]
    fn base58_valid() {
        assert!(is_base58(
            "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        ));
    }

    #[test]
    fn base58_invalid() {
        assert!(!is_base58("0OlI")); // These chars are not in base58
    }

    #[test]
    fn bip39_word_lookup() {
        assert!(is_bip39_word("abandon"));
        assert!(is_bip39_word("ability"));
        assert!(is_bip39_word("zoo"));
        assert!(!is_bip39_word("xyzzy"));
        assert!(!is_bip39_word("ab")); // too short
    }

    // ── Redaction tests ──────────────────────────────────────────────────

    // ── Sensitive marking tests ───────────────────────────────────────────

    #[test]
    fn detect_top_secret_banner() {
        let findings = check_line("TOP SECRET", 1);
        assert!(findings.iter().any(|f| matches!(
            &f.secret_type,
            ContentSecretType::SensitiveMarking {
                marking: "TOP SECRET"
            }
        )));
        assert!(findings
            .iter()
            .any(|f| f.confidence == Confidence::Definitive));
    }

    #[test]
    fn detect_secret_sci_noforn() {
        let findings = check_line("SECRET//SCI//NOFORN", 1);
        assert!(findings
            .iter()
            .any(|f| matches!(&f.secret_type, ContentSecretType::SensitiveMarking { .. })));
        assert!(findings
            .iter()
            .any(|f| f.confidence == Confidence::Definitive));
    }

    #[test]
    fn detect_portion_marking_ts() {
        let findings = check_line("(TS) The following data is classified", 1);
        assert!(findings.iter().any(|f| matches!(
            &f.secret_type,
            ContentSecretType::SensitiveMarking { marking: "(TS)" }
        )));
        assert!(findings
            .iter()
            .any(|f| f.confidence == Confidence::Definitive));
    }

    #[test]
    fn detect_portion_marking_s() {
        let findings = check_line("(S) This paragraph is secret", 1);
        assert!(findings.iter().any(|f| matches!(
            &f.secret_type,
            ContentSecretType::SensitiveMarking { marking: "(S)" }
        )));
    }

    #[test]
    fn detect_cui_banner() {
        let findings = check_line("CUI//SP-PRVCY", 1);
        assert!(findings.iter().any(|f| matches!(
            &f.secret_type,
            ContentSecretType::SensitiveMarking { marking: "CUI" }
        )));
    }

    #[test]
    fn detect_export_controlled_itar() {
        let findings = check_line("This document is controlled under 22 CFR 120-130 (ITAR)", 1);
        assert!(findings.iter().any(|f| matches!(
            &f.secret_type,
            ContentSecretType::SensitiveMarking { marking: "ITAR" }
        )));
        assert!(findings.iter().any(|f| f.confidence == Confidence::High));
    }

    #[test]
    fn detect_corporate_proprietary() {
        let findings = check_line(
            "This document contains proprietary information of Acme Corp.",
            1,
        );
        assert!(findings.iter().any(|f| matches!(
            &f.secret_type,
            ContentSecretType::SensitiveMarking {
                marking: "PROPRIETARY"
            }
        )));
        assert!(findings
            .iter()
            .any(|f| f.confidence == Confidence::ContextDependent));
    }

    #[test]
    fn no_detect_secret_in_prose() {
        // "the secret ingredient is..." — bare word "secret" should NOT trigger
        let findings = check_line("the secret ingredient is love", 1);
        assert!(
            findings
                .iter()
                .all(|f| !matches!(&f.secret_type, ContentSecretType::SensitiveMarking { .. })),
            "Prose containing 'secret' should not trigger sensitive marking detection"
        );
    }

    #[test]
    fn no_detect_confidential_in_prose() {
        // "this is confidential information" — not a standalone banner
        let findings = check_line("this is confidential information", 1);
        assert!(
            findings
                .iter()
                .all(|f| !matches!(&f.secret_type, ContentSecretType::SensitiveMarking { .. })),
            "Prose containing 'confidential' should not trigger sensitive marking detection"
        );
    }

    #[test]
    fn no_detect_marking_in_string_literal() {
        // Source code pattern definitions should not trigger — keyword is inside quotes
        let cases = vec![
            r#"        ("NOFORN", "NOFORN"),"#,
            r#"        ("ORCON", "ORCON"),"#,
            r#"        ("REL TO", "REL TO"),"#,
            r#"    if upper.starts_with("TOP SECRET") {"#,
            r#"        marking: "CONFIDENTIAL","#,
            r#"    for &(phrase, marking) in &[("PROPRIETARY INFORMATION", "PROPRIETARY")]"#,
            r#"        ("EXPORT CONTROLLED", "EXPORT CONTROLLED"),"#,
        ];
        for line in &cases {
            let findings = check_line(line, 1);
            assert!(
                findings
                    .iter()
                    .all(|f| !matches!(&f.secret_type, ContentSecretType::SensitiveMarking { .. })),
                "String literal should not trigger marking detection: {}",
                line
            );
        }
    }

    #[test]
    fn severity_ranking() {
        // API keys should be critical
        assert_eq!(
            ContentSecretType::AwsAccessKey.severity(),
            Severity::Critical
        );
        assert_eq!(
            ContentSecretType::ApiKey { service: "GitHub" }.severity(),
            Severity::Critical
        );
        // Seed phrases should be high
        assert_eq!(ContentSecretType::SeedPhrase.severity(), Severity::High);
        // NOFORN should be medium (policy, not a credential)
        assert_eq!(
            ContentSecretType::SensitiveMarking { marking: "NOFORN" }.severity(),
            Severity::Medium
        );
        // TOP SECRET should be high (classified docs are serious)
        assert_eq!(
            ContentSecretType::SensitiveMarking {
                marking: "TOP SECRET"
            }
            .severity(),
            Severity::High
        );
        // Suspicious images should be low
        assert_eq!(ContentSecretType::SuspiciousImage.severity(), Severity::Low);
    }

    #[test]
    fn category_sensitive() {
        let t = ContentSecretType::SensitiveMarking {
            marking: "TOP SECRET",
        };
        assert_eq!(t.category(), "Sensitivity Labels");
    }

    // ── Redaction tests ──────────────────────────────────────────────────

    #[test]
    fn redaction_never_shows_full_value() {
        let test_cases: Vec<String> = vec![
            "-----BEGIN RSA PRIVATE KEY-----".to_string(),
            "AKIAIOSFODNN7EXAMPLE".to_string(),
            format!("ghp_{}", "a".repeat(36)),
            "4532015112830366".to_string(),
            "postgres://user:password@localhost:5432/db".to_string(),
            "password = mysecretvalue".to_string(),
        ];

        for case in &test_cases {
            let findings = check_line(case.as_str(), 1);
            for finding in &findings {
                // The redacted preview should never contain the full secret
                assert!(
                    finding.redacted_preview.contains("****")
                        || finding.redacted_preview.contains("..."),
                    "Finding preview should be redacted: {:?}",
                    finding.redacted_preview
                );
            }
        }
    }

    // ── Context detection tests ─────────────────────────────────────────

    #[test]
    fn detect_comment_line_double_slash() {
        assert_eq!(
            detect_line_context("  // password = secret123"),
            LineContext::Comment
        );
    }

    #[test]
    fn detect_comment_line_hash() {
        assert_eq!(
            detect_line_context("# AWS_ACCESS_KEY=AKIA..."),
            LineContext::Comment
        );
    }

    #[test]
    fn detect_comment_line_sql() {
        assert_eq!(
            detect_line_context("  -- password: secret"),
            LineContext::Comment
        );
    }

    #[test]
    fn detect_comment_block_start() {
        assert_eq!(
            detect_line_context("  /* secret key here */"),
            LineContext::Comment
        );
    }

    #[test]
    fn detect_comment_block_middle() {
        assert_eq!(
            detect_line_context("  * AKIAIOSFODNN7EXAMPLE"),
            LineContext::Comment
        );
    }

    #[test]
    fn detect_code_not_comment() {
        assert_eq!(
            detect_line_context("password = supersecret123"),
            LineContext::Code
        );
    }

    #[test]
    fn detect_shebang_not_comment() {
        assert_eq!(detect_line_context("#!/bin/bash"), LineContext::Code);
    }

    #[test]
    fn detect_rust_attribute_not_comment() {
        assert_eq!(detect_line_context("#[derive(Debug)]"), LineContext::Code);
    }

    #[test]
    fn comment_downgrades_confidence() {
        // An AWS key in a comment should be downgraded from Definitive to High
        let findings =
            check_line_with_context("  // aws_access_key = AKIAIOSFODNN7EXAMPLE", 1, None);
        assert!(findings
            .iter()
            .any(|f| f.secret_type == ContentSecretType::AwsAccessKey));
        assert!(findings.iter().all(|f| {
            if f.secret_type == ContentSecretType::AwsAccessKey {
                f.confidence == Confidence::High && f.context == LineContext::Comment
            } else {
                true
            }
        }));
    }

    #[test]
    fn code_preserves_confidence() {
        // An AWS key in code should stay Definitive
        let findings = check_line_with_context("aws_access_key = AKIAIOSFODNN7EXAMPLE", 1, None);
        assert!(findings.iter().any(|f| {
            f.secret_type == ContentSecretType::AwsAccessKey
                && f.confidence == Confidence::Definitive
                && f.context == LineContext::Code
        }));
    }

    #[test]
    fn executed_context_override() {
        // Shell history: override to Executed context, no downgrade
        let findings =
            check_line_with_context("password = mysecretvalue", 1, Some(LineContext::Executed));
        assert!(findings.iter().any(|f| {
            f.secret_type == ContentSecretType::PasswordPattern
                && f.confidence == Confidence::ContextDependent
                && f.context == LineContext::Executed
        }));
    }

    // ── Base64 decoding tests ───────────────────────────────────────────

    #[test]
    fn base64_decode_simple() {
        let decoded = base64_decode("SGVsbG8gV29ybGQ=");
        assert_eq!(decoded, Some(b"Hello World".to_vec()));
    }

    #[test]
    fn base64_decode_no_padding() {
        let decoded = base64_decode("QUJDRA==");
        assert_eq!(decoded, Some(b"ABCD".to_vec()));
    }

    #[test]
    fn base64_decode_invalid() {
        // Invalid length (not multiple of 4)
        assert_eq!(base64_decode("abc"), None);
        // Invalid chars
        assert_eq!(base64_decode("a b!"), None);
    }

    #[test]
    fn detect_base64_encoded_aws_key() {
        // "AKIAIOSFODNN7EXAMPLE" base64-encoded
        let encoded = "QUtJQUlPU0ZPRE5ON0VYQU1QTEU=";
        let findings = check_base64_content(encoded, 1);
        assert!(
            findings
                .iter()
                .any(|f| f.secret_type == ContentSecretType::AwsAccessKey),
            "Should detect AWS key inside base64-encoded content"
        );
        assert!(findings
            .iter()
            .all(|f| f.context == LineContext::Base64Encoded));
        assert!(findings
            .iter()
            .all(|f| f.redacted_preview.starts_with("[base64]")));
    }

    #[test]
    fn detect_base64_encoded_pem_header() {
        // "-----BEGIN RSA PRIVATE KEY-----" base64-encoded
        let encoded = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==";
        let findings = check_base64_content(encoded, 1);
        assert!(
            findings
                .iter()
                .any(|f| f.secret_type == ContentSecretType::PemPrivateKey),
            "Should detect PEM header inside base64-encoded content"
        );
    }

    #[test]
    fn no_detect_base64_normal_text() {
        // "Hello World, this is a normal sentence" base64-encoded
        let encoded = "SGVsbG8gV29ybGQsIHRoaXMgaXMgYSBub3JtYWwgc2VudGVuY2U=";
        let findings = check_base64_content(encoded, 1);
        assert!(
            findings.is_empty(),
            "Normal text in base64 should not trigger"
        );
    }

    #[test]
    fn detect_base64_in_longer_line() {
        // A line with a base64 token embedded among other text
        let line = format!("export DATA=QUtJQUlPU0ZPRE5ON0VYQU1QTEU= # encoded key");
        let findings = check_base64_content(&line, 1);
        assert!(
            findings
                .iter()
                .any(|f| f.secret_type == ContentSecretType::AwsAccessKey),
            "Should find AWS key in base64 token within a longer line"
        );
    }

    #[test]
    fn is_likely_base64_rejects_short() {
        assert!(!is_likely_base64("abc="));
        assert!(!is_likely_base64(""));
    }

    #[test]
    fn is_likely_base64_accepts_valid() {
        assert!(is_likely_base64("QUtJQUlPU0ZPRE5ON0VYQU1QTEU="));
    }

    #[test]
    fn confidence_downgrade_chain() {
        assert_eq!(Confidence::Definitive.downgrade(), Confidence::High);
        assert_eq!(Confidence::High.downgrade(), Confidence::ContextDependent);
        assert_eq!(
            Confidence::ContextDependent.downgrade(),
            Confidence::Heuristic
        );
        assert_eq!(Confidence::Heuristic.downgrade(), Confidence::Heuristic);
    }

    #[test]
    fn line_context_labels() {
        assert_eq!(LineContext::Code.label(), "code");
        assert_eq!(LineContext::Comment.label(), "comment");
        assert_eq!(LineContext::Executed.label(), "executed");
        assert_eq!(LineContext::Base64Encoded.label(), "base64");
    }

    // ── Entropy scoring tests ───────────────────────────────────────────

    #[test]
    fn entropy_empty_string() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn entropy_single_char() {
        assert!(shannon_entropy("aaaa") < 0.01);
    }

    #[test]
    fn entropy_high_randomness() {
        // Mix of all printable ASCII chars = high entropy
        let s = "aB3$xZ9@mK7!pQ2#wL5&";
        let e = shannon_entropy(s);
        assert!(
            e > 4.0,
            "High-entropy mixed string should be > 4.0 bits/byte, got {e}"
        );
    }

    #[test]
    fn entropy_real_api_key() {
        let e = shannon_entropy("51Srsy8Am5gWouXUPqhopS7VEKcxIPjv");
        assert!(
            e > ENTROPY_THRESHOLD_API_KEY,
            "Real API key suffix should exceed threshold, got {e}"
        );
    }

    #[test]
    fn entropy_placeholder_low() {
        let e = shannon_entropy("xxxxxxxxxxxx");
        assert!(
            e < ENTROPY_THRESHOLD_API_KEY,
            "Repeated chars should be below threshold, got {e}"
        );
    }

    #[test]
    fn entropy_password_real_vs_fake() {
        // Real password: high entropy
        let real = shannon_entropy("kX9$mP2!nQ7@sT3");
        assert!(real > ENTROPY_THRESHOLD_PASSWORD);

        // Fake/simple: low entropy
        let fake = shannon_entropy("aaaa");
        assert!(fake < ENTROPY_THRESHOLD_PASSWORD);
    }

    #[test]
    fn no_detect_password_low_entropy() {
        // "password = aaaa" should be rejected (low entropy value)
        let findings = check_line("password = aaaaaa", 1);
        assert!(
            findings
                .iter()
                .all(|f| f.secret_type != ContentSecretType::PasswordPattern),
            "Low-entropy password value should be rejected"
        );
    }

    #[test]
    fn detect_password_high_entropy() {
        // "password = kX9$mP2!nQ7@" should be detected (high entropy)
        let findings = check_line("password = kX9mP2nQ7sT3uV6", 1);
        assert!(
            findings
                .iter()
                .any(|f| f.secret_type == ContentSecretType::PasswordPattern),
            "High-entropy password value should be detected"
        );
    }

    // ── D-23: False positive wordlist tests ─────────────────────────────

    #[test]
    fn false_positive_rejects_programming_keywords() {
        assert!(is_false_positive("sha256"));
        assert!(is_false_positive("SHA256"));
        assert!(is_false_positive("encrypt"));
        assert!(is_false_positive("callback"));
    }

    #[test]
    fn false_positive_rejects_hex_constants() {
        assert!(is_false_positive("deadbeef"));
        assert!(is_false_positive("CAFEBABE"));
        assert!(is_false_positive("baadf00d"));
    }

    #[test]
    fn false_positive_allows_real_secrets() {
        assert!(!is_false_positive("kX9mP2nQ7sT3uV6wY1zA4bC5"));
        assert!(!is_false_positive("51Srsy8Am5gWouXUPqhopS7VEKcxIPjv"));
    }

    #[test]
    fn false_positive_rejects_low_entropy_hex_color() {
        // 6-char hex that looks like a CSS color (#aabbcc)
        assert!(is_false_positive("aabbcc"));
    }

    #[test]
    fn password_false_positive_not_detected() {
        // "password = localhost" should not trigger (programming keyword)
        let findings = check_line("password = localhost", 1);
        assert!(
            findings
                .iter()
                .all(|f| f.secret_type != ContentSecretType::PasswordPattern),
            "False positive keyword 'localhost' as password value should be rejected"
        );
    }

    // ── D-24: URI credential tests ──────────────────────────────────────

    #[test]
    fn detect_uri_credentials_https() {
        let findings = check_line("https://admin:s3cretP4ss@db.example.com:5432/mydb", 1);
        assert!(
            findings
                .iter()
                .any(|f| f.secret_type == ContentSecretType::DbConnectionString
                    && f.description.contains("URI with embedded credentials")),
            "Should detect credentials in HTTPS URI"
        );
    }

    #[test]
    fn detect_uri_credentials_ftp() {
        let findings = check_line("ftp://deploy:hunter2abc@files.corp.net/releases", 1);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("URI with embedded credentials")),
            "Should detect credentials in FTP URI"
        );
    }

    #[test]
    fn no_detect_uri_placeholder_password() {
        let findings = check_line("https://user:your-password-here@example.com/api", 1);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("URI with embedded credentials")),
            "Should not detect placeholder password in URI"
        );
    }

    #[test]
    fn no_detect_uri_without_credentials() {
        let findings = check_line("https://example.com/api/v1/data", 1);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("URI with embedded credentials")),
            "Should not flag URIs without credentials"
        );
    }

    // ── D-25: Webhook URL tests ─────────────────────────────────────────

    #[test]
    fn detect_slack_webhook() {
        let findings = check_line(
            "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
            1,
        );
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Slack Incoming Webhook"
            )),
            "Should detect Slack incoming webhook URL"
        );
    }

    #[test]
    fn detect_discord_webhook() {
        let findings = check_line(
            "https://discord.com/api/webhooks/123456789/abcdefghijklmnop",
            1,
        );
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Discord Webhook"
            )),
            "Should detect Discord webhook URL"
        );
    }

    #[test]
    fn detect_teams_webhook() {
        let findings = check_line(
            "https://outlook.office.com/webhook/xxxxx/IncomingWebhook/yyyyy",
            1,
        );
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Microsoft Teams Webhook"
            )),
            "Should detect Teams webhook URL"
        );
    }

    #[test]
    fn detect_telegram_bot_token() {
        let findings = check_line(
            "https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/sendMessage",
            1,
        );
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Telegram Bot Token"
            )),
            "Should detect Telegram bot token URL"
        );
    }

    // ── D-26: Azure pattern tests ───────────────────────────────────────

    #[test]
    fn detect_azure_storage_connection_string() {
        let findings = check_line(
            "DefaultEndpointsProtocol=https;AccountName=myacct;AccountKey=abc123def456ghi789==;EndpointSuffix=core.windows.net",
            1,
        );
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Azure Storage"
            )),
            "Should detect Azure Storage connection string"
        );
    }

    #[test]
    fn detect_azure_sas_token() {
        let findings = check_line(
            "https://myaccount.blob.core.windows.net/container?sv=2021-06-08&se=2024-01-01&sig=abcdef123456",
            1,
        );
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Azure SAS Token"
            )),
            "Should detect Azure SAS token"
        );
    }

    #[test]
    fn no_detect_azure_without_key() {
        let findings = check_line("DefaultEndpointsProtocol=https;AccountName=myacct", 1);
        assert!(
            findings.iter().all(|f| !matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Azure Storage"
            )),
            "Should not detect Azure Storage without AccountKey"
        );
    }

    // ── D-27: AI provider token tests ───────────────────────────────────

    #[test]
    fn detect_deepseek_api_key() {
        let key = "dsk-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
        let findings = check_line(key, 1);
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "DeepSeek API Key"
            )),
            "Should detect DeepSeek API key"
        );
    }

    #[test]
    fn detect_groq_api_key() {
        let key = "gsk_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
        let findings = check_line(key, 1);
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Groq API Key"
            )),
            "Should detect Groq API key"
        );
    }

    #[test]
    fn detect_replicate_api_token() {
        let key = "r8_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8W9";
        let findings = check_line(key, 1);
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Replicate API Token"
            )),
            "Should detect Replicate API token"
        );
    }

    #[test]
    fn detect_perplexity_api_key() {
        let key = "pplx-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
        let findings = check_line(key, 1);
        assert!(
            findings.iter().any(|f| matches!(
                &f.secret_type,
                ContentSecretType::ApiKey { service } if *service == "Perplexity API Key"
            )),
            "Should detect Perplexity API key"
        );
    }

    // ── D-28: Unicode decoding tests ─────────────────────────────────────

    #[test]
    fn safe_prefix_never_splits_a_character() {
        assert_eq!(safe_prefix("abc", 10), "abc");
        assert_eq!(safe_prefix("abcdef", 3), "abc");
        // "—" is three bytes; a cut at byte 2 backs off to the boundary.
        assert_eq!(safe_prefix("a—b", 2), "a");
        assert_eq!(safe_prefix("a—b", 4), "a—");
        assert_eq!(safe_prefix("—", 0), "");
    }

    /// The exact shape of a production crash: a dissemination-control line
    /// whose 60-byte preview cut landed inside an em dash.
    #[test]
    fn marking_preview_survives_multibyte_text() {
        let line = "NOFORN distribution statement for the programme — see annex — more text here";
        let findings = check_line_with_context(line, 1, None);
        assert!(findings
            .iter()
            .any(|f| f.description.contains("Dissemination")));
        for f in &findings {
            assert!(f.redacted_preview.chars().all(|c| c != '\u{FFFD}'));
        }
    }

    /// Every scanner entry point must tolerate multi-byte characters at every
    /// offset around every trigger keyword. This is the test that would have
    /// caught the crash above.
    #[test]
    fn scanners_never_panic_on_multibyte_text_near_triggers() {
        let triggers = [
            "AKIA",
            "eyJ",
            "0x",
            "NOFORN",
            "ORCON",
            "REL TO",
            "EXPORT CONTROLLED",
            "CONFIDENTIAL",
            "(CUI)",
            "(C)",
            "(S)",
            "TOP SECRET",
            "22 CFR 12",
            "15 CFR 73",
            "sk_live_",
            "ghp_",
            "xoxb-",
            "AC",
            "pat",
            "postgres://",
            "mongodb://",
            "-----BEGIN",
            "password=",
            "secret:",
            "token",
            "AIza",
            "SG.",
            "glpat-",
            "PROPRIETARY",
            "TRADE SECRET",
            "ITAR",
            "5KJvsngHeMpm48GZxPqh",
            "L1aW4aubDFB7yfras2S1",
        ];
        let fillers = ["—", "é", "日本", "🦔", "ß", "ø"];
        let mut lines = Vec::new();
        for trigger in triggers {
            for filler in fillers {
                for n in 0..70 {
                    let pad: String = std::iter::repeat_n(filler, n).collect();
                    lines.push(format!("{trigger}{pad}"));
                    lines.push(format!("{pad}{trigger}{pad}"));
                    lines.push(format!(
                        "{trigger}{}{filler}{}",
                        "A".repeat(n),
                        "A".repeat(70 - n)
                    ));
                    lines.push(format!("{trigger} = \"{}{filler}\"", "x".repeat(n)));
                }
            }
        }
        for (i, line) in lines.iter().enumerate() {
            let _ = check_line(line, i + 1);
            let _ = check_line_with_context(line, i + 1, None);
            let _ = check_base64_content(line, i + 1);
            let _ = check_unicode_obfuscated(line, i + 1);
            let _ = detect_line_context(line);
        }
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        for chunk in refs.chunks(500) {
            let _ = check_multi_line(chunk);
        }
    }

    #[test]
    fn decode_unicode_escape_u() {
        // \u0041\u004b\u0049\u0041 = "AKIA"
        let input = r"\u0041\u004b\u0049\u0041IOSFODNN7EXAMPLE";
        let decoded = decode_unicode_escapes(input);
        assert_eq!(decoded, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn decode_unicode_escape_x() {
        // \x41\x4b\x49\x41 = "AKIA"
        let input = r"\x41\x4bIAIOSFODNN7EXAMPLE";
        let decoded = decode_unicode_escapes(input);
        assert_eq!(decoded, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn decode_url_encoding() {
        // %41%4b%49%41 = "AKIA"
        let input = "%41%4b%49%41IOSFODNN7EXAMPLE";
        let decoded = decode_unicode_escapes(input);
        assert_eq!(decoded, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn detect_unicode_obfuscated_aws_key() {
        // AWS key with \u escapes on the prefix
        let line = r"key = \u0041\u004b\u0049\u0041IOSFODNN7EXAMPLE";
        let findings = check_unicode_obfuscated(line, 1);
        assert!(
            findings
                .iter()
                .any(|f| f.secret_type == ContentSecretType::AwsAccessKey),
            "Should detect AWS key through Unicode escapes"
        );
        assert!(findings[0].redacted_preview.starts_with("[unicode]"));
    }

    #[test]
    fn detect_url_encoded_password() {
        // password%3Dmysupersecretvalue (%3D = '=')
        let line = "config password%3Dmysupersecretvalue";
        let findings = check_unicode_obfuscated(line, 1);
        // After decoding: "config password=mysupersecretvalue"
        assert!(
            findings
                .iter()
                .any(|f| f.secret_type == ContentSecretType::PasswordPattern),
            "Should detect password through URL encoding"
        );
    }

    #[test]
    fn no_false_positive_normal_text() {
        // Normal text with no escape sequences should return empty
        let line = "This is a normal line with no secrets";
        let findings = check_unicode_obfuscated(line, 1);
        assert!(findings.is_empty());
    }

    #[test]
    fn no_decode_invalid_escapes() {
        // Invalid escape sequences should not crash
        let line = r"\uGGGG \xZZ %ZZ normal text";
        let decoded = decode_unicode_escapes(line);
        // \uGGGG stays as-is, \xZZ stays, %ZZ stays
        assert!(decoded.contains("normal text"));
    }

    #[test]
    fn decode_mixed_escapes() {
        // Mix of \u, \x, and %XX
        let input = r"\u0048\x65llo%20World";
        let decoded = decode_unicode_escapes(input);
        assert_eq!(decoded, "Hello World");
    }

    #[test]
    fn decode_utf16_le() {
        // UTF-16 LE BOM + "AKIAIOSFODNN7EXAMPLE" in UTF-16 LE
        let text = "AKIAIOSFODNN7EXAMPLE";
        let mut bytes = vec![0xFF, 0xFE]; // BOM
        for ch in text.encode_utf16() {
            bytes.extend_from_slice(&ch.to_le_bytes());
        }
        let decoded = decode_utf16(&bytes);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), text);
    }

    #[test]
    fn decode_utf16_be() {
        // UTF-16 BE BOM + "password=secret"
        let text = "password=secret";
        let mut bytes = vec![0xFE, 0xFF]; // BOM
        for ch in text.encode_utf16() {
            bytes.extend_from_slice(&ch.to_be_bytes());
        }
        let decoded = decode_utf16(&bytes);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap(), text);
    }

    #[test]
    fn no_decode_without_bom() {
        // No BOM — should return None
        let bytes = b"Hello World";
        let decoded = decode_utf16(bytes);
        assert!(decoded.is_none());
    }

    #[test]
    fn has_unicode_escapes_detection() {
        assert!(has_unicode_escapes(r"foo \u0041 bar"));
        assert!(has_unicode_escapes(r"foo \x41 bar"));
        assert!(has_unicode_escapes("foo %41 bar"));
        assert!(!has_unicode_escapes("foo bar baz"));
        assert!(!has_unicode_escapes(r"foo \n bar")); // \n is not \uXXXX
    }

    // ── Marking previews never quote document content ───────────────────

    fn marking_previews(line: &str) -> Vec<(String, &'static str)> {
        check_line(line, 7)
            .into_iter()
            .filter_map(|f| match f.secret_type {
                ContentSecretType::SensitiveMarking { marking } => {
                    assert_eq!(f.line_number, 7, "line number must be kept");
                    Some((f.redacted_preview, marking))
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn marking_previews_are_fixed_labels_without_document_text() {
        let cases: &[(&str, &str, bool)] = &[
            (
                "TOP SECRET//SI//EXAMPLECODEWORD//NOFORN",
                "[MARKING] classification banner (TOP SECRET level)",
                true,
            ),
            (
                "SECRET//SI//EXAMPLECODEWORD//NOFORN",
                "[MARKING] classification banner (SECRET level)",
                true,
            ),
            (
                "CONFIDENTIAL//EXAMPLECODEWORD",
                "[MARKING] classification banner (CONFIDENTIAL level)",
                true,
            ),
            ("CUI//SP-EXAMPLECODEWORD", "[MARKING] CUI designation", true),
            (
                "(TS//SI//EXAMPLECODEWORD) The source reported troop movements",
                "[PORTION] portion mark (TS)",
                true,
            ),
            (
                "(S//EXAMPLECODEWORD) The source reported troop movements",
                "[PORTION] portion mark (S)",
                true,
            ),
            (
                "(C) EXAMPLECODEWORD the source reported troop movements",
                "[PORTION] portion mark (C)",
                true,
            ),
            (
                "(CUI) EXAMPLECODEWORD the source reported",
                "[PORTION] portion mark (CUI)",
                true,
            ),
            (
                "Handling EXAMPLECODEWORD material: NOFORN",
                "[MARKING] dissemination control NOFORN",
                true,
            ),
            (
                "Handling EXAMPLECODEWORD material: ORCON",
                "[MARKING] dissemination control ORCON",
                true,
            ),
            (
                "Handling EXAMPLECODEWORD material: REL TO USA, GBR",
                "[MARKING] dissemination control REL TO",
                true,
            ),
            (
                "EXAMPLECODEWORD data controlled under 22 CFR 120-130",
                "[MARKING] ITAR export-control notice",
                false,
            ),
            (
                "EXAMPLECODEWORD data controlled under 15 CFR 730-774",
                "[MARKING] EAR export-control notice",
                false,
            ),
            (
                "EXAMPLECODEWORD contains proprietary information of Acme",
                "[MARKING] corporate sensitivity label PROPRIETARY",
                false,
            ),
            (
                "EXAMPLECODEWORD is a trade secret of Acme",
                "[MARKING] corporate sensitivity label TRADE SECRET",
                false,
            ),
        ];
        for (line, expected, government) in cases {
            let previews = marking_previews(line);
            assert_eq!(previews.len(), 1, "one marking finding for {line:?}");
            let (preview, marking) = &previews[0];
            assert_eq!(preview, expected, "preview for {line:?}");
            assert!(
                !preview.contains("EXAMPLECODEWORD")
                    && !preview.contains("//SI")
                    && !preview.to_lowercase().contains("source")
                    && !preview.to_lowercase().contains("acme"),
                "preview leaks document text: {preview:?}"
            );
            assert_eq!(
                is_government_marking(marking),
                *government,
                "government classification flag for {marking:?}"
            );
        }
    }
}
