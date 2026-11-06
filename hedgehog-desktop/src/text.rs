// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Plain-text helpers shared by the window: numbers with separators, file
//! sizes, time left, dates from the CLI and paths shown with `~`.

use std::path::PathBuf;

/// "12,153".
pub fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// "1 finding" / "40 findings".
pub fn count(n: u64, one: &str, many: &str) -> String {
    format!("{} {}", thousands(n), if n == 1 { one } else { many })
}

/// A file size in decimal units, as a file manager shows it: "512 bytes",
/// "12 KB", "1.9 MB", "91.6 GB".
pub fn file_size(bytes: u64) -> String {
    if bytes < 1000 {
        return if bytes == 1 {
            "1 byte".into()
        } else {
            format!("{bytes} bytes")
        };
    }
    if bytes < 1_000_000 {
        return format!("{} KB", (bytes as f64 / 1000.0).round() as u64);
    }
    let units = ["MB", "GB", "TB", "PB"];
    let mut value = bytes as f64 / 1_000_000.0;
    let mut unit = 0;
    while value >= 999.95 && unit + 1 < units.len() {
        value /= 1000.0;
        unit += 1;
    }
    let text = format!("{value:.1}");
    let text = text.strip_suffix(".0").unwrap_or(&text);
    format!("{text} {}", units[unit])
}

/// "1 h 50 min", "25 min" (never less than a minute).
pub fn duration_left(seconds: f64) -> String {
    let total_minutes = (seconds.max(60.0) / 60.0).floor() as u64;
    if seconds >= 3600.0 {
        let (h, m) = (total_minutes / 60, total_minutes % 60);
        if m == 0 {
            format!("{h} h")
        } else {
            format!("{h} h {m} min")
        }
    } else {
        format!("{total_minutes} min")
    }
}

/// First letter in capitals: "grants access to AWS" -> "Grants access to AWS".
pub fn capitalise_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (
        if m <= 2 {
            yoe + era * 400 + 1
        } else {
            yoe + era * 400
        },
        m,
        d,
    )
}

/// Seconds since 1970 of an RFC 3339 time as the CLI writes it
/// ("2026-11-03T09:30:00Z", with or without fractional seconds or an
/// offset). None for anything else.
pub fn parse_rfc3339(text: &str) -> Option<i64> {
    let t = text.trim();
    let b = t.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    let num = |r: std::ops::Range<usize>| t.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, s) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if b[13] != b':' || b[16] != b':' || !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let mut rest = &t[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        let digits = frac.chars().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 {
            return None;
        }
        rest = &frac[digits..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let oh = rest.get(1..3)?.parse::<i64>().ok()?;
            let om = rest.get(4..6)?.parse::<i64>().ok()?;
            if rest.len() != 6 || rest.as_bytes()[3] != b':' {
                return None;
            }
            sign * (oh * 3600 + om * 60)
        }
    };
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s - offset)
}

/// "3 Nov 2026, 09:30 UTC".
pub fn utc_label(unix: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (y, m, d) = civil_from_days(unix.div_euclid(86_400));
    let secs = unix.rem_euclid(86_400);
    format!(
        "{d} {} {y}, {:02}:{:02} UTC",
        MONTHS[(m - 1) as usize],
        secs / 3600,
        (secs % 3600) / 60
    )
}

/// "just now", "5 minutes ago", "3 hours ago", "yesterday", "4 days ago",
/// then the date.
pub fn relative_time(then: i64, now: i64) -> String {
    let diff = now - then;
    if diff < 60 {
        "just now".into()
    } else if diff < 3600 {
        format!("{} ago", count((diff / 60) as u64, "minute", "minutes"))
    } else if diff < 86_400 {
        format!("{} ago", count((diff / 3600) as u64, "hour", "hours"))
    } else if diff < 2 * 86_400 {
        "yesterday".into()
    } else if diff < 30 * 86_400 {
        format!("{} days ago", diff / 86_400)
    } else {
        utc_label(then)
    }
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The person's home folder.
pub fn home_dir() -> Option<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .or_else(|| std::env::var_os("HOME"))
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

/// `location` with the home folder written as `~`.
pub fn home_abbrev(location: &str) -> String {
    match home_dir() {
        Some(h) => abbrev_with(&h.to_string_lossy(), location),
        None => location.to_string(),
    }
}

/// `location` with `home` written as `~`, only at a folder boundary (so
/// `/Users/al` never shortens `/Users/alice`). Case-insensitive on Windows.
pub fn abbrev_with(home: &str, location: &str) -> String {
    let home = home.trim_end_matches(['/', '\\']);
    if home.is_empty() || location.len() < home.len() {
        return location.to_string();
    }
    let (head, rest) = location.split_at(
        // A multi-byte character at the cut cannot be a match.
        if location.is_char_boundary(home.len()) {
            home.len()
        } else {
            return location.to_string();
        },
    );
    let same = if cfg!(windows) {
        head.eq_ignore_ascii_case(home)
    } else {
        head == home
    };
    if !same {
        return location.to_string();
    }
    if rest.is_empty() {
        "~".into()
    } else if rest.starts_with('/') || rest.starts_with('\\') {
        format!("~{rest}")
    } else {
        location.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_sizes_and_time_left() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(12_153), "12,153");
        assert_eq!(thousands(674_926), "674,926");
        assert_eq!(thousands(1_234_567), "1,234,567");
        assert_eq!(count(1, "finding", "findings"), "1 finding");
        assert_eq!(count(40, "finding", "findings"), "40 findings");
        assert_eq!(file_size(1), "1 byte");
        assert_eq!(file_size(512), "512 bytes");
        assert_eq!(file_size(12_400), "12 KB");
        assert_eq!(file_size(1_900_000), "1.9 MB");
        assert_eq!(file_size(2_000_000), "2 MB");
        assert_eq!(file_size(91_600_000_000), "91.6 GB");
        assert_eq!(file_size(1_500_000_000_000), "1.5 TB");
        assert_eq!(duration_left(10.0), "1 min");
        assert_eq!(duration_left(25.0 * 60.0 + 30.0), "25 min");
        assert_eq!(
            duration_left(3600.0 * 1.0 + 50.0 * 60.0 + 20.0),
            "1 h 50 min"
        );
        assert_eq!(duration_left(7200.0), "2 h");
        assert_eq!(capitalise_first("grants access"), "Grants access");
        assert_eq!(capitalise_first(""), "");
    }

    #[test]
    fn rfc3339_dates() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2026-11-03T09:30:00Z"), Some(1_793_698_200));
        assert_eq!(
            parse_rfc3339("2026-11-03T09:30:00.123456Z"),
            Some(1_793_698_200)
        );
        assert_eq!(
            parse_rfc3339("2026-11-03T10:30:00+01:00"),
            Some(1_793_698_200)
        );
        assert_eq!(parse_rfc3339("2026-11-03"), None);
        assert_eq!(parse_rfc3339("not a date at all!!"), None);
        assert_eq!(utc_label(1_793_698_200), "3 Nov 2026, 09:30 UTC");
        let t = 1_793_698_200;
        assert_eq!(relative_time(t, t + 5), "just now");
        assert_eq!(relative_time(t, t + 60), "1 minute ago");
        assert_eq!(relative_time(t, t + 3 * 3600 + 5), "3 hours ago");
        assert_eq!(relative_time(t, t + 86_400 + 5), "yesterday");
        assert_eq!(relative_time(t, t + 4 * 86_400), "4 days ago");
        assert_eq!(relative_time(t, t + 90 * 86_400), "3 Nov 2026, 09:30 UTC");
    }

    #[test]
    fn home_is_shortened_only_at_a_folder_boundary() {
        assert_eq!(
            abbrev_with("/Users/al", "/Users/al/Documents/x"),
            "~/Documents/x"
        );
        assert_eq!(
            abbrev_with("/Users/al/", "/Users/al/Documents"),
            "~/Documents"
        );
        assert_eq!(abbrev_with("/Users/al", "/Users/al"), "~");
        assert_eq!(abbrev_with("/Users/al", "/Users/alice/x"), "/Users/alice/x");
        assert_eq!(abbrev_with("", "/x"), "/x");
        assert_eq!(abbrev_with("/Users/al", "/tmp"), "/tmp");
        assert_eq!(
            abbrev_with(r"C:\Users\Al", r"C:\Users\Al\Desktop\k.txt"),
            r"~\Desktop\k.txt"
        );
    }
}
