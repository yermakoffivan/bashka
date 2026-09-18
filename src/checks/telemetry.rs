use crate::analysis::Flag;
use crate::config::{NoConfig, Shared};
use crate::model::{Detail, Span, Verdict};
use crate::parser::{Command, Ctx};
use crate::register_flag;
use crate::url;

pub struct Telemetry {
    shared: Shared,
    /// The first phone-home: destination, span, the machine details it carries, and the
    /// opt-out variable its guard tests.
    home: Option<(String, Span, Vec<&'static str>, Option<String>)>,
    /// A generated identifier is saved to disk, so runs can be correlated.
    identifier: Option<Span>,
}

const HINTS: &[&str] = &[
    "telemetry",
    "analytics",
    "metrics",
    "track",
    "beacon",
    "collect",
    "stats",
    "event",
    "ping",
];

const FINGERPRINTS: &[(&str, &str)] = &[
    ("uname", "OS and architecture"),
    ("hostname", "hostname"),
    ("whoami", "user name"),
    ("id -u", "user id"),
    ("sw_vers", "macOS version"),
    ("lsb_release", "distro"),
    ("ifconfig", "network interfaces"),
    ("ip addr", "network interfaces"),
];

/// Fragments of variable names that switch reporting off: `BEND_NO_TELEMETRY`, `DO_NOT_TRACK`.
const OPT_OUT_HINTS: &[&str] = &[
    "TELEMETRY",
    "ANALYTICS",
    "DO_NOT_TRACK",
    "TRACKING",
    "NO_TRACK",
    "OPT_OUT",
    "OPTOUT",
    "NO_STATS",
    "METRICS",
];

/// The guard around the request that looks like a telemetry switch: the request only runs
/// under a condition testing `BEND_NO_TELEMETRY`, `DO_NOT_TRACK`, and the like.
fn opt_out_variable(c: &Command) -> Option<String> {
    c.guards
        .iter()
        .find(|name| {
            let upper = name.to_ascii_uppercase();
            OPT_OUT_HINTS.iter().any(|h| upper.contains(h))
        })
        .cloned()
}

fn uploads(c: &Command) -> bool {
    match crate::config::base_name(&c.name) {
        "curl" => {
            let args: Vec<&str> = c.arg_texts().collect();
            args.iter().enumerate().any(|(i, a)| {
                matches!(
                    *a,
                    "-d" | "--data" | "--data-raw" | "--data-binary" | "-F" | "--form"
                ) || a.starts_with("-d")
                    // `-X HEAD` / `-X GET` probe; only a writing method counts.
                    || (matches!(*a, "-X" | "--request")
                        && args
                            .get(i + 1)
                            .is_some_and(|m| matches!(m.to_ascii_uppercase().as_str(), "POST" | "PUT" | "PATCH")))
            })
        }
        "wget" => c
            .arg_texts()
            .any(|a| a.starts_with("--post-data") || a.starts_with("--post-file")),
        _ => false,
    }
}

/// `analytics.x.io/collect`, `x.io/install-event`: a hint as a whole host label or path word.
/// Expansions are dropped first so `pkgs.x.com/$TRACK/…` does not read as tracking.
fn looks_like_telemetry(url: &str) -> bool {
    let mut stripped = String::new();
    let mut rest = url;
    while let Some(i) = rest.find('$') {
        stripped.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let len = if after.starts_with('{') {
            after.find('}').map_or(after.len(), |j| j + 1)
        } else {
            after
                .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                .unwrap_or(after.len())
        };
        rest = &after[len..];
    }
    stripped.push_str(rest);
    stripped
        .to_ascii_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|word| HINTS.contains(&word))
}

/// Where the request goes: a literal URL, else the `$ORIGIN/ping`-style operand.
fn destination(c: &Command) -> Option<String> {
    if let Some(u) = c.urls().find(|u| uploads(c) || looks_like_telemetry(u)) {
        return Some(url::host(u).unwrap_or_else(|| u.to_string()));
    }
    if !uploads(c) {
        return None;
    }
    let args: Vec<&str> = c.arg_texts().collect();
    let mut skip = false;
    for (i, a) in args.iter().enumerate() {
        if skip {
            skip = false;
            continue;
        }
        if a.starts_with('-') {
            // Options that consume the next word.
            skip = matches!(
                *a,
                "-X" | "--request"
                    | "-d"
                    | "--data"
                    | "--data-raw"
                    | "--data-binary"
                    | "-F"
                    | "--form"
                    | "-H"
                    | "--header"
                    | "-o"
                    | "--output"
                    | "-A"
                    | "--user-agent"
                    | "--max-time"
                    | "--connect-timeout"
                    | "--retry"
                    | "-u"
                    | "--user"
            ) && args.get(i + 1).is_some();
            continue;
        }
        if a.contains('$') || a.contains('/') {
            return Some((*a).to_string());
        }
    }
    None
}

fn fingerprints(c: &Command) -> Vec<&'static str> {
    let mut out = Vec::new();
    for w in &c.args {
        for (probe, what) in FINGERPRINTS {
            let sub = format!("$({probe}");
            let tick = format!("`{probe}");
            if (w.text.contains(&sub) || w.text.contains(&tick)) && !out.contains(what) {
                out.push(*what);
            }
        }
    }
    out
}

/// `uuidgen > "$DIR/id"`, `cat /proc/sys/kernel/random/uuid > id`, `id=$(uuidgen)`: an
/// installer has no other reason to mint a UUID.
fn mints_identifier(c: &Command) -> bool {
    match crate::config::base_name(&c.name) {
        "uuidgen" => true,
        "cat" | "head" => c
            .arg_texts()
            .any(|a| a.ends_with("/proc/sys/kernel/random/uuid")),
        _ => false,
    }
}

impl Flag for Telemetry {
    fn visit_command(&mut self, c: &Command) -> Verdict {
        if self.identifier.is_none() && mints_identifier(c) {
            self.identifier = Some(c.span.clone());
        }
        if self.home.is_none()
            && self.shared.is_network(&c.name)
            && let Some(dest) = destination(c)
        {
            self.home = Some((dest, c.span.clone(), fingerprints(c), opt_out_variable(c)));
        }
        Verdict::Ignore
    }

    fn finalize(&mut self, _ctx: &Ctx) -> Verdict {
        let Some((dest, span, facts, opt_out)) = self.home.take() else {
            return Verdict::Ignore;
        };
        let mut title = format!("phones home to `{dest}`");
        if !facts.is_empty() {
            title.push_str(" with your ");
            title.push_str(&facts.join(", "));
        }
        let mut explanation = String::from(
            "The installer reports something about you or this machine; check what is sent and whether it can be disabled.",
        );
        if self.identifier.is_some() {
            title.push_str(" under a persistent identifier");
            explanation.push_str(
                " A generated id is written to disk, so every later report from this machine can be linked together.",
            );
        }
        let fix = match &opt_out {
            Some(var) => {
                title.push_str(" (opt out: `");
                title.push_str(var);
                title.push_str("`)");
                format!(
                    "The request only runs when `{var}` is unset; set it before running (`{var}=1 curl … | bashka`) to keep the report from being sent."
                )
            }
            None => {
                "Nothing guards this request, so the report is sent unconditionally.".to_string()
            }
        };
        Verdict::Red(Detail::new(title, explanation).fix(fix).at(span))
    }
}

register_flag! {
    id: "telemetry",
    kind: Red,
    category: Remote,
    description: "Sends data out (POST/--data, or telemetry/analytics URLs), fingerprints the machine, or saves a tracking id",
    config: NoConfig,
    build: |_cfg, shared| Telemetry { shared: shared.clone(), home: None, identifier: None },
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;

    #[test]
    fn detects_uploads_and_analytics_urls() {
        assert!(fires(
            "telemetry",
            "curl -s -X POST -d \"os=$OS\" https://x.io/install-event"
        ));
        assert!(fires(
            "telemetry",
            "curl -fsSL https://analytics.x.io/collect?v=1 -o /dev/null"
        ));
        assert!(!fires(
            "telemetry",
            "curl -fsSL https://x.io/releases/t.tgz -o t.tgz"
        ));
    }

    #[test]
    fn keywords_must_be_whole_words_outside_expansions() {
        assert!(!fires(
            "telemetry",
            "curl -fsSL \"https://pkgs.tailscale.com/$TRACK/$OS/$VERSION/tailscale.repo\" > /etc/yum.repos.d/tailscale.repo"
        ));
        assert!(!fires(
            "telemetry",
            "curl -fsSL https://x.io/tracker-tool/latest.tgz -o t.tgz"
        ));
        assert!(fires(
            "telemetry",
            "curl -fsSL \"https://x.io/ping?v=$VERSION\""
        ));
    }

    #[test]
    fn sees_through_variable_destinations() {
        let t = titles(
            "telemetry",
            "O=${ORIGIN:-https://x.io}\ncurl -s --max-time 3 -H 'Content-Type: application/json' \"$O/ping\" -d \"{\\\"os\\\":\\\"$(uname -s)\\\",\\\"arch\\\":\\\"$(uname -m)\\\"}\"",
        );
        assert_eq!(
            t,
            ["phones home to `$O/ping` with your OS and architecture"]
        );
        assert!(!fires(
            "telemetry",
            "curl -fsSL \"$BASE/$VERSION/tool.tgz\" -o t.tgz"
        ));
        assert!(
            !fires("telemetry", "curl -o /dev/null -fsLI -X HEAD \"$1\""),
            "a HEAD probe sends nothing"
        );
    }

    #[test]
    fn names_the_opt_out_variable() {
        let f = findings(
            "telemetry",
            "[ -n \"${BEND_NO_TELEMETRY:-}\" ] || curl -d \"os=$(uname -s)\" https://x.io/ping",
        );
        assert_eq!(
            f[0].detail.title,
            "phones home to `x.io` with your OS and architecture (opt out: `BEND_NO_TELEMETRY`)"
        );
        assert!(
            f[0].detail
                .fix
                .as_deref()
                .unwrap()
                .contains("BEND_NO_TELEMETRY=1")
        );
        let f = findings("telemetry", "curl -d \"os=$OS\" https://x.io/ping");
        assert!(
            f[0].detail
                .fix
                .as_deref()
                .unwrap()
                .contains("Nothing guards")
        );
        let f = findings(
            "telemetry",
            "NO_TELEMETRY=${NO_TELEMETRY:-0}\ncurl -d \"os=$OS\" https://x.io/ping",
        );
        assert!(
            f[0].detail
                .fix
                .as_deref()
                .unwrap()
                .contains("Nothing guards"),
            "a variable that is mentioned but never tested around the request is no opt-out"
        );
    }

    #[test]
    fn notes_a_persistent_identifier() {
        let t = titles(
            "telemetry",
            "{ cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen; } > \"$B/id\"\ncurl -d \"id=$(cat \"$B/id\")\" https://x.io/ping",
        );
        assert_eq!(t, ["phones home to `x.io` under a persistent identifier"]);
        assert!(
            !fires("telemetry", "uuidgen > \"$B/id\""),
            "an id that is never sent is not telemetry"
        );
    }
}
