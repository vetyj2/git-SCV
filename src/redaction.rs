//! Shared redaction helpers for data that can reach artifacts or user-facing
//! errors.
//!
//! The goal is to make raw untrusted values pass through one policy before they
//! are stored or displayed. P0/P1 artifact contract work should prefer the
//! typed wrappers here over plain `String` fields.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawUntrusted(String);

impl RawUntrusted {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactSafeString(String);

impl ArtifactSafeString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoRelativePath(ArtifactSafeString);

impl RepoRelativePath {
    pub fn new(value: impl Into<String>) -> Self {
        Self(ArtifactSafeString::new(value))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathPrivacyMode {
    RepoRelative,
    RedactedAbsolute,
    Absolute,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecretLikeLabel {
    UrlUserinfo,
    UrlQuery,
    UrlFragment,
    TokenLike,
    BearerLike,
    KeyLike,
    CredentialLike,
    AuthorizationHeaderLike,
    PrivateRegistryLike,
    NetworkCommand,
    ShellExecutionToken,
}

impl SecretLikeLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            SecretLikeLabel::UrlUserinfo => "url-userinfo",
            SecretLikeLabel::UrlQuery => "url-query",
            SecretLikeLabel::UrlFragment => "url-fragment",
            SecretLikeLabel::TokenLike => "token-like",
            SecretLikeLabel::BearerLike => "bearer-like",
            SecretLikeLabel::KeyLike => "key-like",
            SecretLikeLabel::CredentialLike => "credential-like",
            SecretLikeLabel::AuthorizationHeaderLike => "authorization-header-like",
            SecretLikeLabel::PrivateRegistryLike => "private-registry-like",
            SecretLikeLabel::NetworkCommand => "network-command",
            SecretLikeLabel::ShellExecutionToken => "shell-execution-token",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redacted {
    value: ArtifactSafeString,
    labels: Vec<SecretLikeLabel>,
}

impl Redacted {
    fn new(value: String, mut labels: Vec<SecretLikeLabel>) -> Self {
        labels.sort();
        labels.dedup();
        Self {
            value: ArtifactSafeString::new(value),
            labels,
        }
    }

    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }

    pub fn into_string(self) -> String {
        self.value.into_string()
    }

    pub fn labels(&self) -> &[SecretLikeLabel] {
        &self.labels
    }

    pub fn label_strings(&self) -> Vec<String> {
        self.labels
            .iter()
            .map(|label| label.as_str().into())
            .collect()
    }

    pub fn redaction_applied(&self) -> bool {
        !self.labels.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactedUrl(Redacted);

impl RedactedUrl {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn into_string(self) -> String {
        self.0.into_string()
    }

    pub fn labels(&self) -> &[SecretLikeLabel] {
        self.0.labels()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactedCommandArg(Redacted);

impl RedactedCommandArg {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn into_string(self) -> String {
        self.0.into_string()
    }

    pub fn labels(&self) -> &[SecretLikeLabel] {
        self.0.labels()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactedExcerpt(Redacted);

impl RedactedExcerpt {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn into_string(self) -> String {
        self.0.into_string()
    }

    pub fn labels(&self) -> &[SecretLikeLabel] {
        self.0.labels()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgRole {
    ArchiveUrl,
    Path,
    Sha256,
    Other,
}

pub fn redact_url_for_error(value: &str) -> String {
    redact_url(value, QueryFragmentPolicy::Placeholder).into_string()
}

pub fn redact_url_for_artifact(value: &str) -> RedactedUrl {
    RedactedUrl(redact_url(value, QueryFragmentPolicy::Remove))
}

pub fn redact_remote_url(value: &str) -> String {
    redact_url_for_artifact(value).into_string()
}

pub fn strip_url_query_fragment(value: &str) -> &str {
    value
        .split_once('#')
        .map_or(value, |(before_fragment, _)| before_fragment)
        .split_once('?')
        .map_or_else(
            || {
                value
                    .split_once('#')
                    .map_or(value, |(before_fragment, _)| before_fragment)
            },
            |(before_query, _)| before_query,
        )
}

pub fn url_has_userinfo(value: &str) -> bool {
    let Some((_scheme, after_scheme)) = value.split_once("://") else {
        return false;
    };
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    authority.contains('@')
}

pub fn redact_cli_arg(value: &str, role: ArgRole) -> RedactedCommandArg {
    match role {
        ArgRole::ArchiveUrl => RedactedCommandArg(redact_url(value, QueryFragmentPolicy::Tag)),
        ArgRole::Path => RedactedCommandArg(Redacted::new("<path>".into(), Vec::new())),
        ArgRole::Sha256 => RedactedCommandArg(Redacted::new("<sha256>".into(), Vec::new())),
        ArgRole::Other => RedactedCommandArg(redact_token_like_text(value)),
    }
}

pub fn redact_command_excerpt(value: &str) -> RedactedExcerpt {
    let mut labels = redaction_labels(value);
    let mut redacted = redact_urls_in_text(value, &mut labels);
    redacted = redact_authorization_header(&redacted, &mut labels);
    redacted = redact_secret_assignments(&redacted, &mut labels);
    RedactedExcerpt(Redacted::new(redacted, labels))
}

pub fn redact_token_like_text(value: &str) -> Redacted {
    let mut labels = redaction_labels(value);
    let mut redacted = redact_authorization_header(value, &mut labels);
    redacted = redact_secret_assignments(&redacted, &mut labels);
    Redacted::new(redacted, labels)
}

pub fn redaction_labels(value: &str) -> Vec<SecretLikeLabel> {
    let mut labels = Vec::new();
    let lower = value.to_ascii_lowercase();
    if url_has_userinfo(value) || scp_like_userinfo_parts(value).is_some() {
        labels.push(SecretLikeLabel::UrlUserinfo);
    }
    if value.contains('?') {
        labels.push(SecretLikeLabel::UrlQuery);
    }
    if value.contains('#') {
        labels.push(SecretLikeLabel::UrlFragment);
    }
    if contains_any(
        &lower,
        &[
            "token=",
            "access_token",
            "auth_token",
            "_authtoken",
            "x-auth-token",
            "ghp_",
            "github_pat_",
        ],
    ) {
        labels.push(SecretLikeLabel::TokenLike);
    }
    if lower.contains("bearer ") {
        labels.push(SecretLikeLabel::BearerLike);
    }
    if contains_any(
        &lower,
        &[
            "apikey",
            "api_key",
            "private_key",
            "secret_key",
            "client_secret",
        ],
    ) {
        labels.push(SecretLikeLabel::KeyLike);
    }
    if contains_any(
        &lower,
        &["password=", "passwd=", "credential", "credentials"],
    ) {
        labels.push(SecretLikeLabel::CredentialLike);
    }
    if lower.contains("authorization:") {
        labels.push(SecretLikeLabel::AuthorizationHeaderLike);
    }
    if contains_any(&lower, &["_authtoken", "npmrc", "registry.npmjs.org/:"]) {
        labels.push(SecretLikeLabel::PrivateRegistryLike);
    }
    if contains_any(&lower, &["curl ", "wget ", "http://", "https://"]) {
        labels.push(SecretLikeLabel::NetworkCommand);
    }
    if contains_any(
        &lower,
        &[" sh ", " bash ", " | sh", " | bash", "&&", ";", "$("],
    ) {
        labels.push(SecretLikeLabel::ShellExecutionToken);
    }
    labels.sort();
    labels.dedup();
    labels
}

#[derive(Clone, Copy)]
enum QueryFragmentPolicy {
    Remove,
    Placeholder,
    Tag,
}

fn redact_url(value: &str, policy: QueryFragmentPolicy) -> Redacted {
    let mut labels = Vec::new();
    let (without_fragment, had_fragment) = match value.split_once('#') {
        Some((before, _)) => {
            labels.push(SecretLikeLabel::UrlFragment);
            (before, true)
        }
        None => (value, false),
    };
    let (without_query, had_query) = match without_fragment.split_once('?') {
        Some((before, _)) => {
            labels.push(SecretLikeLabel::UrlQuery);
            (before, true)
        }
        None => (without_fragment, false),
    };

    let mut redacted = redact_url_userinfo(without_query, &mut labels)
        .or_else(|| redact_scp_like_userinfo(without_query, &mut labels))
        .unwrap_or_else(|| without_query.into());

    match policy {
        QueryFragmentPolicy::Remove => {}
        QueryFragmentPolicy::Placeholder => {
            if had_query {
                redacted.push_str("?...");
            }
            if had_fragment {
                redacted.push_str("#...");
            }
        }
        QueryFragmentPolicy::Tag => {
            if had_query || had_fragment || labels.contains(&SecretLikeLabel::UrlUserinfo) {
                redacted = "<archive-url:redacted-userinfo-query-fragment>".into();
            }
        }
    }

    Redacted::new(redacted, labels)
}

fn redact_url_userinfo(value: &str, labels: &mut Vec<SecretLikeLabel>) -> Option<String> {
    let (scheme, after_scheme) = value.split_once("://")?;
    let authority_start = scheme.len() + "://".len();
    let path_start = after_scheme
        .find('/')
        .map_or(value.len(), |offset| authority_start + offset);
    let authority = &value[authority_start..path_start];
    let (_userinfo, host) = authority.rsplit_once('@')?;
    labels.push(SecretLikeLabel::UrlUserinfo);
    Some(format!("{}://***@{}{}", scheme, host, &value[path_start..]))
}

fn redact_scp_like_userinfo(value: &str, labels: &mut Vec<SecretLikeLabel>) -> Option<String> {
    let (_userinfo, host, repo_part) = scp_like_userinfo_parts(value)?;
    labels.push(SecretLikeLabel::UrlUserinfo);
    Some(format!("***@{}:{}", host, repo_part))
}

fn scp_like_userinfo_parts(value: &str) -> Option<(&str, &str, &str)> {
    let (user_host, repo_part) = value.split_once(':')?;
    let (userinfo, host) = user_host.rsplit_once('@')?;
    if userinfo.is_empty() || host.is_empty() || repo_part.is_empty() {
        return None;
    }
    if userinfo.contains('/') || host.contains('/') {
        return None;
    }
    Some((userinfo, host, repo_part))
}

fn redact_urls_in_text(value: &str, labels: &mut Vec<SecretLikeLabel>) -> String {
    value
        .split_whitespace()
        .map(|token| redact_url_token(token, labels))
        .collect::<Vec<_>>()
        .join(" ")
}

fn redact_url_token(token: &str, labels: &mut Vec<SecretLikeLabel>) -> String {
    let leading_len = token
        .char_indices()
        .find(|(_, ch)| ch.is_ascii_alphanumeric())
        .map_or(token.len(), |(idx, _)| idx);
    let trailing_start = token
        .char_indices()
        .rev()
        .find(|(_, ch)| {
            ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '-' | '_' | '=' | '&' | '%')
        })
        .map_or(leading_len, |(idx, ch)| idx + ch.len_utf8());
    let (leading, rest) = token.split_at(leading_len);
    let (core, trailing) = rest.split_at(trailing_start.saturating_sub(leading_len));
    if !(core.contains("://") || scp_like_userinfo_parts(core).is_some()) {
        return token.into();
    }

    let redacted = redact_url(core, QueryFragmentPolicy::Placeholder);
    labels.extend_from_slice(redacted.labels());
    format!("{leading}{}{trailing}", redacted.as_str())
}

fn redact_authorization_header(value: &str, labels: &mut Vec<SecretLikeLabel>) -> String {
    value
        .lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if let Some(index) = lower.find("authorization:") {
                labels.push(SecretLikeLabel::AuthorizationHeaderLike);
                let prefix = &line[..index + "authorization:".len()];
                format!("{prefix} <redacted>")
            } else if lower.contains("bearer ") {
                labels.push(SecretLikeLabel::BearerLike);
                replace_after_marker(line, "Bearer ", "<redacted-bearer>")
            } else {
                line.into()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn redact_secret_assignments(value: &str, labels: &mut Vec<SecretLikeLabel>) -> String {
    value
        .split_whitespace()
        .map(|token| {
            let lower = token.to_ascii_lowercase();
            if contains_any(
                &lower,
                &[
                    "token=",
                    "access_token=",
                    "auth_token=",
                    "_authtoken=",
                    "password=",
                    "passwd=",
                    "api_key=",
                    "apikey=",
                    "secret=",
                    "client_secret=",
                ],
            ) {
                if lower.contains("token") {
                    labels.push(SecretLikeLabel::TokenLike);
                }
                if lower.contains("password") || lower.contains("passwd") {
                    labels.push(SecretLikeLabel::CredentialLike);
                }
                if lower.contains("key") || lower.contains("secret") {
                    labels.push(SecretLikeLabel::KeyLike);
                }
                redact_assignment_token(token)
            } else if lower.starts_with("ghp_") || lower.starts_with("github_pat_") {
                labels.push(SecretLikeLabel::TokenLike);
                "<redacted-token>".into()
            } else {
                token.into()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn redact_assignment_token(token: &str) -> String {
    let Some((name, _value)) = token.split_once('=') else {
        return "<redacted>".into();
    };
    format!("{name}=<redacted>")
}

fn replace_after_marker(line: &str, marker: &str, replacement: &str) -> String {
    let Some(index) = line.find(marker) else {
        return line.into();
    };
    format!("{}{}", &line[..index + marker.len()], replacement)
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::{
        redact_cli_arg, redact_command_excerpt, redact_remote_url, redact_url_for_artifact,
        redact_url_for_error, ArgRole, SecretLikeLabel,
    };

    #[test]
    fn url_userinfo_query_and_fragment_are_redacted_for_artifacts() {
        let redacted = redact_url_for_artifact(
            "https://user:secret@example.invalid/archive.zip?token=abc#frag",
        );
        assert_eq!(redacted.as_str(), "https://***@example.invalid/archive.zip");
        assert!(redacted.labels().contains(&SecretLikeLabel::UrlUserinfo));
        assert!(redacted.labels().contains(&SecretLikeLabel::UrlQuery));
        assert!(redacted.labels().contains(&SecretLikeLabel::UrlFragment));
    }

    #[test]
    fn url_redaction_for_errors_keeps_shape_without_raw_query() {
        let redacted =
            redact_url_for_error("https://token@example.invalid/file.txt?query-marker=value#frag");
        assert_eq!(redacted, "https://***@example.invalid/file.txt?...#...");
        assert!(!redacted.contains("token@"));
        assert!(!redacted.contains("query-marker"));
    }

    #[test]
    fn scp_like_remote_userinfo_is_redacted() {
        assert_eq!(
            redact_remote_url("git@example.invalid:org/repo.git"),
            "***@example.invalid:org/repo.git"
        );
    }

    #[test]
    fn archive_cli_arg_uses_contract_placeholder_when_sensitive() {
        let redacted = redact_cli_arg(
            "https://example.invalid/archive.zip?token=GIT_SCV_FAKE_TOKEN_DO_NOT_USE#frag",
            ArgRole::ArchiveUrl,
        );
        assert_eq!(
            redacted.as_str(),
            "<archive-url:redacted-userinfo-query-fragment>"
        );
    }

    #[test]
    fn command_excerpt_redacts_url_query_and_token_like_values() {
        let redacted = redact_command_excerpt(
            "curl https://example.invalid/install.sh?token=abc -H 'Authorization: Bearer abc'",
        );
        assert!(!redacted.as_str().contains("token=abc"));
        assert!(!redacted.as_str().contains("Bearer abc"));
        assert!(redacted.labels().contains(&SecretLikeLabel::UrlQuery));
        assert!(redacted.labels().contains(&SecretLikeLabel::TokenLike));
        assert!(redacted
            .labels()
            .contains(&SecretLikeLabel::AuthorizationHeaderLike));
    }
}
