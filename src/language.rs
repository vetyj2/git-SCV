//! 경로와 확장자 기반 언어 힌트.
//!
//! 파일 본문을 읽지 않고 후속 깊은 분석 라우팅에 필요한 보수적 힌트만 만든다.

use crate::model::Entry;

pub(crate) fn language_hint(entry: &Entry) -> Option<&'static str> {
    let name = entry.path.rsplit('/').next().unwrap_or(entry.path.as_str());
    match name {
        "Makefile" | "makefile" | "GNUmakefile" => return Some("make"),
        ".envrc" => return Some("shell"),
        _ => {}
    }

    match entry.ext.as_deref()? {
        "bash" | "sh" | "zsh" => Some("shell"),
        "c" => Some("c"),
        "cc" | "cpp" | "cxx" | "hpp" => Some("cpp"),
        "cs" => Some("csharp"),
        "go" => Some("go"),
        "java" => Some("java"),
        "js" | "cjs" | "mjs" | "jsx" => Some("javascript"),
        "json" => Some("json"),
        "kt" | "kts" => Some("kotlin"),
        "php" => Some("php"),
        "ps1" => Some("powershell"),
        "py" | "pyw" => Some("python"),
        "rb" => Some("ruby"),
        "rs" => Some("rust"),
        "swift" => Some("swift"),
        "toml" => Some("toml"),
        "ts" | "tsx" => Some("typescript"),
        "yaml" | "yml" => Some("yaml"),
        _ => None,
    }
}

pub(crate) fn is_deep_analysis_candidate(language_hint: Option<&str>) -> bool {
    matches!(
        language_hint,
        Some(
            "c" | "cpp"
                | "csharp"
                | "go"
                | "java"
                | "javascript"
                | "kotlin"
                | "make"
                | "php"
                | "powershell"
                | "python"
                | "ruby"
                | "rust"
                | "shell"
                | "swift"
                | "typescript"
        )
    )
}
