//! 사용자용 오류와 종료 코드 매핑.

#[derive(Debug)]
pub enum ScvError {
    /// 종료 코드 2 — 메시지는 사양 0100 4절의 U01–U05 문구 그대로.
    Usage(String),
    /// 종료 코드 3 — "<단계이름>: <사유>" 형식으로 담는다.
    Inspect(String),
    /// 종료 코드 4 — 실패한 검증 문자열(V01…) 목록.
    Validation(Vec<String>),
}

impl ScvError {
    pub fn exit_code(&self) -> i32 {
        match self {
            ScvError::Usage(_) => 2,
            ScvError::Inspect(_) => 3,
            ScvError::Validation(_) => 4,
        }
    }

    pub fn user_message(&self) -> String {
        match self {
            ScvError::Usage(msg) => msg.clone(),
            ScvError::Inspect(msg) => format!("오류: 검사 실패({msg})"),
            ScvError::Validation(items) => {
                let ids: Vec<&str> = items
                    .iter()
                    .map(|s| s.split(':').next().unwrap_or(s.as_str()))
                    .collect();
                format!("오류: 산출물 검증 실패: {}", ids.join(", "))
            }
        }
    }
}
