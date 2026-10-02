"""모듈 3 데이터 계약 (pydantic v2).

- IsmsPMapping : LLM 구조화 출력. OpenAI `chat.completions.parse(response_format=IsmsPMapping)`에 그대로 넘긴다.
- ScanInput    : 판정 모듈 -> 모듈 3 입력. 모르는 필드는 허용(extra="allow")해서 그쪽이 필드를 늘려도 깨지지 않는다.
- ModuleOutput : 모듈 3 -> 보고서 모듈 출력. 필드가 정확히 고정(extra="forbid")되어 구조가 어긋나면 실행 단계에서 바로 드러난다.

보고서 모듈 쪽에서는 이 파일을 import 해서
    ModuleOutput.model_validate_json(Path("output.json").read_text(encoding="utf-8"))
로 읽으면 타입이 보장된 객체로 받을 수 있다. JSON 스키마 파일은 `python -m module3 schema`로 뽑는다.
"""
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


# ------------------------------------------------------------------ LLM 응답
class IsmsPPick(BaseModel):
    criterion_id: str = Field(description="ISMS-P 인증기준 번호. 예: 2.6.6")
    relevance: Literal["primary", "secondary"] = Field(description="가장 직접적인 기준 하나만 primary")
    reason: str = Field(description="진단 근거의 어떤 사실이 이 기준의 어떤 요구를 미충족하는지 한두 문장")


class IsmsPMapping(BaseModel):
    isms_p: list[IsmsPPick]
    notes: str = Field(description="특이사항. 없으면 빈 문자열")


class ParagraphPick(BaseModel):
    """2차 호출: 규칙으로 매핑된 조문 하나에 대해, 진단 근거의 상황에 해당하는지와 해당 항."""
    law_code: str = Field(description="제시된 조문 코드 그대로. 예: SAFE-6")
    applicable: bool = Field(description="진단 근거의 상황이 이 조문의 의무에 실제로 어긋나면 true")
    paragraphs: list[str] = Field(description='해당하는 항 번호 목록. 예: ["제3항"]. 항 구분이 없는 조문이거나 applicable이 false면 빈 목록')
    reason: str = Field(description="진단 근거의 어떤 사실이 이 조문(항)의 어떤 의무에 어긋나는지 한두 문장. 해당 없으면 그 이유")


class ParagraphSelection(BaseModel):
    laws: list[ParagraphPick]
    notes: str = Field(description="특이사항. 없으면 빈 문자열")


# ------------------------------------------------------------------ 입력 (판정 모듈 -> 모듈 3)
class Asset(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: Optional[str] = None
    name: Optional[str] = None
    handles_personal_data: Optional[bool] = None


class InputFinding(BaseModel):
    model_config = ConfigDict(extra="allow")
    finding_id: Optional[str] = None
    item_id: str
    title: str
    status: str                      # 취약 / 양호 / 수동확인 (그 외 값은 매핑하지 않고 통과)
    severity: Optional[str] = None
    asset: Optional[Asset] = None
    evidence: Optional[str] = None


class ScanInput(BaseModel):
    model_config = ConfigDict(extra="allow")
    scan_id: str
    scan_date: Optional[str] = None
    target_system: Optional[str] = None
    findings: list[InputFinding]


# ------------------------------------------------------------------ 출력 (모듈 3 -> 보고서 모듈)
class Reference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ref_id: str
    title: str
    type: str
    version: Optional[str]
    effective_date: Optional[str]
    source_file: Optional[str]


class ViolatedLaw(BaseModel):
    model_config = ConfigDict(extra="forbid")
    law_code: Optional[str]          # 법령키-조번호. PIPA-29, SAFE-6, PIPA-28의2
    ref_id: Optional[str]            # references[].ref_id
    law_name: str
    article: Optional[str]           # 제29조
    paragraph: Optional[str]         # 제1항 등. 현재는 항 단위 매핑을 하지 않아 null
    article_title: Optional[str]
    text: Optional[str]              # 조문 전체 원문. 원문 미보유 법령은 null
    in_force: Optional[bool]         # 현행본 true, 시행 예정 false, 원문 없음 null
    mapped_by: Literal["rule", "rule+llm", "llm"]   # rule: 관련 법규 표 / rule+llm: 표에서 고른 조문 안에서 LLM이 항 선택
    reviewed: bool
    reason: str
    review_note: Optional[str] = None   # 문제가 있을 때만 존재


class IsmsPCriterion(BaseModel):
    model_config = ConfigDict(extra="forbid")
    criterion_id: str
    ref_id: str
    title: str
    text: str                        # 인증기준 본문
    mapped_by: Literal["llm", "rule"]
    reviewed: bool
    reason: str


class OutputFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_id: str
    item_id: Optional[str]
    title: Optional[str]
    status: Optional[str]
    severity: Optional[str]
    asset: Optional[dict]
    evidence: Optional[str]          # 정식 필드 (항상 존재). 판정 모듈이 준 진단 근거 그대로
    violated_laws: list[ViolatedLaw]
    isms_p: list[IsmsPCriterion]
    review_note: Optional[str] = None


class TokenUsage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prompt: int
    prompt_cached: int
    completion: int
    estimated_cost_usd: Optional[float]


class MappingInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: str                      # "llm+rule"
    model: str
    prompt_version: str
    generated_at: str
    llm_calls: int
    cache_hits: int
    tokens: TokenUsage


class ModuleOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str
    scan_id: str
    scan_date: Optional[str]
    target_system: Optional[str]
    mapping: MappingInfo
    references: list[Reference]
    findings: list[OutputFinding]
