"""LLM 호출 두 가지.

1차 map()    : 취약점 -> ISMS-P 인증기준 선택. 101개 기준 목록 안에서만 고르게 하고, 번호가 목록에 없으면 버린다.
2차 narrow() : 규칙(관련 법규 표)으로 매핑된 조문들 안에서, 진단 근거에 실제로 해당하는 조문·항을 고르고 조문별 이유를 쓴다.
               새 조문을 추가할 수는 없고 걸러내거나 좁히기만 한다 (팀 합의 2026-10-02).
응답은 pydantic 모델(schemas.py)로 받고, 항목별 응답을 cache/ 에 저장해 재실행·시연 때 API 없이도 돌아가게 한다.
"""
import hashlib
import json
import re
import time
from datetime import datetime
from pathlib import Path

from .config import (CACHE_DIR, CRITERIA_FILE, NARROW_PROMPT_VERSION, OPENAI_MODEL, OPENAI_REASONING_EFFORT,
                     PRICE_PER_1M, PROMPT_VERSION)
from .ismsp_loader import IsmsP
from .schemas import IsmsPMapping, ParagraphSelection

CRITERION_ID_RE = re.compile(r'\b([123]\.\d{1,2}\.\d{1,2})\b')


def load_criteria() -> str:
    """팀 공통 판단 기준(criteria.md). 파일이 없으면 빈 문자열."""
    try:
        return CRITERIA_FILE.read_text(encoding='utf-8').strip()
    except OSError:
        return ''


def criteria_block() -> str:
    text = load_criteria()
    return ("\n\n## 판단 기준 (팀 합의, 반드시 따를 것)\n" + text) if text else ''
CIRCLED = '①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳㉑㉒㉓㉔㉕㉖㉗㉘㉙㉚'


def norm_para_label(p) -> str:
    """LLM이 보낸 항 표기를 '제N항'으로 통일. '제3항', '3항', '3', '③' 모두 제3항."""
    s = str(p).strip()
    if s and s[0] in CIRCLED:
        return f"제{CIRCLED.index(s[0]) + 1}항"
    m = re.search(r'\d+', s)
    return f"제{int(m[0])}항" if m else s

SYSTEM_PROMPT = """당신은 ISMS-P(정보보호 및 개인정보보호 관리체계) 인증심사원입니다.
웹 취약점 진단 결과를 보고, 그 취약점이 직접 보여 주는 ISMS-P 인증기준 미충족을 판정합니다.

규칙
1. 반드시 아래에 제공되는 인증기준 목록에 있는 번호만 사용합니다. 목록에 없는 번호나 기준을 만들지 않습니다.
2. 진단 근거에 적힌 사실이 그 기준의 '인증기준' 또는 '주요 확인사항'을 직접 미충족시키는 경우에만 고릅니다. 보통 1개, 많아도 3개입니다. 가장 직접적인 기준 하나를 primary로, 나머지는 secondary로 표시합니다.
3. 다음은 고르지 않습니다.
   - 취약점이 존재한다는 사실만으로 추론한 절차·관리 기준. 예: 2.11.2 취약점 점검 및 조치, 2.8.1 보안 요구사항 정의, 2.8.2 보안 요구사항 검토 및 시험, 1.x 관리체계 기준. 이런 기준은 진단 근거에 "점검을 수행하지 않았다", "요구사항을 정의하지 않았다"처럼 그 절차의 부재가 명시된 경우에만 고릅니다.
   - 3.x 개인정보 처리 단계별 기준 중 수집·동의·목적 외 이용·제3자 제공·보유기간·파기처럼 개인정보처리자의 업무 행위에 관한 기준. 기술적 결함 때문에 권한 없는 사람이 개인정보에 접근할 수 있는 상황은 2.x 보호대책(접근통제, 인증, 권한관리 등)의 미충족이며, 3.x의 '제공'이나 '목적 외 이용'이 아닙니다.
4. 법령이나 조문은 판단하지 않습니다. 인증기준만 고릅니다.
5. reason에는 진단 근거의 어떤 사실이 그 기준의 어떤 요구를 미충족하는지 한국어로 한두 문장으로 씁니다. 진단 근거에 없는 사실을 추측하거나 과장하지 않습니다.
6. 해당하는 기준이 없다고 판단되면 isms_p를 빈 배열로 두고 notes에 이유를 씁니다.
7. 출력은 지정된 JSON 형식만 사용합니다."""

NARROW_PROMPT = """당신은 개인정보 보호 법령에 밝은 정보보호 컨설턴트입니다.
웹 취약점 진단 근거와, 그 취약점에 연결된 ISMS-P 인증기준의 [관련 법규] 조문 원문을 받습니다.
조문마다 진단 근거의 상황이 실제로 그 조문의 의무에 어긋나는지 판단하고, 어긋난다면 어느 항인지 고릅니다.

규칙
1. 제시된 조문(law_code)만 다룹니다. 다른 법령이나 조문을 추가하지 않습니다. 제시된 조문은 빠짐없이 하나씩 판단합니다.
2. 항은 제시된 항 번호 중에서만 "제3항" 형식으로 고릅니다. "항 구분 없음"인 조문은 paragraphs를 빈 목록으로 두고 applicable만 판단합니다.
3. 진단 근거에 적힌 사실이 그 항의 의무와 직접 맞을 때만 고릅니다. "취약점이 있으니 다른 안전조치도 미흡했을 것"이라는 식으로 넓히지 않습니다. 맞는 항이 하나도 없으면 applicable을 false로 합니다.
4. 개인정보의 안전성 확보조치 기준(고시)은 개인정보 보호법 제29조(안전조치의무)를 구체화한 기준입니다. 따라서 고시 조문 중 하나라도 해당하면 제29조도 해당(applicable true)합니다. 제29조처럼 포괄적인 조문을 "구체적이지 않다"는 이유로 빼지 않습니다.
5. reason은 한국어 한두 문장으로, 진단 근거의 어떤 사실이 그 조문(항)의 어떤 의무에 어긋나는지 씁니다. applicable이 false면 왜 해당하지 않는지 씁니다. 진단 근거에 없는 사실을 추측하지 않습니다.
6. 출력은 지정된 JSON 형식만 사용합니다."""


def _finding_block(f: dict) -> str:
    asset = f.get('asset') or {}
    rows = [
        f"- 항목 번호: {f.get('item_id', '')}",
        f"- 항목 이름: {f.get('title', '')}",
        f"- 판정: {f.get('status', '')} (중요도 {f.get('severity', '')})",
        f"- 진단 근거: {f.get('evidence') or '(제공되지 않음)'}",
        f"- 대상 자산: {asset.get('name', '')} / 개인정보 처리 여부: {'예' if asset.get('handles_personal_data') else '아니오 또는 미상'}",
    ]
    return '\n'.join(rows)


def _finding_payload(f: dict) -> dict:
    """캐시 키용: 프롬프트에 들어가는 값만."""
    asset = f.get('asset') or {}
    return {"item_id": f.get('item_id'), "title": f.get('title'), "status": f.get('status'),
            "severity": f.get('severity'), "evidence": f.get('evidence'),
            "asset_name": asset.get('name'), "hpd": asset.get('handles_personal_data')}


class Mapper:
    def __init__(self, ismsp: IsmsP, model: str = OPENAI_MODEL, use_cache: bool = True,
                 offline: bool = False, cache_dir: Path = None, log=print):
        self.ismsp = ismsp
        self.model = model
        self.use_cache = use_cache
        self.offline = offline
        self.cache_dir = Path(cache_dir) if cache_dir else CACHE_DIR   # 호출 시점에 결정 (테스트에서 교체 가능)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.log = log
        self._client = None
        self._criteria_text = ismsp.candidate_text()
        self.calls = 0
        self.cache_hits = 0
        self.prompt_tokens = 0        # 이번 실행에서 실제 호출한 입력 토큰 합
        self.cached_tokens = 0        # 그중 OpenAI 프롬프트 캐시가 적용된 토큰
        self.completion_tokens = 0    # 이번 실행에서 실제 호출한 출력 토큰 합

    def cost_estimate(self):
        """이번 실행의 예상 비용(USD). 가격표에 없는 모델이면 None."""
        price = PRICE_PER_1M.get(self.model) or PRICE_PER_1M.get(self.model.rsplit('-20', 1)[0])
        if not price:
            return None
        in_price, cached_price, out_price = price
        fresh = self.prompt_tokens - self.cached_tokens
        return round((fresh * in_price + self.cached_tokens * cached_price + self.completion_tokens * out_price) / 1e6, 5)

    # ---------------------------------------------------------------- 공통: 캐시, 클라이언트, 호출
    def _cached(self, key: str):
        path = self.cache_dir / f"{key}.json"
        if self.use_cache and path.exists():
            self.cache_hits += 1
            return json.loads(path.read_text(encoding='utf-8'))['response']
        return None

    def _store(self, key: str, raw: dict, usage: dict, extra: dict):
        self.calls += 1
        self.prompt_tokens += usage.get("prompt_tokens", 0)
        self.cached_tokens += usage.get("cached_tokens", 0)
        self.completion_tokens += usage.get("completion_tokens", 0)
        (self.cache_dir / f"{key}.json").write_text(json.dumps({
            "created_at": datetime.now().isoformat(timespec='seconds'), "model": self.model,
            **extra, "usage": usage, "response": raw,
        }, ensure_ascii=False, indent=2), encoding='utf-8')

    @staticmethod
    def _key(payload: dict) -> str:
        # 캐시 파일 이름용 해시 (보안 용도 아님). usedforsecurity=False로 보안 검사 도구 경고를 막는다.
        return hashlib.sha1(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode('utf-8'),
                            usedforsecurity=False).hexdigest()

    @property
    def client(self):
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(max_retries=1)   # 재시도는 _call_llm에서 직접 관리
        return self._client

    def _call_llm(self, messages: list, schema) -> tuple:
        """-> (pydantic 모델을 dict로 푼 응답, usage). 3회 재시도 후 실패하면 RuntimeError."""
        kwargs = dict(model=self.model, messages=messages)
        reasoning_model = self.model.startswith(('gpt-5', 'o1', 'o3', 'o4')) and 'chat' not in self.model
        if not reasoning_model:
            kwargs['temperature'] = 0          # 추론 모델은 temperature를 받지 않음
        elif OPENAI_REASONING_EFFORT:
            kwargs['reasoning_effort'] = OPENAI_REASONING_EFFORT
        last_err = None
        for attempt in range(3):
            try:
                resp, structured = self._create_with_fallback(kwargs, schema)
                u = getattr(resp, 'usage', None)
                details = getattr(u, 'prompt_tokens_details', None) if u else None
                usage = {"prompt_tokens": getattr(u, 'prompt_tokens', 0) or 0,
                         "cached_tokens": getattr(details, 'cached_tokens', 0) or 0,
                         "completion_tokens": getattr(u, 'completion_tokens', 0) or 0} if u else {}
                message = resp.choices[0].message
                if structured:
                    parsed = getattr(message, 'parsed', None)
                    if parsed is None:
                        raise RuntimeError(f"구조화 응답 없음 (거부: {getattr(message, 'refusal', None)})")
                else:   # json_object 폴백: 문자열을 같은 pydantic 모델로 검증
                    parsed = schema.model_validate_json(message.content or '')
                return parsed.model_dump(), usage
            except Exception as e:
                last_err = e
                self.log(f"  [LLM 오류 {attempt + 1}/3] {type(e).__name__}: {str(e)[:160]}")
                time.sleep(2 * (attempt + 1))
        raise RuntimeError(f"LLM 호출 실패: {last_err}")

    def _create_with_fallback(self, kwargs: dict, schema):
        """pydantic 모델로 구조화 출력을 받는다. -> (응답, 구조화 여부)

        모델이 지원하지 않는 옵션이 있으면 그 옵션만 빼고 다시 호출한다:
        temperature 미지원, reasoning_effort 미지원, 구조화 출력 미지원 -> json_object 폴백."""
        kwargs = dict(kwargs)
        structured = True
        for _ in range(4):
            try:
                if structured:
                    return self.client.chat.completions.parse(**kwargs, response_format=schema), True
                return self.client.chat.completions.create(**kwargs, response_format={"type": "json_object"}), False
            except Exception as e:
                msg = str(e)
                if 'temperature' in msg and 'temperature' in kwargs:
                    kwargs.pop('temperature')
                elif 'reasoning_effort' in msg and 'reasoning_effort' in kwargs:
                    kwargs.pop('reasoning_effort')
                elif structured and ('response_format' in msg or 'json_schema' in msg or 'structured' in msg.lower()):
                    structured = False
                else:
                    raise
                self.log(f"  [옵션 조정] {msg[:100]}")
        return self.client.chat.completions.create(**kwargs, response_format={"type": "json_object"}), False

    # ---------------------------------------------------------------- 1차: ISMS-P 기준 선택
    def map(self, f: dict):
        """-> (선택 목록 [{criterion_id, relevance, reason}], 메모 또는 None)"""
        key = self._key({"kind": "map", "model": self.model, "prompt_version": PROMPT_VERSION, **_finding_payload(f)})
        raw = self._cached(key)
        if raw is None:
            if self.offline:
                return [], "오프라인 모드: 캐시된 LLM 응답 없음"
            # 매 호출 똑같은 기준 목록(약 19k 토큰)을 앞에 두고 취약점을 뒤에 둔다.
            # 앞부분이 같으면 OpenAI가 자동으로 프롬프트 캐시를 적용해 입력 단가가 내려간다.
            system = (SYSTEM_PROMPT + criteria_block() +
                      "\n\n## ISMS-P 인증기준 목록 (번호 이름 | 인증기준 요약 | 주요 확인사항 요약)\n" + self._criteria_text)
            user = ("## 취약점 진단 결과\n" + _finding_block(f) +
                    "\n\n위 목록에서 이 취약점이 미충족시키는 기준을 고르세요.")
            raw, usage = self._call_llm([{"role": "system", "content": system}, {"role": "user", "content": user}],
                                        IsmsPMapping)
            self._store(key, raw, usage, {"kind": "map", "prompt_version": PROMPT_VERSION, "finding": f})
        return self._validate(raw)

    def _validate(self, raw):
        picked, seen, dropped = [], set(), []
        if not isinstance(raw, dict):
            return [], f"LLM 응답 형식 오류 (JSON 객체가 아님): {str(raw)[:80]}"
        items = raw.get('isms_p') or []
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                dropped.append(str(item)[:30])
                continue
            text = str(item.get('criterion_id', '')).strip()
            m = CRITERION_ID_RE.search(text)        # "2.5.3 사용자 인증"처럼 이름이 붙어 와도 번호만 취함
            cid = m[1] if m else text
            if cid not in self.ismsp.criteria:
                dropped.append(text)
                continue
            if cid in seen:
                continue
            seen.add(cid)
            picked.append({"criterion_id": cid, "relevance": item.get('relevance', 'secondary'),
                           "reason": (item.get('reason') or '').strip()})
        picked.sort(key=lambda x: 0 if x['relevance'] == 'primary' else 1)
        notes = []
        if dropped:
            notes.append(f"목록에 없는 기준 번호를 LLM이 제시하여 제외함: {', '.join(dropped)}")
        if not picked:
            notes.append("LLM이 해당 기준을 찾지 못함")
            if raw.get('notes'):
                notes.append(f"LLM 메모: {raw['notes']}")
        return picked, (' / '.join(notes) if notes else None)

    # ---------------------------------------------------------------- 2차: 조문 안에서 항 선택
    def narrow(self, f: dict, candidates: list):
        """candidates: [{law_code, law_name, article, title, text, paragraphs: [(라벨, 원문)]}]
        -> ({law_code: {applicable, paragraphs, reason}} 또는 None(판단 불가), 메모 또는 None)"""
        if not candidates:
            return {}, None
        codes = [c['law_code'] for c in candidates]
        key = self._key({"kind": "narrow", "model": self.model, "prompt_version": NARROW_PROMPT_VERSION,
                         "laws": codes, **_finding_payload(f)})
        raw = self._cached(key)
        if raw is None:
            if self.offline:
                return None, "오프라인 모드: 항 판단 캐시 없음 (조문 전체를 유지)"
            raw, usage = self._call_llm([{"role": "system", "content": NARROW_PROMPT + criteria_block()},
                                         {"role": "user", "content": self._narrow_user(f, candidates)}],
                                        ParagraphSelection)
            self._store(key, raw, usage, {"kind": "narrow", "prompt_version": NARROW_PROMPT_VERSION,
                                          "finding": f, "laws": codes})
        return self._validate_narrow(raw, candidates)

    @staticmethod
    def _narrow_user(f: dict, candidates: list) -> str:
        blocks = ["## 취약점 진단 결과", _finding_block(f), "", "## 판단할 조문 (ISMS-P 관련 법규로 매핑된 것)"]
        for c in candidates:
            blocks.append(f"\n### {c['law_code']} | {c['law_name']} {c['article']}({c['title']})")
            if c['paragraphs']:
                for label, body in c['paragraphs']:
                    blocks.append(f"[{label}] {body}")
            else:
                blocks.append("[항 구분 없음] " + c['text'])
        blocks.append("\n위 조문 각각에 대해 진단 근거의 상황이 해당하는지와 해당 항을 고르세요.")
        return '\n'.join(blocks)

    @staticmethod
    def _validate_narrow(raw, candidates: list):
        if not isinstance(raw, dict) or not isinstance(raw.get('laws'), list):
            return None, f"항 판단 응답 형식 오류: {str(raw)[:80]}"
        valid = {c['law_code']: {label for label, _ in c['paragraphs']} for c in candidates}
        result, notes, unknown, bad = {}, [], [], []
        for item in raw['laws']:
            if not isinstance(item, dict):
                continue
            code = str(item.get('law_code', '')).strip()
            if code not in valid:
                unknown.append(code)
                continue
            labels = []
            for p in item.get('paragraphs') or []:
                label = norm_para_label(p)
                if label in valid[code]:
                    if label not in labels:
                        labels.append(label)
                else:
                    bad.append(f"{code} {p}")
            result[code] = {"applicable": bool(item.get('applicable')), "paragraphs": labels,
                            "reason": (item.get('reason') or '').strip()}
        if unknown:
            notes.append(f"제시하지 않은 조문을 LLM이 언급하여 무시함: {', '.join(unknown)}")
        if bad:
            notes.append(f"원문에 없는 항 번호를 LLM이 제시하여 무시함: {', '.join(bad)}")
        missing = [c for c in valid if c not in result]
        if missing:
            notes.append(f"LLM이 판단하지 않은 조문은 전체를 유지함: {', '.join(missing)}")
        return result, (' / '.join(notes) if notes else None)
