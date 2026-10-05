"""
보고서 엔진 — 진단 JSON 1개 → LLM 1회 호출 → 경영진용 PDF + 실무진용 PDF

  1) load      scan.json(진단 결과) + context.json(조직 맥락) + cases.json(사례 카드) + item_catalog.json(항목 기준)
  2) facts     통계, 전체 위험 수준, 사례 검색(case_kb), 노출액 계산(exposure)을 코드로 (LLM 안 씀)
  3) llm       딱 한 번 호출. 판정은 이미 끝났고, LLM은 '문장'만 쓴다
  4) validate  LLM이 언급한 ID가 실제 데이터에 있는지 검사하고, 없는 건 버린다
  5) render    같은 데이터로 템플릿 2개 → HTML → PDF

사용법
  python engine.py --mock                         # LLM 없이 샘플 출력으로 렌더링
  python engine.py                                # 실제 LLM 호출 (.env의 OPENAI_API_KEY 또는 ANTHROPIC_API_KEY)
  python engine.py --llm-output out/llm_output.json   # 저장된 LLM 출력 재사용 (템플릿만 고칠 때)
"""
import argparse
import json
import os
import re
import sys
from datetime import date
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup, escape

import case_kb
import exposure

BASE = Path(__file__).resolve().parent
SEV_ORDER = {"상": 0, "중": 1, "하": 2}
SEV_CLASS = {"상": "h", "중": "m", "하": "l"}
PHASES = [("즉시", "1주 이내"), ("단기", "1개월 이내"), ("중기", "분기 이내")]
# 빨강은 '꼭 봐야 하는 것'에만: 심각·높음 = 빨강, 보통 = 진한 주황, 낮음 = 회색
RISK_COLORS = {"심각": "#E2312D", "높음": "#E2312D", "보통": "#B9601C", "낮음": "#727171"}

# 사례 검색 (case_kb) 설정
CASE_N = 5                                        # 취약점마다 가져올 후보 사례 수
LEVEL_ORDER = ["동일 결함 사례", "같은 취약점 유형", "관련 통제 사례", "참고 사례"]
STRONG_LEVELS = ("동일 결함 사례", "같은 취약점 유형", "관련 통제 사례")  # 보고서에 인용해도 되는 등급 (참고 사례 제외)
LEVEL_SHORT = {"동일 결함 사례": "동일 결함", "같은 취약점 유형": "같은 유형", "관련 통제 사례": "관련 통제", "참고 사례": "참고"}
KIND_LABEL = {"처분": "과징금 처분", "판례": "판례", "기사": "언론 보도", "심사결함사례": "ISMS-P 심사 결함사례"}
SOURCE_LABEL = {"처분": "개인정보보호위원회 보도자료", "판례": "판결문", "기사": "언론 보도", "심사결함사례": "ISMS-P 인증기준 안내서"}
SOURCE_SHORT = {"처분": "개인정보위", "판례": "법원", "기사": "언론", "심사결함사례": "ISMS-P 안내서"}   # 장표 공간이 좁을 때
TAG_LABEL = {   # 사례 제목에 쓰는 짧은 이름 (cases.xlsx의 lists 시트와 같은 값)
    "credential_stuffing": "크리덴셜 스터핑", "no_anomaly_detection": "이상행위 탐지 미흡",
    "weak_password_rule": "비밀번호 규칙 미흡", "no_login_limit": "로그인 실패 제한 없음",
    "password_reset_flaw": "비밀번호 재설정 결함", "weak_identity_check": "본인확인 미흡",
    "idor": "파라미터 변조", "missing_authz_check": "권한 확인 누락", "data_exposure": "개인정보 노출",
    "unpatched_software": "보안 패치 미적용", "admin_page_exposure": "관리자 페이지 노출",
    "weak_crypto": "암호화 미흡", "webshell_upload": "웹셸 업로드",
}


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


CIRCLED = "①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮"


def paragraph_text(text, paragraph):
    """'제3항'이 지정된 조문이면 원문 중 ③ 부분만 잘라낸다 (없거나 못 찾으면 원문 그대로)"""
    m = re.fullmatch(r"제(\d+)항", (paragraph or "").strip())
    if not m or not text:
        return text
    n = int(m.group(1))
    if not 1 <= n <= len(CIRCLED) or CIRCLED[n - 1] not in text:
        return text
    start = text.index(CIRCLED[n - 1])
    end = text.find(CIRCLED[n], start) if n < len(CIRCLED) else -1
    return text[start:end if end > 0 else None].strip()


def normalize_scan(scan):
    """앞단 JSON의 표기 차이를 엔진 형식으로 맞춘다. 원본 값은 *_full / 원래 키로 보존.
    - evidence가 문자열이면 {"summary": 문자열}로 (스키마 1.0 제안은 객체였음)
    - evidence가 null이면 빈 객체로 (module3는 근거가 없으면 null을 보냄)
    - 항이 지정된 조문은 그 항만 보이게, <개정 …> 같은 이력 꼬리표는 떼고 (원문 그대로는 text_full에)"""
    for f in scan.get("findings", []):
        ev = f.get("evidence")
        if isinstance(ev, str):
            f["evidence"] = {"summary": ev, "detail": None}
        elif ev is None:
            f["evidence"] = {"summary": None, "detail": None}
        for law in f.get("violated_laws", []):
            if not law.get("text"):
                continue
            law["text_full"] = law["text"]
            shown = paragraph_text(law["text"], law["paragraph"]) if law.get("paragraph") else law["text"]
            law["text"] = re.sub(r"\s*[<\[](개정|신설|전문개정|본조신설|타법개정)[^>\]]*[>\]]", "", shown).strip()
    return scan

def resolve_catalog(scan, catalog):
    """카탈로그에 없는 item_id는 (1) 점검 항목 이름 → (2) ID 앞부분 순서로 KISA 항목에 연결한다.
    예: W-03 '불충분한 권한 검증' → IN (이름), IL-COMMENT-01 → IL (ID 앞부분)
    연결된 항목의 이름은 f["team_vuln"]에 남겨서 사례 검색(case_kb)도 같은 기준을 쓰게 한다."""
    key = lambda t: re.sub(r"\s+|\(.*?\)", "", t or "")
    by_title = {key(v.get("title")): k for k, v in catalog.items() if isinstance(v, dict) and v.get("title")}
    notes = []
    for f in scan.get("findings", []):
        iid = f.get("item_id")
        if iid not in catalog:
            hit, how = by_title.get(key(f.get("title"))), "이름 일치"
            if not hit:
                prefix = (iid or "").split("-")[0]
                if isinstance(catalog.get(prefix), dict):
                    hit, how = prefix, "ID 앞부분 일치"
            if hit:
                catalog[iid] = catalog[hit]
                notes.append(f"{iid} '{f.get('title')}' → 카탈로그 {hit} 항목 사용 ({how})")
            else:
                notes.append(f"{iid} '{f.get('title')}' → 카탈로그에 없음 (실무진용 판단 기준·조치 방법 칸이 비어 나옴)")
        entry = catalog.get(iid)
        if isinstance(entry, dict) and entry.get("title"):
            f["team_vuln"] = entry["title"]
    return notes


# ───────────────────────── 2) facts: 판정은 코드가 한다 ─────────────────────────

def law_label(law, ref_by_id):
    ref = ref_by_id.get(law.get("ref_id"), {})
    para = f" {law['paragraph']}" if law.get("paragraph") else ""
    return f"{ref.get('title', law.get('ref_id', ''))} {law['article']}{para}({law.get('article_title', '')})"


def compute_risk_level(vulns):
    """전체 위험 수준 판정 규칙. 팀 기준에 맞게 바꿔도 됨."""
    high = [f for f in vulns if f["severity"] == "상"]
    if any(f["asset"].get("handles_personal_data") for f in high):
        return "심각", "개인정보를 처리하는 자산에 '상' 위험 취약점이 있음"
    if high:
        return "높음", "'상' 위험 취약점이 있음"
    if any(f["severity"] == "중" for f in vulns):
        return "보통", "'중' 위험 취약점이 있음"
    return "낮음", "'하' 위험 취약점만 있거나 취약점 없음"


def card_to_case(card, level):
    """사례 카드(cases.json) → 템플릿이 쓰는 사례 형태. 금액·처분 결과는 카드 원문 그대로."""
    tags = [TAG_LABEL.get(t, t) for t in card.get("attack_tags", [])[:2]]
    return {
        "case_id": card["case_id"],
        "kind": KIND_LABEL.get(card["type"], card["type"]),
        "title": f"{card['org']} · {', '.join(tags)}" if tags else card["org"],
        "org": card["org"], "date": card["date"], "outcome": card["outcome"],
        "summary": card.get("facts"), "source": SOURCE_LABEL.get(card["type"], card["type"]),
        "source_short": SOURCE_SHORT.get(card["type"], card["type"]),
        "source_url": card.get("source_url"), "fine_krw": card.get("fine_krw"),
        "penalty_krw": card.get("penalty_krw"), "law_regime": card.get("law_regime"),
        "match_level": level, "finding_ids": [],
    }


def match_cases(vulns, cards, search):
    """취약점별 후보 사례(등급 포함)와, 후보 전체를 case_id로 모은 사전을 만든다."""
    card_by_id = {c["case_id"]: c for c in cards}
    cases, candidates = {}, {}
    for f in vulns:
        candidates[f["finding_id"]] = []
        for hit in search(f, CASE_N):
            card = card_by_id.get(hit["case_id"])
            if not card:      # 지식베이스와 cases.json이 어긋난 경우: load를 다시 돌려야 함
                continue
            level = hit["match_level"]
            candidates[f["finding_id"]].append({"case_id": card["case_id"], "match_level": level})
            c = cases.setdefault(card["case_id"], card_to_case(card, level))
            if LEVEL_ORDER.index(level) < LEVEL_ORDER.index(c["match_level"]):
                c["match_level"] = level        # 여러 취약점에 걸리면 가장 높은 등급으로
            c["finding_ids"].append(f["finding_id"])
    return cases, candidates


def make_search(n=CASE_N):
    """취약점 하나당 검색은 한 번만: 사례 매칭과 노출액 계산이 같은 결과를 나눠 쓴다."""
    cache = {}

    def search(f, k=n):
        key = (f["finding_id"], k)
        if key not in cache:
            cache[key] = case_kb.search_for_finding(f, n=k)
        return cache[key]
    return search


def build_profile(context):
    """context.json → exposure가 쓰는 고객사 프로필. 회원 수는 context의 member_count 하나로 통일."""
    return {
        "company": context.get("org_name"),
        "data_subjects": context.get("member_count"),
        **context.get("exposure_profile", {}),
    }


def build_facts(scan, context, cases, catalog, search):
    findings = scan["findings"]
    ref_by_id = {r["ref_id"]: r for r in scan.get("references", [])}
    vulns = sorted(
        [f for f in findings if f["status"] == "취약"],
        key=lambda f: SEV_ORDER.get(f["severity"], 9),
    )

    # 법령·ISMS-P 역색인: 어떤 조항이 몇 개 취약점에 걸리는지
    laws, criteria = {}, {}
    unreviewed = 0
    for f in vulns:
        for law in f.get("violated_laws", []):
            e = laws.setdefault(law["law_code"], {
                "law_code": law["law_code"], "label": law_label(law, ref_by_id),
                "text": law.get("text", ""), "in_force": law.get("in_force", True),
                "finding_ids": [], "unreviewed": False,
            })
            e["finding_ids"].append(f["finding_id"])
            if not law.get("reviewed"):
                e["unreviewed"] = True
                unreviewed += 1
        for c in f.get("isms_p", []):
            e = criteria.setdefault(c["criterion_id"], {
                "criterion_id": c["criterion_id"], "title": c.get("title", ""),
                "finding_ids": [], "unreviewed": False,
            })
            e["finding_ids"].append(f["finding_id"])
            if not c.get("reviewed"):
                e["unreviewed"] = True
                unreviewed += 1

    # 사례 매칭: 취약점마다 지식베이스에서 후보 사례를 등급과 함께 찾는다 (case_kb)
    matched_cases, candidates = match_cases(vulns, cases, search)

    # 노출액: 법정 상한, 유사 사례 금액, 투자 감경, 우선순위 (exposure). 금액은 전부 여기서 계산
    exposure_result = exposure.compute(scan, build_profile(context), search, CASE_N)

    assets = {}
    for f in findings:
        a = assets.setdefault(f["asset"]["id"], {**f["asset"], "count": 0})
        a["count"] += 1

    level, reason = compute_risk_level(vulns)
    pd_assets = sorted({f["asset"]["name"] for f in vulns if f["asset"].get("handles_personal_data")})
    stats = {
        "total": len(findings),
        "vuln": len(vulns),
        "good": sum(1 for f in findings if f["status"] == "양호"),
        "other": sum(1 for f in findings if f["status"] not in ("취약", "양호")),
        "by_sev": {s: sum(1 for f in vulns if f["severity"] == s) for s in SEV_ORDER},
        "pd_assets": pd_assets,
        "unreviewed_mappings": unreviewed,
    }
    return {
        "scan": scan, "context": context, "catalog": catalog,
        "vulns": vulns, "findings_sorted": sorted(findings, key=lambda f: (f["status"] != "취약", SEV_ORDER.get(f["severity"], 9))),
        "vuln_by_id": {f["finding_id"]: f for f in vulns}, "assets": list(assets.values()),
        "finding_by_id": {f["finding_id"]: f for f in findings},
        "laws": laws, "criteria": criteria, "cases": matched_cases, "case_candidates": candidates,
        "exposure": exposure_result,
        "risk": {"level": level, "reason": reason, "color": RISK_COLORS[level]},
        "stats": stats, "ref_by_id": ref_by_id,
    }


def facts_for_llm(facts):
    """LLM에 넘길 최소한의 사실만 추린다. 판례 금액은 일부러 빼서 LLM이 숫자를 옮겨 적다 틀릴 일을 없앤다."""
    # 로고 경로, 안내 문구, 메모는 문장 생성에 필요 없으니 빼고 넘긴다
    ctx = {k: v for k, v in facts["context"].items()
           if k not in ("logo", "disclaimer", "exposure_profile") and not k.startswith("_")}  # 매출 등 금액은 LLM에 안 넘김
    return {
        "context": ctx,
        "overall_risk": facts["risk"],
        "stats": facts["stats"],
        "vulnerabilities": [{
            "finding_id": f["finding_id"], "item_id": f["item_id"], "title": f["title"],
            "severity": f["severity"], "asset": f["asset"],
            "evidence": f.get("evidence", {}).get("summary"),
            "laws": [{"law_code": l["law_code"], "label": facts["laws"][l["law_code"]]["label"],
                      "reviewed": bool(l.get("reviewed")), "reason": l.get("reason")} for l in f.get("violated_laws", [])],
            "isms_p": [{"criterion_id": c["criterion_id"], "title": c.get("title")} for c in f.get("isms_p", [])],
            "fix_hint": facts["catalog"].get(f["item_id"], {}).get("fix"),
        } for f in facts["vulns"]],
        "case_candidates": {fid: [{
            "case_id": h["case_id"], "match_level": h["match_level"],
            "title": facts["cases"][h["case_id"]]["title"], "kind": facts["cases"][h["case_id"]]["kind"],
            "summary": facts["cases"][h["case_id"]]["summary"],
        } for h in hits] for fid, hits in facts["case_candidates"].items()},
        "exposure_hints": exposure_hints(facts["exposure"]),
    }


def exposure_hints(ex):
    """노출액 결과에서 문장에 필요한 사실만. 원화 금액은 일부러 뺀다 (금액은 템플릿이 채운다)."""
    dist = ex["case_evidence"]["fine_distribution"] or {}
    return {
        "special_10pct_possible": ex["legal_cap"]["special_10pct"]["possible"],
        "similar_case_count": dist.get("count", 0),
        "similar_cases_mostly_larger_companies": bool(dist.get("median_exceeds_client_cap")),
        "investment_reduction_max_pct": int(ex["reductions"]["investment"]["max_rate"] * 100),
        "has_security_investment_record": ex["reductions"]["investment"]["has_record"],
        "isms_p_certified": ex["reductions"]["isms_p"]["certified"],
        "priority_order": [r["finding_id"] for r in ex["priority"]["ranked"]],
    }


# ───────────────────────── 3) llm: 딱 한 번 ─────────────────────────

SYSTEM_PROMPT = """너는 정보보호 컨설팅 보고서를 쓰는 시니어 컨설턴트다. 입력으로 주어지는 진단 사실(facts)만 근거로, 지정된 JSON 형식의 문장을 작성한다.

규칙
1. facts에 없는 취약점, 법령, 조항, 사례, 금액, 수치를 만들어 내지 않는다. 숫자는 facts.context와 facts.stats에 있는 값만 쓴다.
2. 취약점은 finding_id로, 법령은 law_code로, 사례는 case_id로만 참조한다. facts에 없는 ID는 쓰지 않는다.
3. reviewed가 false인 법령 매핑은 단정하지 말고 "위반 소지"로 표현한다.
4. 경영진용 문장(headline, summary, top_risks, roadmap, decisions)은 기술 용어 대신 사업 영향(고객, 개인정보, 법적 책임, 신뢰, 비용)으로 쓴다. 명령어, 설정 이름, URL은 쓰지 않는다.
5. 실무진용 문장(finding_notes)은 기술적으로 정확하게, 원인과 악용 시나리오가 드러나게 쓴다.
6. 모든 문장은 보고서체(~습니다)로 쓴다.
7. JSON 외의 텍스트(설명, 마크다운 코드블록)는 출력하지 않는다.
8. 사례는 각 취약점의 case_candidates 안에서만 고르고, match_level 우선순위는 '동일 결함 사례' > '같은 취약점 유형' > '관련 통제 사례'다. 서로 다른 위험에는 가능하면 다른 사례를 쓴다. 위험 하나에 최대 2개. '참고 사례'는 같은 결함이 아니므로 인용하지 않는다.
9. 원화 금액(과징금, 과태료, 노출액)은 문장에 쓰지 않는다. 금액은 보고서 템플릿이 원본 데이터에서 직접 채운다.
10. top_risks의 순서와 roadmap의 즉시 단계는 exposure_hints.priority_order를 따른다. 보안 투자 기록이 없으면(has_security_investment_record=false) 과징금 감경 근거를 남기기 위한 조치·투자 기록 관리를 decisions에 포함할 수 있다.

문장 품질 (규칙을 지키는 것만으로는 부족하다. 경영진이 읽고 바로 이해하고 움직이게 써야 한다)
11. headline은 '무엇이 열려 있어서 누구의 무엇이 위험한지'를 구체적으로 쓴다. '보안 강화가 시급합니다' 같은 일반론은 쓰지 않는다.
    나쁨: "개인정보 보호 강화가 시급합니다."
    좋음: "결제 정보를 가진 주문 서버에 외부인이 직접 들어올 수 있습니다"
12. summary에는 영향받는 규모(context.member_count 등 facts에 있는 숫자)와, 공격이 성공하면 실제로 벌어지는 일을 넣는다.
13. top_risks.title은 점검 항목 이름을 그대로 쓰지 않고 사업 영향으로 바꿔 쓴다. 무엇이 '없거나 부족한지'가 분명해야 한다.
    나쁨: "약한 비밀번호 정책", "관리자 계정의 원격 접근 통제로 인한 보안 위험" (통제가 없어서 생긴 위험인데 통제 때문인 것처럼 읽힘)
    좋음: "누구나 추측할 수 있는 비밀번호로 가입할 수 있음", "주문번호만 알면 남의 배송지를 볼 수 있음"
14. decisions는 경영진이 승인·지정·결정할 일을 '[목적]을 위해 [시간·예산·책임자 등]을 승인해(지정해, 결정해) 주십시오' 형식으로 쓴다.
    건수·기간은 roadmap과 facts에 있는 값과 맞아야 한다. 담당자가 할 일을 그대로 옮기지 않는다. 아래 예시 문장을 그대로 쓰지 않는다.
    나쁨: "보안 투자 계획을 수립해야 합니다."
    좋음(다른 서비스 예): "주문 서버 외부 접속 차단 작업을 위해 이번 주말 점검 시간을 승인해 주십시오."
15. roadmap.action은 '~추가', '~차단'처럼 명사형으로 끝내고 25자 안팎으로 쓴다. '~해 주십시오'는 decisions에만 쓴다.
    나쁨: "비밀번호 정책을 강화하여 보안을 개선해 주십시오."   좋음: "비밀번호 최소 길이·조합 규칙 서버 검증 추가"
16. finding_notes는 vulnerabilities.evidence에 적힌 사실을 바꾸지 않는다(예: '숫자 4자리 비밀번호가 허용됨'을 '숫자 4자리만 허용'으로 바꾸지 않음).
    다만 description은 evidence 문장을 되풀이하지 말고, 어느 단계에서 어떤 확인이 빠졌는지(원인)와 공격자가 그것을 어떤 순서로 악용하는지를 쓴다.
"""

OUTPUT_SCHEMA = """{
  "headline": "경영진용 한 줄 결론, 45자 이내. overall_risk.level과 어긋나지 않게",
  "summary": "결론을 뒷받침하는 2~3문장",
  "top_risks": [
    {"title": "사업 언어로 쓴 위험 제목", "finding_ids": ["..."], "impact": "회사에 미치는 영향 1~2문장",
     "law_codes": ["..."], "case_ids": ["..."]}
  ],
  "roadmap": [{"phase": "즉시 | 단기 | 중기", "action": "조치 한 줄", "finding_ids": ["..."]}],
  "decisions": ["경영진이 내려야 할 결정 한 문장"],
  "finding_notes": {"<finding_id>": {"description": "실무진용 설명 2~3문장", "impact": "악용 시 영향 1~2문장"}}
}
제약: top_risks는 최대 3개, 위험이 큰 순서. 관련된 취약점은 하나의 위험으로 묶어도 된다.
roadmap.phase는 즉시(1주 이내), 단기(1개월 이내), 중기(분기 이내) 중 하나. decisions는 2~3개.
finding_notes에는 vulnerabilities의 finding_id를 빠짐없이 넣는다.
roadmap에는 vulnerabilities의 모든 finding_id가 한 번 이상 들어가야 한다 (top_risks에 못 들어간 취약점도)."""


def call_llm(system, user):
    """LLM 호출은 이 함수 하나에만 있다. LLM_PROVIDER=openai|anthropic (없으면 있는 키로 자동 선택)"""
    provider = os.getenv("LLM_PROVIDER") or ("openai" if os.getenv("OPENAI_API_KEY") else "anthropic")
    if provider == "openai":
        from openai import OpenAI
        client = OpenAI()  # 환경변수 OPENAI_API_KEY 사용
        resp = client.chat.completions.create(
            model=os.getenv("LLM_MODEL", "gpt-4o"),
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            response_format={"type": "json_object"},
            temperature=0.2,
        )
        return resp.choices[0].message.content
    from anthropic import Anthropic
    client = Anthropic()  # 환경변수 ANTHROPIC_API_KEY 사용
    resp = client.messages.create(
        model=os.getenv("LLM_MODEL", "claude-sonnet-5-5"),
        max_tokens=4000,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return "".join(b.text for b in resp.content if b.type == "text")


def parse_json_text(text):
    text = re.sub(r"```(?:json)?", "", text).strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < 0:
        raise ValueError("LLM 출력에서 JSON을 찾지 못했습니다:\n" + text[:500])
    return json.loads(text[start:end + 1])


def run_llm(facts):
    user = (
        "아래 facts로 보고서 문장을 작성해줘.\n\n출력 형식:\n" + OUTPUT_SCHEMA
        + "\n\nfacts:\n" + json.dumps(facts_for_llm(facts), ensure_ascii=False, indent=2)
    )
    return parse_json_text(call_llm(SYSTEM_PROMPT, user))


# ───────────────────────── 4) validate: LLM이 지어낸 ID는 버린다 ─────────────────────────

def validate(llm, facts):
    warnings = []
    vuln_ids = {f["finding_id"] for f in facts["vulns"]}

    def keep(ids, valid, what, where):
        good = [i for i in ids or [] if i in valid]
        for bad in set(ids or []) - set(good):
            warnings.append(f"{where}: 존재하지 않는 {what} '{bad}' 제거")
        return good

    risks, used_cases = [], set()
    for i, r in enumerate(llm.get("top_risks", [])[:3]):
        where = f"top_risks[{i}]"
        r["finding_ids"] = keep(r.get("finding_ids"), vuln_ids, "finding_id", where)
        if not r["finding_ids"]:
            warnings.append(f"{where}: 유효한 취약점이 없어 위험 항목 제거")
            continue
        r["law_codes"] = keep(r.get("law_codes"), facts["laws"], "law_code", where)
        allowed = {h["case_id"]: h["match_level"] for fid in r["finding_ids"]
                   for h in facts["case_candidates"].get(fid, [])}
        allowed = {c: lv for c, lv in allowed.items() if lv in STRONG_LEVELS}
        r["case_ids"] = keep(r.get("case_ids"), allowed, "case_id(이 위험의 인용 가능 후보가 아님)", where)[:2]
        if not r["case_ids"] and allowed:
            # 앞 위험에서 이미 쓴 사례는 피하고, 등급이 가장 높은 후보를 연결 (후보 순서 = 검색 순위)
            order = sorted(allowed, key=lambda c: (c in used_cases, LEVEL_ORDER.index(allowed[c])))
            best = order[0]
            r["case_ids"] = [best]
            warnings.append(f"{where}: 인용 사례가 없어 최상위 후보 '{best}'({allowed[best]})를 코드가 연결")
        used_cases.update(r["case_ids"])
        risks.append(r)

    phase_names = [p for p, _ in PHASES]
    roadmap = []
    for i, step in enumerate(llm.get("roadmap", [])):
        if step.get("phase") not in phase_names:
            warnings.append(f"roadmap[{i}]: 알 수 없는 단계 '{step.get('phase')}' 제거")
            continue
        step["finding_ids"] = keep(step.get("finding_ids"), vuln_ids, "finding_id", f"roadmap[{i}]")
        roadmap.append(step)

    # 로드맵에 빠진 취약점은 위험도 기준 단계로 코드가 추가 (상 → 즉시, 중 → 단기, 하 → 중기)
    in_roadmap = {fid for st in roadmap for fid in st["finding_ids"]}
    sev_phase = {"상": "즉시", "중": "단기", "하": "중기"}
    for f in facts["vulns"]:
        if f["finding_id"] not in in_roadmap:
            phase = sev_phase.get(f["severity"], "단기")
            roadmap.append({"phase": phase, "action": f"{f['title']} 조치", "finding_ids": [f["finding_id"]]})
            warnings.append(f"roadmap: '{f['title']}'이 빠져 있어 '{phase}' 단계에 코드가 추가")

    # 문장에 원화 금액이 섞였는지 검사 (금액은 템플릿만 쓰기로 했으므로 경고)
    money = re.compile(r"\d[\d,.]*\s*(억|천만|백만|만)?\s*원")
    texts = [("headline", llm.get("headline", "")), ("summary", llm.get("summary", ""))]
    texts += [(f"top_risks[{i}]", r.get("impact", "") + " " + r.get("title", "")) for i, r in enumerate(risks)]
    texts += [(f"decisions[{i}]", d) for i, d in enumerate(llm.get("decisions", []))]
    for where, t in texts:
        if money.search(t or ""):
            warnings.append(f"{where}: 문장에 금액이 들어 있음 → '{money.search(t).group(0)}' (금액은 템플릿이 채워야 함)")

    notes = {k: v for k, v in llm.get("finding_notes", {}).items() if k in vuln_ids}
    for fid in vuln_ids - set(notes):
        warnings.append(f"finding_notes: '{fid}' 설명 누락 (보고서에는 빈칸으로 표시)")

    clean = {
        "headline": llm.get("headline", ""), "summary": llm.get("summary", ""),
        "top_risks": risks, "roadmap": roadmap,
        "decisions": llm.get("decisions", [])[:3], "finding_notes": notes,
    }
    return clean, warnings


# ───────────────────────── 5) render: 같은 데이터, 템플릿 두 개 ─────────────────────────

def enrich(facts, llm):
    """템플릿이 쓰기 편하게 LLM 출력에 실제 데이터를 붙인다. 금액·조문은 여기서 원본 데이터로 채워진다."""
    by_id = {f["finding_id"]: f for f in facts["vulns"]}
    for r in llm["top_risks"]:
        fs = [by_id[i] for i in r["finding_ids"]]
        r["severity"] = min((f["severity"] for f in fs), key=lambda s: SEV_ORDER.get(s, 9))
        r["findings"] = fs
        # 검토 상태는 이 위험에 묶인 취약점들의 매핑 기준으로 다시 계산
        r["laws"] = [{
            **facts["laws"][c],
            "unreviewed": any(not l.get("reviewed") for f in fs for l in f.get("violated_laws", []) if l["law_code"] == c),
        } for c in r["law_codes"]]
        r["cases"] = [{**facts["cases"][c], "level": case_level(facts, c, r["finding_ids"])} for c in r["case_ids"]]
        for c in r["cases"]:   # 사례 장표의 등급도 인용된 위험 기준으로 (같은 사례가 장표마다 다른 등급으로 보이지 않게)
            prev = facts["cases"][c["case_id"]].get("cited_level")
            if prev is None or LEVEL_ORDER.index(c["level"]) < LEVEL_ORDER.index(prev):
                facts["cases"][c["case_id"]] = {**facts["cases"][c["case_id"]], "cited_level": c["level"]}
    facts["exposure_view"] = exposure_view(facts)
    llm["roadmap_by_phase"] = [
        {"phase": p, "window": w, "steps": [s for s in llm["roadmap"] if s["phase"] == p]} for p, w in PHASES
    ]
    return llm


def case_level(facts, case_id, finding_ids):
    """이 위험에 묶인 취약점들 기준으로 본 사례 등급 (가장 높은 것)"""
    levels = [h["match_level"] for fid in finding_ids for h in facts["case_candidates"].get(fid, [])
              if h["case_id"] == case_id]
    return min(levels, key=LEVEL_ORDER.index) if levels else facts["cases"][case_id]["match_level"]


def exposure_view(facts):
    """경영진 '과징금 노출' 장표용: 유사 처분 사례 중 최대 4건을 금액 분포가 보이게 고른다 (최소·최대 포함)"""
    ex, pool = facts["exposure"], facts.get("case_pool", facts["cases"])
    dist = ex["case_evidence"]["fine_distribution"]
    rows = []
    if dist:
        ids = [c for c in dist["case_ids"] if c in pool]          # 과징금 오름차순
        n = len(ids)
        pick = sorted({0, n // 3, (2 * n) // 3, n - 1}) if n > 4 else range(n)   # 장표 공간상 최대 4건
        cap = ex["legal_cap"]["cap_krw"]
        rows = [{**pool[ids[i]], "over_cap": (pool[ids[i]]["fine_krw"] or 0) > cap} for i in pick]
        rows.sort(key=lambda r: r["fine_krw"] or 0, reverse=True)
    return {"rows": rows, "dist": dist}


def krw(n):
    """원화를 보고서 표기로: 150000000 → '1억 5,000만 원'. 만 원 아래 단위가 있으면 원 단위 그대로."""
    if n is None:
        return "-"
    n = int(n)
    if n < 10_000 or n % 10_000:
        return f"{n:,}원"
    eok, man = divmod(n // 10_000, 10_000)
    parts = ([f"{eok:,}억"] if eok else []) + ([f"{man:,}만"] if man else [])
    return " ".join(parts) + " 원"


def keep_words(text):
    """제목용: 어절 단위로만 줄바꿈 (WeasyPrint가 word-break: keep-all을 지원하지 않아서)"""
    return Markup(" ".join(f'<span class="nw">{escape(w)}</span>' for w in str(text or "").split()))


def asset_uri(rel_path):
    """context.json의 로고 경로를 file:// URI로. 파일이 없으면 None → 템플릿이 로고 자리를 비운다"""
    if not rel_path:
        return None
    p = (BASE / rel_path).resolve()
    return p.as_uri() if p.exists() else None


def render(facts, llm, out_dir):
    env = Environment(loader=FileSystemLoader(BASE / "templates"), autoescape=True)
    env.filters["sev"] = lambda s: SEV_CLASS.get(s, "x")
    env.filters["kw"] = keep_words
    env.filters["krw"] = krw
    env.filters["lvl"] = lambda lv: LEVEL_SHORT.get(lv, lv)
    ctx = {**facts, "llm": llm, "today": date.today().isoformat(), "phases": PHASES,
           "font_dir": (BASE / "fonts").as_uri(),
           "logo_uri": asset_uri(facts["context"].get("logo"))}

    from weasyprint import HTML
    outputs = []
    for name, tpl in [("exec_report", "exec.html.j2"), ("tech_report", "tech.html.j2")]:
        html = env.get_template(tpl).render(**ctx)
        (out_dir / f"{name}.html").write_text(html, encoding="utf-8")
        pdf_path = out_dir / f"{name}.pdf"
        HTML(string=html, base_url=str(BASE)).write_pdf(pdf_path)
        outputs.append(pdf_path)
    return outputs


def main():
    ap = argparse.ArgumentParser(description="진단 JSON → 경영진용·실무진용 보고서 PDF")
    ap.add_argument("--scan", default=BASE / "data/scan.json")
    ap.add_argument("--context", default=BASE / "data/context.json")
    ap.add_argument("--cases", default=BASE / "data/cases.json")
    ap.add_argument("--catalog", default=BASE / "data/item_catalog.json")
    ap.add_argument("--out", default=None, help="결과 폴더 (기본: out/<scan_id>)")
    ap.add_argument("--llm-output", help="LLM을 호출하지 않고 이 파일의 출력을 사용")
    ap.add_argument("--mock", action="store_true", help="data/mock_llm_output.json 사용")
    args = ap.parse_args()

    from dotenv import load_dotenv
    team_env = BASE.parent / ".env"
    load_dotenv(team_env if team_env.exists() else BASE / ".env")

    scan_raw = normalize_scan(load_json(args.scan))
    out_dir = Path(args.out) if args.out else BASE / "out" / scan_raw["scan_id"]
    out_dir.mkdir(parents=True, exist_ok=True)

    catalog = load_json(args.catalog)
    for note in resolve_catalog(scan_raw, catalog):
        print(f"[카탈로그] {note}")
    facts = build_facts(scan_raw, load_json(args.context), load_json(args.cases), catalog, make_search())
    print(f"[facts] 취약 {facts['stats']['vuln']}건 / 전체 {facts['stats']['total']}개, 위험 수준 {facts['risk']['level']}")
    ex = facts["exposure"]
    (out_dir / "exposure_result.json").write_text(json.dumps(ex, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[exposure] 법정 상한 {ex['legal_cap']['cap_krw']:,}원, 후보 사례 {len(facts['cases'])}건 → {out_dir}")

    source = BASE / "data/mock_llm_output.json" if args.mock else args.llm_output
    if source:
        raw = load_json(source)
        print(f"[llm] 호출 생략, {source} 사용")
    else:
        print("[llm] 호출 1회...")
        raw = run_llm(facts)
        (out_dir / "llm_output.json").write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")

    llm, warnings = validate(raw, facts)
    for w in warnings:
        print(f"[검증] {w}")
    # 보고서에는 실제로 인용된 사례만 싣는다 (후보 전체를 실으면 사례 슬라이드가 넘친다)
    cited = list(dict.fromkeys(c for r in llm["top_risks"] for c in r["case_ids"]))
    facts["case_pool"] = facts["cases"]
    facts["cases"] = {c: facts["cases"][c] for c in cited}
    (out_dir / "run_log.json").write_text(json.dumps({
        "scan_id": facts["scan"]["scan_id"], "generated": date.today().isoformat(),
        "llm_source": str(source) if source else "live", "warnings": warnings,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    for p in render(facts, enrich(facts, llm), out_dir):
        print(f"[render] {p}")


if __name__ == "__main__":
    sys.exit(main())
