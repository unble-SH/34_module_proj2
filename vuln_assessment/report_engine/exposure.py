#!/usr/bin/env python3
"""
4단계: 노출액 추정 (금액은 전부 코드가 계산한다. LLM은 숫자를 만들지 않는다)

사용법 (report_ai 폴더에서 실행):
    python exposure.py
    python exposure.py --findings data/mock_findings.json --profile data/profile.json --out data/exposure_result.json

입력
  - findings: 재용님 JSON v1.0 (취약점 진단 결과)
  - profile:  고객사 프로필 (data/profile.json)
  - 사례 지식베이스: case_kb.py로 적재한 Chroma

출력 (data/exposure_result.json) — 5단계 보고서 생성과 6단계 숫자 검증이 이 파일 하나만 본다
  1. legal_cap        과징금 법정 상한 (원칙 3%) + 10% 특례 시나리오와 요건 점검
  2. reductions       투자 감경(최대 40%), ISMS-P 인증 감경(최대 30%) 안내와 상한 기준 예시
  3. violations       위반 조항별로 묶은 취약점 (같은 조항은 한 번만 센다)
  4. case_evidence    유사 처분 사례의 실제 과징금 분포와 근거 case_id
  5. priority         취약점별 우선순위 점수와 "상위 N개 조치 시 리스크 감소율"
  6. excluded         계산에서 뺀 항목과 이유
  7. assumptions      보고서 부록에 그대로 실을 가정 목록

주의: 법정 상한은 "최대치"이지 예상 부과액이 아니다. 실제 부과액은 개인정보위
과징금 부과기준 고시의 산정 단계(기준금액 → 투자 감경 → 1차·2차 조정)를 거쳐
훨씬 작아지는 경우가 많아서, 유사 사례 실제 부과액을 함께 보여준다.
"""
import argparse
import json
import statistics
from datetime import date
from pathlib import Path

import case_kb

BASE = Path(__file__).resolve().parent

# ---- 법정 기준 (개정 개인정보 보호법 제64조의2, 2026-09-11 시행) ----
CAP_RATE = 0.03                    # 원칙: 전체 매출액(위반과 무관한 매출 제외)의 3%
CAP_NO_REVENUE_KRW = 2_000_000_000  # 매출액이 없거나 산정 곤란: 20억 원
SPECIAL_RATE = 0.10                # 특례: 10%
SPECIAL_NO_REVENUE_KRW = 5_000_000_000  # 특례 + 매출 산정 곤란: 50억 원
MASS_VICTIMS = 10_000_000          # 특례 요건 중 피해 1천만 명
INVEST_MAX = 0.40                  # 투자 감경: 기준금액의 최대 40% (고의·중과실 제외)
ISMSP_MAX = 0.30                   # ISMS-P 인증 감경: 최대 30% (개정 전 50%)
PUBLIC_ONLY_CODES = {"PIPA-33"}    # 개인정보 영향평가: 공공기관 의무 조항

# ---- 우선순위 점수 가중치 (설명 가능한 단순 규칙, 부록에 공개) ----
SEV_W = {"상": 3, "중": 2, "하": 1}
EVIDENCE_W = {"동일 결함 사례": 1.0, "같은 취약점 유형": 0.7, "관련 통제 사례": 0.5, "참고 사례": 0.3, None: 0.2}
PII_W = {True: 1.0, False: 0.3}
STRONG_LEVELS = ("동일 결함 사례", "같은 취약점 유형", "관련 통제 사례")  # 금액 분포에 넣는 등급 (참고 사례 제외)


def won(x):
    return f"{x:,}원" if x is not None else "-"


def legal_cap(profile):
    rev = profile.get("annual_revenue_krw")
    unrelated = profile.get("revenue_unrelated_krw") or 0
    if not rev:
        base, cap, sp_cap = None, CAP_NO_REVENUE_KRW, SPECIAL_NO_REVENUE_KRW
        basis = "매출액이 없거나 산정이 곤란한 경우의 상한"
    else:
        base = max(rev - unrelated, 0)
        cap, sp_cap = round(base * CAP_RATE), round(base * SPECIAL_RATE)
        basis = "전체 매출액에서 위반과 무관한 매출을 뺀 금액의 3%"

    subjects = profile.get("data_subjects") or 0
    conditions = [
        {"name": "고의·중과실로 3년 내 같은 유형 반복 위반",
         "possible": bool(profile.get("prior_violation_within_3y")),
         "why": "고객사 프로필의 3년 내 위반 이력 기준. 고의·중과실 여부는 도구가 판단하지 않음"},
        {"name": "고의·중과실로 피해 1천만 명 이상",
         "possible": subjects >= MASS_VICTIMS,
         "why": f"정보주체 {subjects:,}명 → 1천만 명 기준 {'이상' if subjects >= MASS_VICTIMS else '미달'}"},
        {"name": "시정명령 불이행으로 유출",
         "possible": bool(profile.get("corrective_order_pending")),
         "why": "고객사 프로필의 시정명령 미이행 여부 기준"},
    ]
    return {
        "law_basis": "개인정보 보호법 제64조의2(과징금의 부과), 2026-09-11 시행 개정법",
        "relevant_revenue_krw": base,
        "rate": CAP_RATE if base is not None else None,
        "cap_krw": cap,
        "basis": basis,
        "special_10pct": {
            "cap_krw": sp_cap,
            "possible": any(c["possible"] for c in conditions),
            "conditions": conditions,
            "note": "세 요건 중 하나에 해당할 때만 적용. 보고서에는 '이 조건이 붙으면' 시나리오로만 표기",
        },
        "public_institution": bool(profile.get("is_public_institution")),
    }


def reductions(profile, cap_krw):
    certified = bool(profile.get("isms_p_certified"))
    budget = profile.get("security_budget_krw")
    return {
        "investment": {
            "max_rate": INVEST_MAX,
            "has_record": budget is not None,
            "note": "보호 투자·보호체계 운영·추가 안전조치를 고려해 기준금액의 최대 40% 감경. "
                    "위반 전 3개 사업연도 노력을 보며 고의·중과실 위반은 제외",
            "illustration_on_cap_krw": round(cap_krw * (1 - INVEST_MAX)),
            "illustration_note": "법정 상한에 최대 감경률을 적용한 예시값. 실제 감경은 기준금액에 적용됨",
        },
        "isms_p": {
            "max_rate": ISMSP_MAX,
            "certified": certified,
            "note": "ISMS-P 인증에 따른 감경 상한은 최대 30%(개정 전 50%). "
                    "중요 개인정보처리자 대상 인증 의무화는 2027-07-01 시행 예정",
        },
    }


def classify(findings, profile):
    """계산 대상 취약점과 제외 항목을 나눈다."""
    public = bool(profile.get("is_public_institution"))
    active, excluded, by_code = [], [], {}
    for f in findings:
        fid = f["finding_id"]
        if f.get("status") != "취약":
            excluded.append({"finding_id": fid, "reason": f"상태가 '{f.get('status')}'라 노출액 계산에서 제외"})
            continue
        active.append(f)
        pii = (f.get("asset") or {}).get("handles_personal_data", False)
        if not f.get("violated_laws"):
            excluded.append({"finding_id": fid, "reason": "관련 법 조항이 없어 법적 노출액에서 제외 (ISMS-P 심사 리스크로만 다룸)"})
            continue
        if not pii:
            excluded.append({"finding_id": fid, "reason": "개인정보를 처리하지 않는 자산이라 개인정보보호법 노출액에서 제외"})
            continue
        for law in f["violated_laws"]:
            code = law.get("law_code")
            if not law.get("in_force", True):
                excluded.append({"finding_id": fid, "reason": f"{code}는 아직 시행 전 조문이라 제외"})
                continue
            if not str(code).startswith("PIPA-"):
                continue   # 고시 조항(SAFE-5 등)은 제29조의 세부 기준이라 과징금 상한을 따로 세지 않는다
            if code in PUBLIC_ONLY_CODES and not public:
                excluded.append({"finding_id": fid, "reason": f"{code}는 공공기관 의무 조항이라 민간 대상에서 제외"})
                continue
            by_code.setdefault(code, {"law_code": code, "article": law.get("article"),
                                      "article_title": law.get("article_title"), "finding_ids": []})
            if fid not in by_code[code]["finding_ids"]:
                by_code[code]["finding_ids"].append(fid)
    return active, excluded, list(by_code.values())


def case_evidence(active, search_fn, n):
    per_finding, pool = {}, {}
    for f in active:
        hits = search_fn(f, n)
        per_finding[f["finding_id"]] = [
            {"case_id": h["case_id"], "match_level": h["match_level"], "org": h["metadata"]["org"],
             "fine_krw": h["metadata"].get("fine_krw", 0), "law_regime": h["metadata"].get("law_regime")}
            for h in hits]
        for h in hits:
            m = h["metadata"]
            if h["match_level"] in STRONG_LEVELS and m.get("type") == "처분" and (m.get("fine_krw") or 0) > 0:
                pool[h["case_id"]] = m["fine_krw"]

    fines = sorted(pool.values())
    dist = None
    if fines:
        dist = {"count": len(fines), "min_krw": fines[0], "median_krw": round(statistics.median(fines)),
                "max_krw": fines[-1], "case_ids": sorted(pool, key=pool.get)}
    return {"fine_distribution": dist, "per_finding": per_finding,
            "note": "참고 사례를 뺀 등급(동일 결함·같은 유형·관련 통제)의 처분 사례 중 과징금이 있는 것만 집계. "
                    "사례 기업과 고객사의 매출 규모가 달라 예상 부과액이 아니라 '유사 사례에서 실제로 나온 금액'임"}


def evidence_fine(evidence, case_id):
    for hits in evidence["per_finding"].values():
        for h in hits:
            if h["case_id"] == case_id:
                return h["fine_krw"]
    return 0


def priority(active, per_finding):
    rows = []
    for f in active:
        hits = per_finding.get(f["finding_id"], [])
        best = hits[0]["match_level"] if hits else None
        pii = bool((f.get("asset") or {}).get("handles_personal_data", False))
        # 심각도가 먼저, 사례 근거는 최대 1.5배까지만 올린다 → '상'은 근거가 약해도 '중'보다 뒤로 가지 않는다
        score = SEV_W.get(f.get("severity"), 1) * PII_W[pii] * (1 + 0.5 * EVIDENCE_W[best])
        rows.append({"finding_id": f["finding_id"], "title": f.get("title"), "severity": f.get("severity"),
                     "best_evidence": best, "handles_personal_data": pii, "score": round(score, 2)})
    rows.sort(key=lambda r: r["score"], reverse=True)
    total = sum(r["score"] for r in rows) or 1
    cum, reduction = 0, []
    for i, r in enumerate(rows, 1):
        cum += r["score"]
        r["rank"] = i
        reduction.append({"top_n": i, "risk_reduction_pct": round(cum / total * 100, 1)})
    return {"ranked": rows, "top_n_reduction": reduction,
            "formula": "점수 = 심각도(상3·중2·하1) × 개인정보 자산(예 1.0·아니오 0.3) "
                       "× (1 + 0.5 × 사례 근거(동일 결함 1.0·같은 유형 0.7·관련 통제 0.5·참고 0.3·없음 0.2))"}


def compute(findings_doc, profile, search_fn, n=5):
    findings = findings_doc.get("findings", [])
    cap = legal_cap(profile)
    active, excluded, violations = classify(findings, profile)
    evidence = case_evidence(active, search_fn, n)
    dist = evidence["fine_distribution"]
    if dist:
        dist["over_client_cap_count"] = sum(1 for c in dist["case_ids"]
                                            if evidence_fine(evidence, c) > cap["cap_krw"])
        dist["median_exceeds_client_cap"] = dist["median_krw"] > cap["cap_krw"]
        if dist["median_exceeds_client_cap"]:
            dist["warning"] = ("유사 사례 중앙값이 이 고객사의 법정 상한보다 큼. 사례 기업이 더 커서 생긴 차이이므로 "
                               "사례 금액을 고객사 예상 과징금처럼 쓰면 안 됨 (상한을 넘는 과징금은 불가능)")
    return {
        "generated_at": date.today().isoformat(),
        "scan_id": findings_doc.get("scan_id"),
        "company": profile.get("company"),
        "legal_cap": cap,
        "reductions": reductions(profile, cap["cap_krw"]),
        "violations": violations,
        "case_evidence": evidence,
        "priority": priority(active, evidence["per_finding"]),
        "excluded": excluded,
        "assumptions": [
            "고객사 프로필(매출·정보주체 수 등)은 모의 교육 플랫폼 가정값",
            "법정 상한은 최대치이며 예상 부과액이 아님",
            "같은 조항에 걸린 취약점이 여러 개여도 법정 상한은 한 번만 적용",
            "유사 사례 금액은 대부분 개정법 시행(2026-09-11) 이전 구법 기준 처분",
            "투자 감경 예시값은 법정 상한에 최대 감경률을 적용한 것으로, 실제 감경은 기준금액에 적용됨",
            "우선순위 점수는 조치 순서를 정하기 위한 상대 점수이며 금액이 아님",
        ],
    }


def print_summary(r):
    cap = r["legal_cap"]
    print(f"\n[{r['company']}] 노출액 추정 ({r['scan_id']})")
    print(f"  법정 상한: {won(cap['cap_krw'])}  ({cap['basis']})")
    sp = cap["special_10pct"]
    print(f"  10% 특례 시나리오: {won(sp['cap_krw'])}  → 요건 해당 가능성 {'있음' if sp['possible'] else '없음'}")
    inv = r["reductions"]["investment"]
    print(f"  투자 감경 예시(상한 기준): {won(inv['illustration_on_cap_krw'])}  (최대 {int(inv['max_rate']*100)}%)")
    d = r["case_evidence"]["fine_distribution"]
    if d:
        print(f"  유사 사례 실제 과징금 {d['count']}건: 최소 {won(d['min_krw'])} / 중앙값 {won(d['median_krw'])} / 최대 {won(d['max_krw'])}")
        if d.get("warning"):
            print(f"  ⚠ {d['warning']} (상한 초과 사례 {d['over_client_cap_count']}건)")
    print("  위반 조항: " + (", ".join(f"{v['law_code']}({len(v['finding_ids'])}건)" for v in r["violations"]) or "없음"))
    print("\n  우선순위")
    for row in r["priority"]["ranked"]:
        red = r["priority"]["top_n_reduction"][row["rank"] - 1]["risk_reduction_pct"]
        print(f"   {row['rank']}. {row['title']} (심각도 {row['severity']}, 근거 {row['best_evidence']}) "
              f"점수 {row['score']} → 여기까지 조치 시 리스크 {red}% 감소")
    if r["excluded"]:
        print("\n  계산에서 뺀 항목")
        for e in r["excluded"]:
            print(f"   - {e['finding_id']}: {e['reason']}")


def main():
    ap = argparse.ArgumentParser(description="4단계 노출액 추정")
    ap.add_argument("--findings", default=BASE / "data" / "mock_findings.json", type=Path)
    ap.add_argument("--profile", default=BASE / "data" / "profile.json", type=Path)
    ap.add_argument("--out", default=BASE / "data" / "exposure_result.json", type=Path)
    ap.add_argument("-n", type=int, default=5, help="취약점마다 가져올 사례 수")
    args = ap.parse_args()

    findings_doc = json.loads(args.findings.read_text(encoding="utf-8"))
    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    result = compute(findings_doc, profile, lambda f, n: case_kb.search_for_finding(f, n=n), args.n)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print_summary(result)
    print(f"\n저장 완료: {args.out}")


if __name__ == "__main__":
    main()
