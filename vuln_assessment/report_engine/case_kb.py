#!/usr/bin/env python3
"""
2단계: 사례 카드(cases.json) → Chroma 지식베이스 적재 + 검색

사용법 (report_engine 폴더에서 실행, .env에 OPENAI_API_KEY 필요):
    python case_kb.py load
    python case_kb.py search --text "로그인 실패 횟수 제한 없음" --isms 2.5.3 2.11.3 --vuln "불충분한 인증 절차"

적재 규칙
  - verified가 TRUE인 카드만 넣는다.
  - 돌릴 때마다 지식베이스를 통째로 새로 만든다. 그래서 시트에서 지우거나 바꾼 태그,
    FALSE로 바꾼 카드가 지식베이스에 남지 않는다.
  - Chroma 메타데이터에는 목록을 넣기 어려워서, 팀 취약점·공격 태그·ISMS-P·조항을
    'isms_2_5_3: True' 같은 True 플래그로 펼쳐서 저장한다.

검색 규칙 (위에서부터 채우고, 모자라면 다음 등급으로)
  1. 동일 결함 사례: ISMS-P 기준과 팀 취약점이 둘 다 일치
  2. 같은 취약점 유형: 팀 취약점만 일치 (결함 종류가 같음)
  3. 관련 통제 사례: ISMS-P 기준만 일치 (통제 영역만 같음)
  4. 참고 사례: 필터 없이 유사도 순
  같은 보도자료(source_file)에서는 한 건만 고른다. 거의 같은 문장의 쌍둥이 카드가
  결과를 독차지하는 걸 막기 위해서다.
  결과마다 match_level을 붙여서, 보고서가 "같은 결함으로 처분받은 사례"인지
  "참고 사례"인지 구분해서 쓰게 한다.
"""
import argparse
import json
import re
from pathlib import Path

import chromadb
from dotenv import load_dotenv

BASE = Path(__file__).resolve().parent
CASES_JSON = BASE / "data" / "cases.json"
CHROMA_DIR = BASE / "data" / "chroma_db"
COLLECTION = "pipc_cases"
EMBED_MODEL = "text-embedding-3-small"

# 팀 취약점 이름(lists 시트) → 메타데이터 키에 쓸 영문 이름
VULN_SLUG = {
    "정보 누출": "info_leak",
    "약한 비밀번호 정책": "weak_pw_policy",
    "불충분한 권한 검증": "weak_authz",
    "취약한 비밀번호 복구 절차": "weak_pw_recovery",
    "불충분한 인증 절차": "weak_authn",
}


def slug(s):
    """'2.5.3' → '2_5_3', 'PIPA-29' → 'PIPA_29'"""
    return re.sub(r"[^0-9A-Za-z]+", "_", str(s)).strip("_")


def openai_embed(texts):
    from openai import OpenAI
    load_dotenv()
    client = OpenAI()  # OPENAI_API_KEY는 .env에서 읽음
    resp = client.embeddings.create(model=EMBED_MODEL, input=texts)
    return [d.embedding for d in resp.data]


def doc_text(card):
    """임베딩할 문장: 사실관계 + 팀 취약점 이름 + 처분 결과. ID·링크·금액 숫자는 메타데이터로만."""
    parts = [card.get("facts") or ""]
    if card.get("team_vuln"):
        parts.append("관련 취약점: " + ", ".join(card["team_vuln"]))
    if card.get("outcome"):
        parts.append("처분 결과: " + card["outcome"])
    return "\n".join(p for p in parts if p)


def metadata(card):
    m = {
        "case_id": card["case_id"],
        "type": card["type"],
        "date": card["date"],
        "year": int(card["date"][:4]),
        "org": card["org"],
        "industry": card.get("industry") or "",
        "fine_krw": card.get("fine_krw") or 0,
        "penalty_krw": card.get("penalty_krw") or 0,
        "law_regime": card.get("law_regime") or "",
        "source_url": card.get("source_url") or "",
        "source_file": card.get("source_file") or "",
        "is_general": not card.get("team_vuln"),  # 팀 취약점 없는 일반 사례(예: 반복 위반)
    }
    for v in card.get("team_vuln", []):
        if v in VULN_SLUG:
            m[f"vuln_{VULN_SLUG[v]}"] = True
    for t in card.get("attack_tags", []):
        m[f"tag_{slug(t)}"] = True
    for i in card.get("isms_p_ids", []):
        m[f"isms_{slug(i)}"] = True
    for c in card.get("violated_codes", []):
        m[f"code_{slug(c)}"] = True
    return m


def get_collection(path=CHROMA_DIR):
    client = chromadb.PersistentClient(path=str(path))
    return client.get_or_create_collection(COLLECTION, metadata={"hnsw:space": "cosine"})


def load(cases_path=CASES_JSON, embed=openai_embed, path=CHROMA_DIR):
    cards = json.loads(Path(cases_path).read_text(encoding="utf-8"))
    ok = [c for c in cards if c.get("verified")]

    # 매번 컬렉션을 통째로 새로 만든다.
    # Chroma의 upsert는 메타데이터를 덮어쓰지 않고 합쳐서, 시트에서 지운 태그 플래그가
    # 지식베이스에 그대로 남는다. 카드 수가 적어서 전부 다시 임베딩해도 비용은 미미하다.
    client = chromadb.PersistentClient(path=str(path))
    before = 0
    if COLLECTION in [c if isinstance(c, str) else c.name for c in client.list_collections()]:
        before = client.get_collection(COLLECTION).count()
        client.delete_collection(COLLECTION)
    col = client.create_collection(COLLECTION, metadata={"hnsw:space": "cosine"})

    if ok:
        texts = [doc_text(c) for c in ok]
        col.add(ids=[c["case_id"] for c in ok], documents=texts,
                metadatas=[metadata(c) for c in ok], embeddings=embed(texts))

    print(f"적재 완료: {len(ok)}장 (verified FALSE라서 제외 {len(cards) - len(ok)}장)")
    print(f"지식베이스를 새로 만들었어요: {before}장 → {col.count()}장 ({path})")


def _flag_filter(keys):
    keys = list(dict.fromkeys(keys))
    if not keys:
        return None
    if len(keys) == 1:
        return {keys[0]: True}
    return {"$or": [{k: True} for k in keys]}


def search_cases(query_text, isms_ids=(), team_vuln=None, n=3, embed=openai_embed, path=CHROMA_DIR):
    col = get_collection(path)
    total = col.count()
    if total == 0:
        return []
    q = embed([query_text])[0]

    isms_f = _flag_filter([f"isms_{slug(i)}" for i in isms_ids])
    vuln_f = {f"vuln_{VULN_SLUG[team_vuln]}": True} if team_vuln in VULN_SLUG else None

    # 위에서부터 채우고, 모자라면 다음 등급으로 내려간다
    tiers = []
    if isms_f and vuln_f:
        tiers.append(("동일 결함 사례", {"$and": [isms_f, vuln_f]}))   # ISMS-P 기준 + 팀 취약점 둘 다 일치
    if vuln_f:
        tiers.append(("같은 취약점 유형", vuln_f))                      # 팀 취약점만 일치 (같은 결함 종류)
    if isms_f:
        tiers.append(("관련 통제 사례", isms_f))                        # ISMS-P 기준만 일치 (같은 통제 영역)
    tiers.append(("참고 사례", None))                                   # 필터 없이 유사도만

    results, seen_ids, seen_sources = [], set(), set()
    for level, where in tiers:
        if len(results) >= n:
            break
        # 같은 보도자료 쌍둥이 카드를 건너뛸 여유를 두고 넉넉히 가져온다
        k = min(max(n * 4, 10), total)
        res = col.query(query_embeddings=[q], n_results=k, where=where,
                        include=["documents", "metadatas", "distances"])
        for cid, doc, meta, dist in zip(res["ids"][0], res["documents"][0],
                                        res["metadatas"][0], res["distances"][0]):
            src = meta.get("source_file") or cid
            if cid in seen_ids or src in seen_sources:   # 보도자료 하나당 한 건만
                continue
            seen_ids.add(cid)
            seen_sources.add(src)
            results.append({"case_id": cid, "match_level": level, "distance": round(dist, 4),
                            "metadata": meta, "document": doc})
            if len(results) >= n:
                break
    return results


def search_for_finding(finding, n=3, **kw):
    """재용님 JSON(v1.0)의 finding 하나로 바로 검색.
    팀 취약점은 engine이 카탈로그로 맞춘 이름(team_vuln)을 먼저 쓰고, 없으면 제목을 쓴다."""
    isms = finding.get("isms_p", [])
    query = " ".join([finding.get("title", "")] +
                     [f"{x.get('title', '')} {x.get('reason', '')}" for x in isms])
    return search_cases(query, isms_ids=[x["criterion_id"] for x in isms],
                        team_vuln=finding.get("team_vuln") or finding.get("title"), n=n, **kw)


def main():
    ap = argparse.ArgumentParser(description="사례 지식베이스 적재·검색")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_load = sub.add_parser("load", help="cases.json → Chroma")
    p_load.add_argument("--cases", default=CASES_JSON, type=Path)
    p_s = sub.add_parser("search", help="검색 품질 확인")
    p_s.add_argument("--text", required=True, help="취약점 설명 문장")
    p_s.add_argument("--isms", nargs="*", default=[], help="ISMS-P 기준 번호 (예: 2.5.3 2.11.3)")
    p_s.add_argument("--vuln", default=None, help="팀 취약점 이름 (예: 불충분한 인증 절차)")
    p_s.add_argument("-n", type=int, default=3)
    args = ap.parse_args()

    if args.cmd == "load":
        load(args.cases)
    else:
        for i, r in enumerate(search_cases(args.text, args.isms, args.vuln, args.n), 1):
            m = r["metadata"]
            print(f"{i}. [{r['match_level']}] {r['case_id']} {m['org']} "
                  f"(과징금 {m['fine_krw']:,}원, 거리 {r['distance']})")
            print(f"   {r['document'][:90]}...")


if __name__ == "__main__":
    main()
