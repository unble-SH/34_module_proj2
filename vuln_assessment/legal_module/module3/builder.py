"""출력 JSON 조립.

- isms_p        : LLM이 고른 기준 (mapped_by "llm")
- violated_laws : 고른 기준의 [관련 법규]에 적힌 조문을 법령 txt에서 꺼내 채움 (mapped_by "rule")
                  이어서 LLM이 진단 근거를 보고 조문 안에서 해당 항을 고르고 조문별 이유를 씀 (mapped_by "rule+llm").
                  해당 항이 없다고 판단된 조문은 빼고 review_note에 남긴다. 새 조문을 추가하지는 못한다.
- 조문이 txt에 없거나 제목이 다르면 review_note에 사유를 남긴다.
- 관련 법규가 없는 기준만 선택되면 violated_laws는 빈 배열 (LLM으로 채우지 않음, 팀 합의).
"""
import re
from typing import Callable, Optional

from .config import ISMSP_REF, UMBRELLA_RULES
from .ismsp_loader import IsmsP
from .law_loader import norm_title

MAPPED_STATUSES = ('취약', '수동확인')      # 이 판정만 ISMS-P·법령 매핑을 수행한다
LAW_ORDER = {'PIPA': 0, 'SAFE': 1}          # 출력 정렬: 개인정보 보호법 -> 고시 -> 그 외


def _sort_key(entry: dict):
    code = entry.get('law_code') or ''
    key = code.split('-')[0]
    m = re.search(r'제(\d+)조(?:의(\d+))?', entry.get('article') or '')
    num, sub = (int(m[1]), int(m[2] or 0)) if m else (10 ** 6, 0)
    return (entry['text'] is None, LAW_ORDER.get(key, 9), key, num, sub)


def make_finding_id(finding: dict, idx: int, scan_id: str) -> str:
    if finding.get('finding_id'):
        return finding['finding_id']
    asset_id = (finding.get('asset') or {}).get('id') or f"A{idx + 1:02d}"
    return f"{scan_id}-{finding.get('item_id', f'F{idx + 1:02d}')}-{asset_id}"


def _provenance(from_labels: list) -> str:
    return f"ISMS-P 기준 {', '.join(from_labels)}의 [관련 법규]로 지정된 조문 (ISMS-P 인증기준 안내서 2023.11)"


def _short_provenance(from_labels: list) -> str:
    return f"(근거: ISMS-P {', '.join(from_labels)} 관련 법규)"


def _law_entry(law_key: Optional[str], law_name: str, aid: Optional[str], guide_title: Optional[str],
               laws: dict, from_labels: list, hpd: Optional[bool]) -> dict:
    notes = []
    law = laws.get(law_key) if law_key else None
    art = law.get(aid) if (law and aid) else None

    if law_key is None:
        law_code = law_name
        ref_id = None
        notes.append("안내서에 적힌 법령명이 등록되어 있지 않음")
    elif aid is None:
        law_code = law_key
        ref_id = law.ref_id if law else law_key
        notes.append("안내서가 법령만 지정하고 조문은 지정하지 않음")
    else:
        law_code = f"{law_key}-{art.code_suffix}" if art else f"{law_key}-{aid[1:].replace('조', '', 1)}"
        ref_id = law.ref_id if law else law_key

    if law is None and law_key is not None:
        notes.append("원문(txt) 미보유 법령: text 없음")
    elif law is not None and aid is not None and art is None:
        notes.append("원문(txt)에 해당 조문 없음")
    if art is not None:
        if art.title and guide_title and norm_title(art.title) != norm_title(guide_title):
            notes.append(f"제목 불일치: 안내서 '{guide_title}' / 원문 '{art.title}'")
        if not art.in_force:
            notes.append(f"시행 예정 조문 ({art.future_date or '부칙 참조'})")
        if art.note and art.in_force:
            notes.append(art.note)
    if hpd is False and law_key in ('PIPA', 'SAFE'):
        notes.append("자산이 개인정보를 처리하지 않음: 개인정보 관련 법령 적용 여부 확인 필요")

    entry = {
        "law_code": law_code,
        "ref_id": ref_id,
        "law_name": law.name if law else law_name,
        "article": aid,
        "paragraph": None,
        "article_title": (art.title if art else guide_title),
        "text": art.text if art else None,
        "in_force": art.in_force if art else None,
        "mapped_by": "rule",
        "reviewed": False,
        "reason": _provenance(from_labels),
    }
    if notes:
        entry["review_note"] = ' / '.join(notes)
    return entry


def _apply_narrowing(violated: list, labels_by_code: dict, laws: dict, finding: dict,
                     narrower: Callable) -> tuple:
    """2차 LLM 판단을 조문 목록에 반영. -> (남은 조문 목록, 메모 목록)"""
    notes = []
    candidates = []
    for e in violated:
        if e['text'] is None:
            continue
        art = laws[e['law_code'].split('-')[0]].get(e['article'])
        candidates.append({"law_code": e['law_code'], "law_name": e['law_name'], "article": e['article'],
                           "title": e['article_title'], "text": e['text'], "paragraphs": art.paragraphs()})
    if not candidates:
        return violated, notes
    try:
        result, note = narrower(finding, candidates)
    except Exception as ex:
        result, note = None, f"항 판단 LLM 호출 실패: {type(ex).__name__}: {str(ex)[:100]}"
    if note:
        notes.append(note)
    if result is None:                        # 판단 불가: 규칙 매핑 결과(조문 전체)를 그대로 둔다
        return violated, notes
    kept, removed, dropped = [], [], {}
    for e in violated:
        r = result.get(e['law_code'])
        if e['text'] is None or r is None:
            kept.append(e)
            continue
        if not r['applicable']:
            dropped[e['law_code']] = e
            removed.append(f"{e['law_code']} {e['article']}({e['article_title']}): {r['reason'] or '해당 항 없음'}")
            continue
        e['paragraph'] = ', '.join(r['paragraphs']) or None
        e['reason'] = (r['reason'] + ' ' if r['reason'] else '') + _short_provenance(labels_by_code[e['law_code']])
        e['mapped_by'] = 'rule+llm'
        kept.append(e)
    # 상위 의무 조문 보정: 고시 조문이 남아 있으면 제29조는 LLM이 빼도 유지한다 (고시 = 제29조의 구체 기준)
    for umbrella, detail_keys in UMBRELLA_RULES.items():
        e = dropped.get(umbrella)
        if e is None:
            continue
        details = [k for k in kept if k['law_code'].split('-')[0] in detail_keys]
        if details:
            names = ', '.join(f"{k['law_name']} {k['article']}" for k in details)
            e['paragraph'] = None
            e['reason'] = (f"{names}의 안전조치 미이행은 그 상위 의무인 {e['law_name']} {e['article']}({e['article_title']}) "
                           f"위반을 구성함 {_short_provenance(labels_by_code[umbrella])}")
            e['mapped_by'] = 'rule+llm'
            kept.append(e)
            removed[:] = [s for s in removed if not s.startswith(umbrella + ' ')]
            notes.append(f"LLM이 {e['article']}를 제외했으나 고시 조문이 해당하므로 상위 의무 조문으로 유지함")
    if removed:
        notes.append("LLM 항 판단으로 제외한 조문: " + ' / '.join(removed))
    return kept, notes


def build_finding(finding: dict, idx: int, scan_id: str, selection: list, llm_note: Optional[str],
                  ismsp: IsmsP, laws: dict, narrower: Optional[Callable] = None) -> dict:
    out = {
        "finding_id": make_finding_id(finding, idx, scan_id),
        "item_id": finding.get('item_id'),
        "title": finding.get('title'),
        "status": finding.get('status'),
        "severity": finding.get('severity'),
        "asset": finding.get('asset'),
        "evidence": finding.get('evidence'),      # 정식 필드: 항상 포함 (없으면 null)
    }

    status = finding.get('status')
    if status not in MAPPED_STATUSES:
        out.update(violated_laws=[], isms_p=[])
        if status != '양호':
            out["review_note"] = f"판정 상태 '{status}'는 매핑 대상이 아님 (취약·수동확인만 매핑)"
        return out

    hpd = (finding.get('asset') or {}).get('handles_personal_data')
    isms_entries = []
    law_entries = {}          # (law_key or law_name, article id) -> (law_key, law_name, aid, guide_title)
    from_labels = {}          # 같은 키 -> 어느 기준에서 왔는지
    for sel in selection:
        crit = ismsp.get(sel['criterion_id'])
        if crit is None:
            continue
        isms_entries.append({
            "criterion_id": crit.id,
            "ref_id": ISMSP_REF["ref_id"],
            "title": crit.title,
            "text": crit.standard,
            "mapped_by": "llm",
            "reviewed": False,
            "reason": sel.get('reason', ''),
        })
        for ref in crit.related_laws:
            targets = ref.articles or [(None, None)]
            for aid, gtitle in targets:
                key = (ref.law_key or ref.law_name, aid)
                from_labels.setdefault(key, []).append(crit.label)
                if key not in law_entries:
                    law_entries[key] = (ref.law_key, ref.law_name, aid, gtitle)

    violated = [_law_entry(lk, ln, aid, gt, laws, from_labels[key], hpd)
                for key, (lk, ln, aid, gt) in law_entries.items()]
    labels_by_code = {e['law_code']: from_labels[key] for e, key in zip(violated, law_entries)}

    notes = []
    if llm_note:
        notes.append(llm_note)
    if narrower is not None and violated:
        violated, nnotes = _apply_narrowing(violated, labels_by_code, laws, finding, narrower)
        notes.extend(nnotes)
    # 원문 보유 조문을 앞에, 개인정보 보호법 -> 고시 -> 그 외, 조문 번호 순
    violated.sort(key=_sort_key)

    out["violated_laws"] = violated
    out["isms_p"] = isms_entries

    if status == '수동확인':
        notes.append("판정이 '수동확인'인 항목: 취약 여부를 사람이 확인해야 함")
    if isms_entries and not violated and not any('제외한 조문' in n for n in notes):
        notes.append("선택된 기준에 [관련 법규]가 없어 조문을 비움 (팀 합의: LLM으로 채우지 않음)")
    if notes:
        out["review_note"] = ' / '.join(notes)
    return out


def build_references(laws: dict) -> list:
    refs = [law.reference() for law in laws.values()]
    refs.append(dict(ISMSP_REF))
    return refs
