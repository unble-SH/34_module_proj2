"""모듈 3 실행 진입점.

사용법
  python -m module3 run 입력.json -o 출력.json [--model gpt-4.1-mini] [--offline] [--no-cache]
  python -m module3 selftest            # LLM 없이 로더·조립 점검
"""
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from pydantic import ValidationError

from .adapters import looks_like_scanner_output, to_scan_input
from .builder import MAPPED_STATUSES, build_finding, build_references, flag_inconsistencies
from .config import ENV_FILE, MODULE_DIR, NARROW_PROMPT_VERSION, OPENAI_MODEL, PROMPT_VERSION, SCHEMA_VERSION
from .ismsp_loader import load_ismsp
from .law_loader import load_all_laws, norm_title
from .schemas import IsmsPMapping, ModuleOutput, ScanInput


def log(msg: str):
    print(msg, flush=True)


def load_input(path: Path):
    """JSON 파일을 읽는다. 스캐너의 print() 출력을 그대로 저장한 파이썬 리터럴('…' 따옴표)도 받아 준다."""
    text = path.read_text(encoding='utf-8')
    try:
        return json.loads(text)
    except json.JSONDecodeError as je:
        import ast
        try:
            data = ast.literal_eval(text.strip())
        except (ValueError, SyntaxError):
            raise SystemExit(f"입력 파일을 읽을 수 없음 ({path.name}): JSON도 파이썬 리터럴도 아님. {je}")
        log("입력이 JSON이 아니라 파이썬 print 형식이라 변환해서 읽음 (가능하면 json.dump로 저장해 주세요)")
        return data


def run(input_path: Path, output_path: Path, model: str, offline: bool, use_cache: bool,
        target_url: str = "", scan_id: str = None) -> dict:
    load_dotenv(ENV_FILE)
    from .mapper import Mapper

    laws = load_all_laws()
    ismsp = load_ismsp()
    data = load_input(input_path)
    if looks_like_scanner_output(data):       # 스캐너(ResponseFormat) 형식이면 ScanInput으로 변환
        kw = {k: v for k, v in (('target_url', target_url), ('scan_id', scan_id)) if v}
        data = to_scan_input(data, **kw)
        log(f"스캐너 형식 입력 감지: 항목 {len(data['findings'])}건을 변환함")
    try:
        ScanInput.model_validate(data)        # 입력 구조 검증 (모르는 필드는 허용)
    except ValidationError as e:
        raise SystemExit(f"입력 JSON 구조 오류 ({input_path.name}):\n{e}")
    scan_id = data.get('scan_id', 'SCAN')
    mapper = Mapper(ismsp, model=model, use_cache=use_cache, offline=offline, log=log)

    findings_out = []
    for idx, f in enumerate(data.get('findings', [])):
        label = f"{f.get('item_id', '?')} {f.get('title', '')} [{f.get('status', '')}]"
        if f.get('status') not in MAPPED_STATUSES:
            log(f"- {label}: 매핑 생략")
            selection, note = [], None
        else:
            try:
                selection, note = mapper.map(f)
            except Exception as e:
                selection, note = [], f"LLM 호출 실패: {type(e).__name__}: {str(e)[:120]}"
            picked = ', '.join(s['criterion_id'] for s in selection) or '없음'
            log(f"- {label}: ISMS-P {picked}" + (f"  ({note})" if note else ''))
        built = build_finding(f, idx, scan_id, selection, note, ismsp, laws, narrower=mapper.narrow)
        if built['violated_laws'] or built['isms_p']:
            laws_txt = ', '.join(f"{v['law_code']}{'(' + v['paragraph'] + ')' if v['paragraph'] else ''}"
                                 for v in built['violated_laws']) or '없음'
            log(f"    조문: {laws_txt}" + ("  (제외 있음, review_note 참고)" if '제외한 조문' in built.get('review_note', '') else ''))
        findings_out.append(built)

    flagged = flag_inconsistencies(findings_out)
    if flagged:
        log(f"! 같은 유형 항목 간 판단 불일치 {flagged}건 → review_note 표시")

    out = {
        "schema_version": SCHEMA_VERSION,
        "scan_id": scan_id,
        "scan_date": data.get('scan_date'),
        "target_system": data.get('target_system'),
        "mapping": {
            "method": "llm+rule",
            "model": model,
            "prompt_version": f"{PROMPT_VERSION}/{NARROW_PROMPT_VERSION}",
            "generated_at": datetime.now().isoformat(timespec='seconds'),
            "llm_calls": mapper.calls,
            "cache_hits": mapper.cache_hits,
            "tokens": {
                "prompt": mapper.prompt_tokens,
                "prompt_cached": mapper.cached_tokens,
                "completion": mapper.completion_tokens,
                "estimated_cost_usd": mapper.cost_estimate(),
            },
        },
        "references": build_references(laws),
        "findings": findings_out,
    }
    ModuleOutput.model_validate(out)          # 출력 계약 검증. 어긋나면 여기서 예외 (코드 버그)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
    cost = mapper.cost_estimate()
    log(f"저장: {output_path}  (LLM 호출 {mapper.calls}회, 캐시 {mapper.cache_hits}회, "
        f"토큰 입력 {mapper.prompt_tokens:,} (캐시 {mapper.cached_tokens:,}) / 출력 {mapper.completion_tokens:,}, "
        f"예상 비용 {'$' + format(cost, '.4f') if cost is not None else '모델 가격 미등록'})")
    return out


def selftest() -> int:
    ok = True
    laws = load_all_laws()
    for key, law in laws.items():
        print(f"[{key}] {law.name} | {law.version} | 시행 {law.effective_date} | ref_id {law.ref_id}")
        print(f"    조문 {len(law.articles)}개 (예정본만 있는 조문 {sum(1 for a in law.articles.values() if not a.in_force)}개), "
              f"예정본 {len(law.future_versions)}개 {sorted(law.future_versions)}")
        if law.dropped_duplicates:
            print(f"    ! 현행본이 두 벌인 조문: {law.dropped_duplicates}")
            ok = False
    pipa = laws.get('PIPA')
    if pipa:
        a1 = pipa.get('제1조')
        print(f"    제1조 제목 = {a1.title!r} (부칙 제1조(시행일)가 아니어야 함)")
        ok &= a1.title == '목적'
        a2 = pipa.get('제2조')
        print(f"    제2조 현행본 in_force={a2.in_force}, 본문 첫 줄: {a2.text.splitlines()[0][:70]}")
        ok &= a2.in_force and '2026. 9. 8.' not in a2.text.splitlines()[0]
        a = pipa.get('제28조의12')
        print(f"    제28조의12 in_force={a.in_force} note={a.note}")
        ok &= a.in_force is False
        print(f"    후보 목록(현행, 중복 제거) {len(pipa.candidate_list())}개")
    safe = laws.get('SAFE')
    if safe:
        for aid in ('제5조', '제6조', '제12조', '제15조', '제18조'):
            a = safe.get(aid)
            print(f"    {aid} {a.title!r} in_force={a.in_force} note={a.note}")

    ismsp = load_ismsp()
    with_law = [c for c in ismsp.criteria.values() if c.related_laws]
    print(f"[ISMS-P] 기준 {len(ismsp.criteria)}개, 관련 법규 있는 기준 {len(with_law)}개, "
          f"미등록 법령명 {sorted(ismsp.unknown_law_names) or '없음'}")
    ok &= len(ismsp.criteria) == 101
    missing = []
    for c in with_law:
        for ref in c.related_laws:
            law = laws.get(ref.law_key)
            if law is None:
                continue
            for aid, gtitle in ref.articles:
                art = law.get(aid)
                if art is None:
                    missing.append((c.id, ref.law_key, aid, '조문 없음'))
                elif art.title and gtitle and norm_title(art.title) != norm_title(gtitle):
                    missing.append((c.id, ref.law_key, aid, f"제목: 안내서 '{gtitle}' / 원문 '{art.title}'"))
    print(f"    안내서 관련 법규 vs 원문 대조: 문제 {len(missing)}건")
    for m in missing[:20]:
        print(f"      - {m}")

    # 항 분리 점검
    for key, aid in (('SAFE', '제6조'), ('SAFE', '제5조'), ('PIPA', '제29조'), ('PIPA', '제34조')):
        paras = laws[key].get(aid).paragraphs()
        print(f"    {key} {aid} 항 {len(paras)}개: {[p[0] for p in paras]}")
    ok &= [p[0] for p in safe.get('제6조').paragraphs()] == ['제1항', '제2항', '제3항', '제4항', '제5항']   # ⑥ 삭제 제외
    ok &= pipa.get('제29조').paragraphs() == []

    # LLM 없이 조립 점검 (항 판단은 가짜 함수)
    fake = {"item_id": "W-00", "title": "테스트", "status": "취약", "severity": "상",
            "asset": {"id": "WEB01", "name": "웹서버", "handles_personal_data": True}, "evidence": "테스트"}
    sel = [{"criterion_id": "2.6.3", "relevance": "primary", "reason": "테스트"}]

    def fake_narrower(f, candidates):
        return {"PIPA-29": {"applicable": True, "paragraphs": [], "reason": "테스트"},
                "SAFE-5": {"applicable": True, "paragraphs": ["제1항"], "reason": "테스트"},
                "SAFE-6": {"applicable": True, "paragraphs": ["제3항"], "reason": "테스트"},
                "SAFE-12": {"applicable": False, "paragraphs": [], "reason": "출력·복사와 무관"}}, None

    out = build_finding(fake, 0, "SCAN-TEST", sel, None, ismsp, laws, narrower=fake_narrower)
    print(f"[조립] isms_p {len(out['isms_p'])}개, violated_laws {len(out['violated_laws'])}개:")
    for v in out['violated_laws']:
        print(f"    - {v['law_code']} {v['article']}({v['article_title']}) paragraph={v['paragraph']} "
              f"mapped_by={v['mapped_by']} in_force={v['in_force']} {v.get('review_note', '')}")
    print(f"    review_note: {out.get('review_note')}")
    ok &= [v['law_code'] for v in out['violated_laws']] == ['PIPA-29', 'SAFE-5', 'SAFE-6'] and 'SAFE-12' in out.get('review_note', '')
    print("\n결과:", "정상" if ok else "확인 필요")
    return 0 if ok else 1


def export_schemas(out_dir: Path) -> list:
    """팀 공유용 JSON 스키마 파일 생성 (입력, 출력, LLM 응답)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, model in (('input', ScanInput), ('output', ModuleOutput), ('llm_response', IsmsPMapping)):
        path = out_dir / f"{name}.schema.json"
        path.write_text(json.dumps(model.model_json_schema(), ensure_ascii=False, indent=2), encoding='utf-8')
        written.append(path)
    return written


def main(argv=None):
    sys.stdout.reconfigure(encoding='utf-8')
    p = argparse.ArgumentParser(prog='module3', description='취약점 -> ISMS-P 기준 -> 법령 조문 매핑')
    sub = p.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run', help='입력 JSON을 처리해 출력 JSON 생성')
    r.add_argument('input', type=Path)
    r.add_argument('-o', '--output', type=Path, default=None)
    r.add_argument('--model', default=OPENAI_MODEL)
    r.add_argument('--offline', action='store_true', help='LLM 호출 없이 캐시만 사용')
    r.add_argument('--no-cache', action='store_true', help='캐시를 읽지 않고 항상 LLM 호출')
    r.add_argument('--target-url', default='', help='스캐너 형식 입력일 때 점검 대상 URL (asset 이름에 사용)')
    r.add_argument('--scan-id', default=None, help='스캐너 형식 입력일 때 scan_id')
    sub.add_parser('selftest', help='로더와 조립 점검 (LLM 미사용)')
    s = sub.add_parser('schema', help='입력·출력·LLM 응답 JSON 스키마 파일 생성')
    s.add_argument('-o', '--out-dir', type=Path, default=MODULE_DIR / 'schemas')
    args = p.parse_args(argv)

    if args.cmd == 'selftest':
        return selftest()
    if args.cmd == 'schema':
        for path in export_schemas(args.out_dir):
            log(f"생성: {path}")
        return 0
    output = args.output or args.input.with_name(args.input.stem + '_mapped.json')
    run(args.input, output, model=args.model, offline=args.offline, use_cache=not args.no_cache,
        target_url=args.target_url, scan_id=args.scan_id)
    return 0


if __name__ == '__main__':
    sys.exit(main())
