"""스캐너 출력 -> 모듈 3 입력(ScanInput) 변환.

vuln_assessment/scanner/ 의 점검 모듈(예: leak_info.py)은 결과를 다음 pydantic 형식(ResponseFormat)의 목록으로 낸다.
    path, content: [str], category, result: vulnerable|pass|unknown, severity: high|medium|low, reason
이 형식을 모듈 3이 바로 받을 수 있도록 finding 단위로 바꾼다. 다른 스캐너도 같은 형식을 쓰면 변환기 하나로 끝난다.

판정 대응: vulnerable -> 취약, pass -> 양호, unknown -> 수동확인
중요도 대응: high -> 상, medium -> 중, low -> 하
"""
import re
from datetime import date
from urllib.parse import urlparse

RESULT_MAP = {"vulnerable": "취약", "pass": "양호", "unknown": "수동확인"}
SEVERITY_MAP = {"high": "상", "medium": "중", "low": "하"}

# 스캐너의 category -> 항목 코드. 모르는 category는 'W' + 순번으로 만든다.
# 코드 앞부분은 보고서 모듈(report_engine/data/item_catalog.json)의 KISA 항목 코드와 맞춘다:
#   IL 정보 누출, BF 약한 비밀번호 정책, IA 불충분한 인증 절차, IN 불충분한 권한 검증, PR 취약한 비밀번호 복구 절차.
# 보고서 모듈은 item_id의 '-' 앞부분으로 판단 기준·조치 방법을 찾으므로 여기만 맞으면 된다.
CATEGORY_CODES = {
    # 정보 누출 (leak_info.py)
    "정보 누출": "IL",
    "주석 내 정보 누출": "IL-COMMENT",
    "중요 정보 마스킹 미흡": "IL-MASKING",
    "에러페이지 정보 노출": "IL-ERRORPAGE",
    "에러 페이지 정보 누출": "IL-ERRORPAGE",
    # 약한 비밀번호 정책 (check_pwd_rule.py)
    "약한 비밀번호 정책": "BF",
    "유추 가능한 비밀번호": "BF-GUESS",
    "낮은 복잡도의 비밀번호 정책": "BF-POLICY",
    # 불충분한 인증 절차 (insufficient_auth.py)
    "불충분한 인증 절차": "IA",
    # 불충분한 권한 검증 (access_control.py)
    "불충분한 권한 검증": "IN",
    "비인증 접근": "IN-UNAUTH",
    "수직 권한 상승": "IN-VERTICAL",
    "타인 문의글 열람": "IN-READ",
    "타인 문의글 댓글 작성": "IN-COMMENT",
    # 취약한 비밀번호 복구 절차 (password_recovery.py)
    "취약한 비밀번호 복구 절차": "PR",
}
MAX_CONTENT_ITEMS = 5
MAX_CONTENT_LEN = 100


def looks_like_scanner_output(data) -> bool:
    """스캐너 형식인지 판별: 목록이거나, findings 없이 results 목록을 가진 dict."""
    items = data if isinstance(data, list) else (data.get('results') if isinstance(data, dict) and 'findings' not in data else None)
    return isinstance(items, list) and (not items or all(isinstance(i, dict) and 'result' in i and 'category' in i for i in items))


def _evidence(item: dict) -> str:
    parts = []
    if item.get('path'):
        parts.append(f"{item['path']} 경로에서 {item.get('category', '취약점')} 확인.")
    if item.get('reason'):
        parts.append(str(item['reason']).strip())
    content = [str(c)[:MAX_CONTENT_LEN] for c in (item.get('content') or [])][:MAX_CONTENT_ITEMS]
    if content:
        more = len(item.get('content') or []) - len(content)
        parts.append("확인된 정보: " + '; '.join(content) + (f" 외 {more}건" if more > 0 else ''))
    return ' '.join(parts)


def _asset(target_url: str, handles_personal_data: bool) -> dict:
    host = urlparse(target_url).netloc or target_url or "unknown"
    asset_id = re.sub(r'[^A-Za-z0-9]+', '-', host).strip('-').upper() or "WEB01"
    return {"id": asset_id, "name": f"웹 서비스 ({host})", "handles_personal_data": handles_personal_data}


def from_scanner_results(items: list, scan_id: str = None, target_url: str = "", scan_date: str = None,
                         handles_personal_data: bool = True, target_system: str = None) -> dict:
    """스캐너 결과 목록 -> ScanInput dict."""
    scan_date = scan_date or date.today().isoformat()
    scan_id = scan_id or f"SCAN-{scan_date.replace('-', '')}-001"
    asset = _asset(target_url, handles_personal_data)
    findings, seq = [], {}
    for item in items:
        category = str(item.get('category') or '취약점').strip()
        code = CATEGORY_CODES.get(category, 'W')
        seq[code] = seq.get(code, 0) + 1
        findings.append({
            "item_id": f"{code}-{seq[code]:02d}",
            "title": category,
            "status": RESULT_MAP.get(str(item.get('result', '')).lower(), '수동확인'),
            "severity": SEVERITY_MAP.get(str(item.get('severity', '')).lower(), '중'),
            "asset": dict(asset),
            "evidence": _evidence(item),
            "source": {"path": item.get('path'), "scanner_result": item.get('result'),
                       "scanner_severity": item.get('severity')},
        })
    return {
        "scan_id": scan_id,
        "scan_date": scan_date,
        "target_system": target_system or asset["name"],
        "findings": findings,
    }


def to_scan_input(data, **kw) -> dict:
    """스캐너 형식(목록 또는 {results, target_url, scan_id ...})을 ScanInput으로. 이미 ScanInput이면 그대로."""
    if isinstance(data, list):
        return from_scanner_results(data, **kw)
    if isinstance(data, dict) and 'findings' not in data and isinstance(data.get('results'), list):
        opts = {k: data[k] for k in ('scan_id', 'target_url', 'scan_date', 'handles_personal_data', 'target_system') if k in data}
        opts.update(kw)
        return from_scanner_results(data['results'], **opts)
    return data
