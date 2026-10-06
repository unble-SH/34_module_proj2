import json
import requests

from dotenv import load_dotenv
from openai import OpenAI

from access_control import check_authz
from check_pwd_rule import check_vuln_pwd
from insufficient_auth import check_insufficient_auth
from leak_info import check_leak_info
from password_recovery import check_password_recovery


BASE_URL = "http://localhost:5000/"


def flatten_results(data):
    """
    scanner마다 다른 결과 형태를 하나의 list[dict] 형태로 통일한다.
    """
    results = []

    if data is None:
        return results

    # Pydantic 객체인 경우 dict로 변환
    if hasattr(data, "model_dump"):
        data = data.model_dump()

    # 리스트라면 안쪽까지 재귀적으로 펼침
    if isinstance(data, list):
        for item in data:
            results.extend(flatten_results(item))
        return results

    # 딕셔너리
    if isinstance(data, dict):
        # access_control.py는 {"results": [...]} 형태
        if "results" in data and isinstance(data["results"], list):
            results.extend(flatten_results(data["results"]))
        else:
            results.append(data)

    return results


def run_all_scans(url=BASE_URL):
    """
    5개 취약점 진단 모듈을 차례대로 실행하고
    결과를 하나의 리스트로 통합한다.
    """
    load_dotenv()

    client = OpenAI()
    session = requests.Session()

    all_results = []
    errors = []

    # 1. 정보 누출
    try:
        print("[1/5] 정보 누출 진단 시작")
        result = check_leak_info(url, client)
        all_results.extend(flatten_results(result))
    except Exception as e:
        errors.append({
            "scanner": "leak_info",
            "error": f"{type(e).__name__}: {e}"
        })

    # 2. 약한 비밀번호
    try:
        print("[2/5] 약한 비밀번호 진단 시작")
        result = check_vuln_pwd(url)
        all_results.extend(flatten_results(result))
    except Exception as e:
        errors.append({
            "scanner": "weak_password",
            "error": f"{type(e).__name__}: {e}"
        })

    # 3. 불충분한 인증
    try:
        print("[3/5] 불충분한 인증 절차 진단 시작")
        result = check_insufficient_auth(url)
        all_results.extend(flatten_results(result))
    except Exception as e:
        errors.append({
            "scanner": "insufficient_auth",
            "error": f"{type(e).__name__}: {e}"
        })

    # 4. 불충분한 권한 검증
    try:
        print("[4/5] 불충분한 권한 검증 진단 시작")

        # 1차 통합에서는 Rule 기반 결과만 사용
        # GPT를 여기까지 사용하면 항목별 API 호출이 많아질 수 있음
        result = check_authz(url, client=None)

        all_results.extend(flatten_results(result))
    except Exception as e:
        errors.append({
            "scanner": "access_control",
            "error": f"{type(e).__name__}: {e}"
        })

    # 5. 취약한 비밀번호 복구
    # 다른 진단에 사용하는 계정 상태에 영향을 줄 가능성을 고려해 마지막에 실행
    try:
        print("[5/5] 비밀번호 복구 절차 진단 시작")
        result = check_password_recovery(session, url, client)
        all_results.extend(flatten_results(result))
    except Exception as e:
        errors.append({
            "scanner": "password_recovery",
            "error": f"{type(e).__name__}: {e}"
        })

    return {
        "target": url,
        "results": all_results,
        "errors": errors
    }


if __name__ == "__main__":
    final_result = run_all_scans()

    print("\n===== 통합 진단 결과 =====")
    print(json.dumps(final_result, ensure_ascii=False, indent=2))