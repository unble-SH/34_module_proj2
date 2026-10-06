import json
import subprocess
import sys
from pathlib import Path
import webbrowser

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
        result = check_leak_info(url)
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

    # 통합 진단 결과를 JSON 파일로 저장
    output_dir = Path(__file__).resolve().parent / "output"
    output_dir.mkdir(exist_ok=True)

    output_path = output_dir / "scanner_result.json"
    output_path.write_text(
        json.dumps(final_result, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    print(f"\n스캐너 결과 저장 완료: {output_path}")


    # 저장된 스캐너 결과를 법률 분석 모듈에 전달
    legal_dir = Path(__file__).resolve().parent.parent / "legal_module"
    legal_output_path = output_dir / "legal_result.json"

    print("\n===== 법률 / ISMS-P 분석 시작 =====")

    subprocess.run(
        [
            sys.executable,
            "-m",
            "module3",
            "run",
            str(output_path),
            "-o",
            str(legal_output_path),
            "--model",
            "gpt-4.1-mini",
            "--target-url",
            final_result["target"],
        ],
        cwd=legal_dir,
        check=True,
    )

    print(f"\n법률 분석 결과 저장 완료: {legal_output_path}")


    # 법률 분석 결과를 보고서 생성 모듈에 전달
    report_dir = Path(__file__).resolve().parent.parent / "report_engine"

    print("\n===== 보고서 생성 시작 =====")

    subprocess.run(
        [
            sys.executable,
            "engine.py",
            "--scan",
            str(legal_output_path),
        ],
        cwd=report_dir,
        check=True,
    )

    print("\n보고서 생성 완료")


    # 이번 실행의 scan_id 확인
    legal_data = json.loads(
        legal_output_path.read_text(encoding="utf-8")
    )
    scan_id = legal_data["scan_id"]

    # 생성된 보고서 경로
    report_output_dir = report_dir / "out" / scan_id

    exec_pdf = report_output_dir / "exec_report.pdf"
    tech_pdf = report_output_dir / "tech_report.pdf"

    # 생성된 PDF 자동 열기
    if exec_pdf.exists():
        webbrowser.open(exec_pdf.resolve().as_uri())

    if tech_pdf.exists():
        webbrowser.open(tech_pdf.resolve().as_uri())
