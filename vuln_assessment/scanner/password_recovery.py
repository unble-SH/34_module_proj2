import json
import os
import re
from typing import List, Literal
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, Field
import requests

# ----------------- 진단 환경 설정 -------------------------
BASE_URL = "http://localhost:5000/"

# ----------------- 취약점 진단 결과 스키마 -----------------
class ResponseFormat(BaseModel):
    """
    주요정보통신기반시설 취약점 평가 가이드 기반 진단 결과 규격 (팀 공통)
    """
    path: str = Field(description="취약점 점검 대상 URL 경로")
    content: List[str] = Field(description="재현 요청 또는 응답에서 식별된 취약점 증적 데이터")
    category: Literal[
        "취약한 비밀번호 복구 절차",
        "주석 내 정보 누출",
        "중요 정보 마스킹 미흡",
        "에러페이지 정보 노출"
    ] = Field(description="점검 항목 분류")
    result: Literal["vulnerable", "pass", "unknown"] = Field(
        description="가이드 기준에 따른 진단 결과 (취약: vulnerable, 양호: pass, 확인 불가: unknown)"
    )
    severity: Literal["high", "medium", "low"] = Field(
        description="""
        위험도 평가:
        - high: 임시 비밀번호가 웹 화면에 평문 노출되거나 고정된 규칙으로 즉시 재설정되는 경우
        - medium: 추가 인증 수단이 미흡하거나 비밀번호 복구 힌트가 노출되는 경우
        - low: 인증된 외부 채널(이메일/SMS)로 일회용 난수 링크가 전송되는 정상 절차
        """
    )
    reason: str = Field(description="가이드 평가 기준에 따른 세부 판단 근거")

# ----------------- PR-12 진단 로직 ------------------------
def check_password_recovery(session: requests.Session, url: str, client: OpenAI) -> ResponseFormat:
    """
    [PR-12] 취약한 비밀번호 복구 절차 진단 수행
    - app.py의 /find_password 엔드포인트에 맞춘 파라미터 전송 (username, pw_question, pw_answer)
    - 응답 본문 내 고정/단순 임시 비밀번호("temp1234!") 화면 노출 여부 추출
    - OpenAI Structured Outputs를 통한 자동 판정
    """
    find_pw_url = urljoin(url, "/find_password")

    # 1. app.py의 request.form 규격에 맞춘 테스트 페이로드
    test_payload = {
        "username": "student1",
        "pw_question": "가장 좋아하는 음식은?",
        "pw_answer": "pizza"
    }

    try:
        response = session.post(find_pw_url, data=test_payload, timeout=5)
        response_text = response.text
    except Exception as e:
        print(f"[!] 대상 서버 연결 실패: {e}")
        return None

    # 2. BeautifulSoup으로 응답 본문 내 임시 비밀번호 노출 증적 추출
    soup = BeautifulSoup(response_text, "html.parser")
    evidence_texts = []

    # 태그 내 임시 비밀번호 관련 키워드 탐색
    for tag in soup.find_all(["p", "div", "span", "alert", "h4", "li"]):
        text = tag.get_text(strip=True)
        if any(keyword in text for keyword in ["임시 비밀번호", "temp", "password", "비밀번호"]):
            evidence_texts.append(text)

    # 정규식 패턴 탐색 (태그 구조 외 직접 텍스트 대비)
    if not evidence_texts:
        matches = re.findall(r"(?:임시\s*비밀번호|비밀번호)[:\s]*([^\s<]+)", response_text)
        if matches:
            evidence_texts = [f"추출된 비밀번호: {m}" for m in matches]

    # 3. LLM 분석용 데이터 및 가이드라인 프롬프트 구성
    diagnostic_evidence = {
        "target_url": find_pw_url,
        "request_data": test_payload,
        "extracted_content": evidence_texts if evidence_texts else [response_text[:300]]
    }

    system_prompt = f"""
    당신은 웹 취약점 진단 및 보안 컴플라이언스 전문가입니다.
    대상 URL({find_pw_url})의 비밀번호 복구 절차 점검 데이터를 분석하여 결과를 도출하세요.

    [주요정보통신기반시설 기술적 취약점 분석·평가 가이드 - PR-12 취약한 비밀번호 복구 절차]
    - 양호: 비밀번호 재설정 시 난수를 이용하여 인증된 사용자 메일이나 SMS로 임시 비밀번호 또는 재설정 링크가 전송되는 경우
    - 취약: 비밀번호 재설정 시 일정 패턴으로 재설정되고 웹 사이트 화면에 바로 출력될 경우

    제공된 점검 데이터(extracted_content)에 임시 비밀번호가 평문으로 화면에 노출되었는지, 고정된 패턴인지 평가하고 규격에 맞춰 JSON 형태로 응답하세요.
    """

    # 4. OpenAI 호출 (Structured Outputs)
    completion = client.beta.chat.completions.parse(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(diagnostic_evidence, ensure_ascii=False)}
        ],
        response_format=ResponseFormat
    )

    return completion.choices[0].message.parsed


if __name__ == "__main__":
    load_dotenv()
    client = OpenAI()
    session = requests.Session()

    print("[*] PR-12: 취약한 비밀번호 복구 절차 진단 시작...")
    diag_result = check_password_recovery(session, BASE_URL, client)

    if diag_result:
        result_dict = diag_result.model_dump()
        print("\n[진단 완료]")
        print(json.dumps(result_dict, indent=2, ensure_ascii=False))

        # JSON 결과 파일 저장
        output_filename = "PR-12_result.json"
        with open(output_filename, "w", encoding="utf-8") as f:
            json.dump(result_dict, f, indent=2, ensure_ascii=False)
        print(f"\n[+] 결과 파일 저장 완료: '{output_filename}'")
    else:
        print("[!] 진단 실패: 서버 응답을 확인하지 못했습니다.")