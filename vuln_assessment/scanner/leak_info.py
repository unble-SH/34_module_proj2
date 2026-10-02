import requests
import re
import os

from openai import OpenAI
from dotenv import load_dotenv

from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin

import json
from typing import Literal, List
from pydantic import BaseModel, Field

#-----------------전역 변수 선언-------------------------
url = "http://localhost:5000/"
data = {
    "username" : "student1",
    "password" : "student123"
}

keywords = [ # 로그인 후 개인정보 접근 페이지 후보
    "mypage",
    "my-page",
    "profile",
    "account",
    "member",
    "user",
    "userinfo",
    "user-info",
    "my-information",
    "my-info",
    "personal",
    "personal-info",
    "privacy",
    "setting",
    "settings",
    "회원",
    "내정보",
    "개인정보",
    "프로필",
    "계정"
]

patterns = { # 주석 내 정보 확인 패턴
        "account_info": [
            r"\b(?:id|userid|user_id|username|password|passwd|pwd|account)\b",
            r"\b(?:아이디|사용자명|사용자\s*ID|계정|비밀번호|패스워드)\b"
        ],

        "debug_info": [
            r"\b(?:debug|debugging|trace|stack\s*trace|exception|error|log)\b",
            r"\b(?:디버그|디버깅|스택\s*트레이스|예외|에러|로그)\b"
        ],
    }
#-------------------------------------------------------

#------------------openai 출력 구조화--------------------
class ResponseFormat(BaseModel):
    path: str = Field(description="정보가 확인된 url 경로")
    content : List[str] = Field(description="확인된 정보")
    category: Literal["주석 내 정보 누출", "중요 정보 마스킹 미흡", "에러페이지 정보 노출"] = Field(description="발견된 취약점 유형")
    result: Literal["vulnerable", "pass", "unknown"] = Field(description="노출된 정보를 취약, 양호, 판단 불가로 구분")
    severity: Literal["high", "medium", "low"] = Field(description="""
                                                노출된 정보의 위험성. 
                                                취약하지 않은 정보거나 제대로 마스킹처리 되어있는 경우, result가 pass인 경우 low,
                                                중요 정보가 아닌 개인정보가 노출되거나 다른 취약점과 연계되어 위험할 수 있는 정보이거나 result가 unknown이면 medium,
                                                중요 정보가 마스킹 없이 노출되거나 즉시 취약점이 될 수 있는 정보가 노출되면 high
                                                """)
    reason: str = Field(description="판단 근거")
#-------------------------------------------------------

def check_comment(session, url, client):
    """
    제공된 url의 html 파일 내의 주석 검사<br>
    주석에 계정 정보, 디버깅 정보 등이 존재하는지 확인
    """
    r = session.get(url)

    soup = BeautifulSoup(r.text, 'html.parser')
    comments = soup.find_all(string = lambda text: isinstance(text, Comment)) # 페이지 내 주석 확인

    results = []

    for comment in comments:
        text = str(comment).strip()

        if not text:
            continue

        matched_types = []

        for info_type, regex_list in patterns.items():
            for pattern in regex_list:
                if re.search(pattern, text, re.IGNORECASE):
                    matched_types.append(info_type)
                    break

        if matched_types:
            results.append({
                "comment": text,
                "types": matched_types
            })

    if not results:
        return None # 발견된 패턴이 없으면 None 반환
    
    response = client.responses.parse(
        model="gpt-5.5",
        input=[
            {
                "role" : "system",
                "content" : f"""
                다음은 {url}경로의 html 주석 내 계정 정보, 디버그 정보로 추정되는 내용임
                "comment"는 주석의 내용, "types"는 추측되는 해당 내용의 유형
                실제로 중요한 정보가 주석에 포함되었는지 판단할 것
                확실한 근거가 없다면 unknown
                """ 
            },
            {
                "role" : "user",
                "content" : str(results)
            }
        ],
        text_format=ResponseFormat
    )

    return response.output_parsed

def find_mypage(session, url):
    """
    로그인된 상태의 메인 페이지에서 개인정보를 확인할 수 있는 링크 탐색<br>
    keywards 기반
    """
    r = session.get(url)
    soup = BeautifulSoup(r.text, "html.parser")

    results = []
    for a in soup.find_all("a", href=True): # <a></a> 태그 탐색
        next_url = urljoin(url, a["href"])
        for keyword in keywords:
            if keyword in next_url: # keyward가 존재하면 개인정보 확인 링크로 판단
                results.append(next_url)
                break

    return results

def find_personal_info(session, url):
    """
    개인정보를 확인할 수 있는 페이지에서 출력되는 개인정보 확인<br>
    {"이름":"김철수"} 형태
    """
    r = session.get(url)
    soup = BeautifulSoup(r.text, "html.parser")

    result = {}

    # 개인 정보가 테이블 형태로 출력될 때

    for tr in soup.find_all("tr"):
        cells = tr.find_all(["th", "td"], recursive=False)

        if len(cells) < 2:
            continue

        # 일반적인 [항목, 값] 구조
        key = cells[0].get_text(" ", strip=True)
        value = cells[1].get_text(" ", strip=True)

        if key and value:
            result[key] = value

    # 개인 정보가 label + input 태그 형태로 출력될 때

    for label in soup.find_all("label"):

        key = label.get_text(" ", strip=True)

        if not key:
            continue

        # label의 for 속성 확인
        input_id = label.get("for")

        if input_id:
            input_tag = soup.find("input", id=input_id)

            if input_tag:
                value = input_tag.get("value", "").strip()

                if value:
                    result[key] = value

    # label과 input이 for로 연결되어있지 않은 경우

    for label in soup.find_all("label"):

        key = label.get_text(" ", strip=True)

        if not key or key in result:
            continue # 키가 없거나 이미 찾았다면 생략

        # label 다음에 있는 input 탐색
        input_tag = label.find_next("input")

        if input_tag:
            value = input_tag.get("value", "").strip()

            if value:
                result[key] = value

    return result

def check_personal_info(session, url, client):
    """
    개인정보 및 중요정보가 노출되는지, 노출된 정보가 취약한지 판단
    """
    p_info = find_personal_info(session, url) # personal info

    if not p_info: # 찾은 내용이 없다면 None 반환
        return None

    response = client.responses.parse(
        model="gpt-5.5",
        input=[
            {
                "role" : "system",
                "content" : f"""
                다음은 {url}경로에서 표시되는 정보들로, 로그인한 상태에서 접근 가능한 본인의 개인정보임
                딕셔너리 형태이며 key는 분류, value는 값
                개인정보 및 중요한 정보가 노출되는지, 취약한지 확인할 것
                개인정보는 이름, 생년월일, 연락처 등
                중요 정보는 비밀번호, 금융정보, 주민등록번호 등
                중요 정보가 있더라도 적절하게 마스킹이 되어있다면 양호한 것으로 판단
                확실한 근거가 없다면 unknown
                """ 
            },
            {
                "role" : "user",
                "content" : str(p_info)
            }
        ],
        text_format=ResponseFormat
    )

    return response.output_parsed

def check_leak_info(url, client):
    session = requests.Session()
    results = []

    # 로그인 화면 검사 및 로그인
    login_url = urljoin(url, "/login")
    result = check_comment(session, login_url, client)
    if result: # 검사 결과가 존재하면 append
        results.append(result)

    r = session.post(login_url, data=data) # data : student1/student123
    if r.history[0].status_code // 100 != 3: # redirect 되지 않았다면 로그인 실패로 간주
        print("로그인 실패")
        return results

    info_candidate = find_mypage(session, r.url) # 개인정보 열람이 가능할 것으로 추정되는 경로들

    for path in info_candidate:
        result = check_comment(session, path, client) # 각 경로의 주석 확인
        if result:
            results.append(result)

        result = check_personal_info(session, path, client) # 각 경로의 개인정보 노출 확인
        if result:
            results.append(result)

    return results


if __name__=="__main__":
    load_dotenv()
    client = OpenAI() # 환경 변수 OPENAI_API_KEY 자동 인식
    url = "http://localhost:5000/"

    print(check_leak_info(url, client))