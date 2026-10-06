import requests
import re

from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, urlparse, urldefrag

#-------------------------------------------------------
# 전역 변수 선언
#-------------------------------------------------------
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

comment_patterns = { # 주석 내 정보확인 패턴
        "account_info": [
            r"\b(?:id|userid|user_id|username|password|passwd|pwd|account)\s*[:=]\s*[^\s<]+",
            r"\b(?:아이디|사용자명|사용자\s*ID|계정|비밀번호|패스워드)\s*[:=]\s*[^\s<]+"
        ],

        "debug_info": [
            r"\b(?:debug|debugging|trace|stack|stack\s*trace|exception|error|log)\b",
            r"\b(?:디버그|디버깅|스택|스택\s*트레이스|예외|에러|로그)\b"
        ]
}

info_patterns = {
        "account_number": r"\b\d{3,6}[- ]?\d{2,6}[- ]?\d{2,8}\b", # 계좌 번호 패턴,

        "card_number": r"\b(?:\d{4}[- ]?){3}\d{4}\b", # 카드 번호 패턴,
     
        "resident_registration_number": r"\b\d{6}-\d{7}\b", # 주민등록번호 패턴

        "pwd_placeholder_pattern" : # 비밀번호 란에 표시되는 것을 허용할 패턴
            r"^(?:입력|입력하세요|입력해 주세요|변경|변경할 비밀번호|새 비밀번호|새로운 비밀번호|현재 비밀번호|확인|비밀번호 확인)$",

        "pwd_masking_pattern" : r"^[*•●xX#]+$" # 비밀번호 마스킹 패턴
}

reason_format = { # 판단 근거 포매팅
    "vuln_comment" : "계정정보, 시스템 파악에 사용될 수 있는 디버그 정보 등이 주석에 존재",
    "pass_comment" : "주석 내에 중요하거나 민감한 정보가 포함되지 않음",
    "unknown_comment" : "주석에 노출된 정보의 중요도를 판단할 근거 부족",
    "vuln_info" : "주민등록번호, 금융 정보 등의 중요 정보가 마스킹 없이 노출되고 있음",
    "pass_info" : "중요 정보가 마스킹되어있거나 평문으로 노출되지 않음",
    "unknown_info" : "중요 정보가 노출되고 있는지 판단할 근거 부족"
}

category = {
    "comment" : "주석 내 정보 누출",
    "masking" : "중요 정보 마스킹 미흡",
    "error" : "에러 페이지 정보 누출"
}

#-------------------------------------------------------
# 모든 페이지의 주석을 확인하기 위해 링크 탐색
#-------------------------------------------------------
class WebCrawler:
    def __init__(self, base_url, session=None):
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()

        parsed = urlparse(self.base_url)
        self.allowed_netloc = parsed.netloc

        self.visited = set()
        self.results = []

    def normalize_url(self, url):
        """
        URL을 정규화한다.
        """
        url = urldefrag(url)[0]  # #fragment 제거

        parsed = urlparse(url)

        # http / https 이외에는 제외
        if parsed.scheme not in ("http", "https"):
            return None

        # 외부 도메인 제외
        if parsed.netloc != self.allowed_netloc:
            return None

        # 기본적으로 URL의 끝 '/' 차이 제거
        normalized = parsed._replace(
            fragment=""
        ).geturl().rstrip("/")

        return normalized

    def extract_links(self, html, current_url):
        """
        현재 HTML에서 같은 사이트의 링크를 추출한다.
        로그아웃 링크는 제외한다.
        """
        soup = BeautifulSoup(html, "html.parser")

        links = set()

        # 제외할 경로
        excluded_paths = {
            "/logout",
            "/signout",
        }

        for a in soup.find_all("a", href=True):
            href = a.get("href")

            if not href:
                continue

            # javascript:, mailto:, tel:, data: 등 제외
            if href.startswith((
                "javascript:",
                "mailto:",
                "tel:",
                "data:"
            )):
                continue

            absolute_url = urljoin(current_url, href)
            normalized_url = self.normalize_url(absolute_url)

            if not normalized_url:
                continue

            # URL에서 path만 추출
            path = urlparse(normalized_url).path

            # 로그아웃 링크 제외
            if path in excluded_paths:
                print(f"[SKIP] logout: {normalized_url}")
                continue

            links.add(normalized_url)

        return links

    def crawl(self, start_url=None):
        """
        start_url부터 재귀적으로 모든 페이지를 탐색한다.
        """
        if start_url is None:
            start_url = self.base_url

        start_url = self.normalize_url(start_url)

        if not start_url:
            return

        self._crawl_page(start_url)

    def _crawl_page(self, url):
        if url in self.visited:
            return

        self.visited.add(url)

        try:
            response = self.session.get(
                url,
                timeout=10,
                allow_redirects=True
            )

            final_url = self.normalize_url(response.url)

            result = {
                "url": url,
                "final_url": final_url,
                "status_code": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
                "links": []
            }

            self.results.append(result)

            print(
                f"      -> {response.status_code} "
                f"{response.url}"
            )

            # HTML인 경우에만 링크 탐색
            content_type = response.headers.get(
                "Content-Type",
                ""
            ).lower()

            if "text/html" not in content_type:
                return

            links = self.extract_links(
                response.text,
                response.url
            )

            result["links"] = sorted(links)

            # 발견한 링크를 재귀적으로 방문
            for link in sorted(links):
                self._crawl_page(link)

        except requests.RequestException as e:
            print(f"      [ERROR] {e}")

    def get_results(self):
        return self.results
    
    def get_urls(self):
        return [result["url"] for result in self.results]

#-------------------------------------------------------
# 함수 정의
#-------------------------------------------------------
def make_result(path, content, category, result, severity, reason):
    return {
        "path" : path,
        "content" : content,
        "category" : category,
        "result" : result,
        "severity" : severity,
        "reason" : reason
    }

def check_comment(session, base_url):
    """
    제공된 url 및 연결된 링크의 html 파일 내의 주석 검사<br>
    주석에 계정 정보, 디버깅 정보 등이 존재하는지 확인
    """
    crawler = WebCrawler(base_url, session=session)
    crawler.crawl()
    urls = crawler.get_urls() # base_url 및 href로 연결되는 url

    results = []

    for url in urls:
        r = session.get(url)

        soup = BeautifulSoup(r.text, 'html.parser')
        comments = soup.find_all(string = lambda text: isinstance(text, Comment)) # 페이지 내 주석 확인

        has_vuln = False
        for comment in comments:
            text = str(comment).strip()

            if not text:
                continue

            matched_types = []

            for info_type, regex_list in comment_patterns.items():
                for pattern in regex_list:
                    if re.search(pattern, text, re.IGNORECASE):
                        matched_types.append(info_type)
                        break
            if matched_types:
                has_vuln = True
                results.append(
                    make_result(
                        path=url, 
                        content={
                            "comment": text,
                            "types": matched_types}, 
                        category=category["comment"], 
                        result="vulnerable", 
                        severity="high", 
                        reason=reason_format["vuln_comment"]))
        if not has_vuln:
            results.append(
                make_result(
                    path=url, 
                    content={}, 
                    category=category["comment"], 
                    result="pass", 
                    severity="low", 
                    reason=reason_format["pass_comment"]))

    return results

    
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

def check_personal_info(session, url):
    """
    개인정보 및 중요정보가 노출되는지, 노출된 정보가 취약한지 판단
    """
    p_info = find_personal_info(session, url) # personal info

    if not p_info:
        return None

    result = []
    for key in p_info.keys():
        if re.match(r"\b주민\s*(?:등록)?\s*번호\b", key):
            if re.match(info_patterns["resident_registration_number"], p_info[key]):
                result.append(make_result(url, {key:p_info[key]}, category["masking"], "vulnerable", "high", reason_format["vuln_info"]))
            continue
        if re.match(r"\b카드\s*번호\b", key):
            if re.match(info_patterns["card_number"], p_info[key]):
                result.append(make_result(url, {key:p_info[key]}, category["masking"], "vulnerable", "high", reason_format["vuln_info"]))
            continue
        if re.match(r'^(?:비밀번호|패스\s*워드|pass\s*word|passwd|pwd)$', key, re.IGNORECASE):
            if re.match(info_patterns["pwd_placeholder_pattern"], p_info[key]) or re.match(info_patterns["pwd_masking_pattern"], p_info[key]):
                continue # 비밀번호 placeholder이거나 마스킹되어있다면 양호한 것으로 판단
            result.append(make_result(url, {key:p_info[key]}, category["masking"], "vulnerable", "high", reason_format["vuln_info"]))
        if re.match(r"\b계좌\s*번호\b", key):
            if re.match(info_patterns["account_number"], p_info[key]):
                result.append(make_result(url, {key:p_info[key]}, category["masking"], "vulnerable", "medium", reason_format["vuln_info"]))
            continue

    if not result: # 취약한 값이 발견되지 않았으면 양호한 것으로 판단
         result.append(make_result(url, {}, category["masking"], "pass", "low", reason_format["pass_info"]))
         
    return result

#-------------------------------------------------------
# 메인 모듈에서 호출할 함수
#-------------------------------------------------------
def check_leak_info(url="http://localhost:5000"):
    """
    주어진 url에 대해 정보 누출 취약점이 존재하는지 확인
    """
    session = requests.Session()
    results = []
    data = {
            "username" : "student1",
            "password" : "student123"
            }

    # 로그인 화면 검사 및 로그인
    login_url = urljoin(url, "/login")
    if result := check_comment(session, login_url) : # 검사 결과가 존재하면
        results.extend(result)

    r = session.post(login_url, data=data)
    if r.history[0].status_code // 100 != 3: # redirect 되지 않았다면 로그인 실패로 간주
        print("로그인 실패")
        return results

    info_candidate = find_mypage(session, r.url) # 개인정보 열람이 가능할 것으로 추정되는 경로들

    if result := check_comment(session, r.url): # 로그인 이후 메인 페이지 기준 주석 확인
        results.extend(result) 

    for path in info_candidate:
        if result := check_personal_info(session, path): # 각 경로의 개인정보 노출 확인
            results.extend(result)

    return results

#-------------------------------------------------------
# 테스트용
#-------------------------------------------------------
if __name__=="__main__":
    from pprint import pprint
    url = "http://localhost:5000/"

    pprint(check_leak_info(url), sort_dicts=False, width=120)