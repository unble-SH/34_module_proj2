import requests

from bs4 import BeautifulSoup
from urllib.parse import urljoin
import uuid

#-------------------------------------------------------
# 전역 변수 선언
#-------------------------------------------------------
vuln_pwd_pattern = {
    "char" : ["student", "qwer", "asdf", "abcd", "admin", "administator", "rhksflwk", "instructor", "teacher", "mentor", "tutor", ""],
    "num" : ["1", "2", "3", "4", "123", "321", "1111", "2222", ""]
}

reason_format = {
    "vuln_pwd_login" : "관리자 및 사용자 계정의 비밀번호가 유추하기 쉬운 값으로 설정되어 있음",
    "pass_pwd_login" : "관리자 및 사용자 계정의 비밀번호가 유추하기 어렵게 설정되어 있음",
    "vuln_pwd_register" : "1234와 같은 간단한 비밀번호로 회원가입 가능",
    "pass_pwd_register" : "s@f3P4ssW0rd와 같은 복잡한 비밀번호로 회원가입 가능"
}

#-------------------------------------------------------
# 함수 정의
#-------------------------------------------------------
def check_vuln_login(login_url, id):
    """
    관리자 및 사용자 계정의 비밀번호가 유추하기 쉬운 값으로 설정되어 있는지 확인<br>
    몇 가지 조합의 간단한 비밀번호로 로그인을 시도하여 로그인에 성공하면 True, 실패하면 False를 반환
    """
    for c in vuln_pwd_pattern["char"]:
        for n in vuln_pwd_pattern["num"]:
            r = requests.post(login_url, data={"username":id, "password":c+n}) # admin1234, student123 등의 비밀번호 시도
            if r.history and r.history[0].status_code // 100 == 3: # redirect 됐다면 = 로그인에 성공했다면
                return (True, c+n)
    return (False, None)

def generate_value(name, input_type="text"):
    """
    input의 name/type을 기반으로 테스트용 값을 생성한다.
    """

    name = (name or "").lower()

    if input_type == "email" or "email" in name:
        return f"test@example.com"

    if input_type == "password" or "password" in name:
        return "1234"

    if (
        "username" in name
        or "user_id" in name
        or name == "id"
        or "login" in name
    ):
        return "testuser" + str(uuid.uuid4())[:4] # 반복 테스트 시 충돌을 막기 위해 랜덤값 추가

    if "phone" in name or "tel" in name or "mobile" in name:
        return "010-1234-5678"

    if "name" in name:
        return "테스트사용자"

    if "birth" in name:
        return "2000-01-01"

    if "address" in name:
        return "테스트 주소"

    if "zipcode" in name or "zip" in name:
        return "12345"

    if "date" in name:
        return "2000-01-01"

    # 기본값
    return "test"


def fill_signup_form(signup_url):
    """
    회원가입 페이지를 가져와 form을 분석하고
    자동으로 데이터를 생성한다.
    """

    response = requests.get(signup_url)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")

    form = soup.find("form")

    if form is None:
        raise RuntimeError("회원가입 form을 찾을 수 없습니다.")

    data = {}

    # --------------------------------------------------
    # input 처리
    # --------------------------------------------------

    for tag in form.find_all("input"):

        name = tag.get("name")

        # name이 없으면 서버에 전송할 수 없으므로 무시
        if not name:
            continue

        input_type = tag.get("type", "text").lower()

        # hidden input
        if input_type == "hidden":
            data[name] = tag.get("value", "")
            continue

        # checkbox
        if input_type == "checkbox":
            # checked가 기본값이면 해당 value 사용
            if tag.has_attr("checked"):
                data[name] = tag.get("value", "on")

            continue

        # radio
        if input_type == "radio":
            if tag.has_attr("checked"):
                data[name] = tag.get("value", "on")

            continue

        # submit/button은 직접 전송하지 않음
        if input_type in ("submit", "button", "reset", "image", "file"):
            continue

        value = generate_value(name, input_type)

        data[name] = value

    # --------------------------------------------------
    # select 처리
    # --------------------------------------------------

    for select in form.find_all("select"):

        name = select.get("name")

        if not name:
            continue

        selected_value = None

        for option in select.find_all("option"):

            value = option.get("value")

            # value 속성이 존재하고 빈 문자열이 아니면 선택
            if value:
                selected_value = value
                break

        if selected_value is not None:
            data[name] = selected_value

    return data

def check_vuln_register(signup_url):
    """
    회원가입 시 비밀번호 정책의 복잡성 확인<br>
    낮은 복잡성의 비밀번호로 회원가입 성공 시 True, 실패 이후 비밀번호를 복잡하게 바꿨을 때 회원가입에 성공하면 False
    """
    data = fill_signup_form(signup_url)

    r = requests.post(signup_url, data=data)
    if r.history[0].status_code // 100 == 3: # redirect 되면 회원가입 성공으로 판단
        return True

    for key in data.keys():
        if "password" in key:
            data[key] = "s@f3P4ssW0rd"

    r = requests.post(signup_url, data=data)
    if r.history[0].status_code // 100 == 3: # redirect 되면 회원가입 성공으로 판단
            return False # 비밀번호만 바꿨을 때 로그인에 성공하면 높은 복잡도의 비밀번호 정책이 설정된 것으로 판단

    return None # 두 번 모두 회원가입 실패 시 별도의 문제

def make_format(path, content, category, result, severity, reason):
    return {
        "path" : path,
        "content" : [content],
        "category" : category,
        "result" : result,
        "severity" : severity,
        "reason" : reason
    }

#-------------------------------------------------------
# 메인 모듈에서 호출할 함수
#-------------------------------------------------------
def check_vuln_pwd(url):
    result = []
    #------------------
    # 로그인 체크
    #------------------
    login_url = urljoin(url, "/login")

    is_vuln, pwd = check_vuln_login(login_url, "student1")
    data = f"id:student1 password:{pwd}"

    if is_vuln:
        result.append(make_format(login_url, data, "유추 가능한 비밀번호", "vulnerable", "high", reason_format["vuln_pwd_login"]))
    else:
        result.append(make_format(login_url, data, "유추 가능한 비밀번호", "pass", "low", reason_format["pass_pwd_login"]))

    #------------------
    # 회원가입 체크
    #------------------
    register_url = urljoin(url, "/register")

    is_vuln = check_vuln_register(register_url)

    if is_vuln == None:
        print("비밀번호 외의 문제로 회원가입 불가")
        return result
    
    if is_vuln:
        data = "id:testuser password:1234"
        result.append(make_format(register_url, data, "낮은 복잡도의 비밀번호 정책", "vulnerable", "high", reason_format["vuln_pwd_register"]))
    else:
        data = "id:testuser password:s@f3P4ssW0rd"
        result.append(make_format(register_url, data, "낮은 복잡도의 비밀번호 정책", "pass", "low", reason_format["pass_pwd_register"]))

    return result


#-------------------------------------------------------
# 테스트용
#-------------------------------------------------------
if __name__=="__main__":
    url = "http://localhost:5000/"

    print(check_vuln_pwd(url))