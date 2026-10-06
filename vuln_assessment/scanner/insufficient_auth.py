"""개인정보 변경 시 재인증 절차가 충분한지 동적으로 진단한다.

진단 중 개인정보를 일시적으로 변경하므로, 원본 정보를 수집한 뒤에는
성공/실패와 관계없이 ``finally`` 블록에서 원복을 시도한다.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup, Tag


PROFILE_PATH = "/student/profile"
MYPAGE_PATH = "/student/mypage"
LOGIN_PATH = "/login"
PERSONAL_FIELDS = ("name", "birth_date", "phone")
DEFAULT_TIMEOUT = 10

# 현재 비밀번호, OTP 등 재인증 필드에서 일반적으로 사용하는 이름이다.
# 실제 전송 필드는 HTML에서 읽으며, 아래 값은 재인증 필드 식별에만 사용한다.
REAUTH_FIELD_HINTS = (
    "current_password",
    "current-password",
    "password",
    "passwd",
    "pwd",
    "otp",
    "totp",
    "mfa",
    "auth_code",
    "auth-code",
    "verification_code",
    "verification-code",
    "verify_code",
    "verify-code",
    "pin",
)


@dataclass
class ProfileForm:
    """개인정보 수정 폼에서 추출한 전송 정보."""

    action: str
    method: str
    values: Dict[str, str]
    hidden_values: Dict[str, str]
    reauth_fields: List[str]


def _build_result(
    result: str,
    content: List[str],
    reason: str,
) -> Dict[str, object]:
    severity = {
        "vulnerable": "high",
        "unknown": "medium",
        "pass": "low",
    }[result]

    return {
        "path": PROFILE_PATH,
        "content": content,
        "category": "불충분한 인증 절차",
        "result": result,
        "severity": severity,
        "reason": reason,
    }


def _unknown(reason: str, content: Optional[List[str]] = None) -> Dict[str, object]:
    evidence = list(content or [])
    while len(evidence) < 3:
        evidence.append("진단을 완료하지 못해 확인할 수 없음")
    return _build_result("unknown", evidence, reason)


def _normalize_base_url(url: str) -> str:
    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Target URL은 http:// 또는 https://로 시작하는 유효한 URL이어야 합니다.")
    return url.rstrip("/") + "/"


def _same_origin(first_url: str, second_url: str) -> bool:
    first = urlparse(first_url)
    second = urlparse(second_url)
    return (first.scheme.lower(), first.netloc.lower()) == (
        second.scheme.lower(),
        second.netloc.lower(),
    )


def _response_summary(response: requests.Response) -> str:
    redirects = [item.status_code for item in response.history]
    redirect_text = " -> ".join(str(code) for code in redirects)
    if redirect_text:
        redirect_text += " -> "
    return f"HTTP {redirect_text}{response.status_code}, 최종 URL {response.url}"


def _is_login_response(response: requests.Response) -> bool:
    return urlparse(response.url).path.rstrip("/") == LOGIN_PATH


def _login_and_verify(
    session: requests.Session,
    base_url: str,
    username: str,
    password: str,
    timeout: int,
) -> Tuple[requests.Response, requests.Response]:
    login_url = urljoin(base_url, LOGIN_PATH.lstrip("/"))
    login_response = session.post(
        login_url,
        data={"username": username, "password": password},
        timeout=timeout,
        allow_redirects=True,
    )
    login_response.raise_for_status()

    # Redirect 유무만으로 로그인 성공을 판단하지 않는다. 같은 세션으로 인증이
    # 필요한 마이페이지를 요청하고, 로그인 화면으로 되돌아가지 않았는지 확인한다.
    mypage_url = urljoin(base_url, MYPAGE_PATH.lstrip("/"))
    mypage_response = session.get(
        mypage_url,
        timeout=timeout,
        allow_redirects=True,
    )
    mypage_response.raise_for_status()

    if _is_login_response(mypage_response) or username not in mypage_response.text:
        raise RuntimeError("인증이 필요한 마이페이지에서 로그인 상태를 확인하지 못했습니다.")

    return login_response, mypage_response


def _is_reauth_input(input_tag: Tag) -> bool:
    field_type = str(input_tag.get("type", "text")).lower()
    field_name = str(input_tag.get("name", "")).lower()
    if field_type in {"hidden", "submit", "button"}:
        return False
    if field_type == "password":
        return True
    return any(hint in field_name for hint in REAUTH_FIELD_HINTS)


def _parse_profile_form(response: requests.Response) -> ProfileForm:
    soup = BeautifulSoup(response.text, "html.parser")

    for form in soup.find_all("form"):
        named_inputs = {
            str(input_tag.get("name")): input_tag
            for input_tag in form.find_all("input")
            if input_tag.get("name")
        }
        if not set(PERSONAL_FIELDS).issubset(named_inputs):
            continue

        values = {
            field: str(named_inputs[field].get("value", ""))
            for field in PERSONAL_FIELDS
        }
        if not all(values.values()):
            raise ValueError("개인정보 수정 폼에서 기존 name, birth_date, phone 값을 읽지 못했습니다.")

        hidden_values = {
            name: str(input_tag.get("value", ""))
            for name, input_tag in named_inputs.items()
            if str(input_tag.get("type", "text")).lower() == "hidden"
        }
        reauth_fields = sorted(
            name
            for name, input_tag in named_inputs.items()
            if name not in PERSONAL_FIELDS and _is_reauth_input(input_tag)
        )

        action = urljoin(response.url, str(form.get("action") or response.url))
        method = str(form.get("method", "get")).lower()
        return ProfileForm(
            action=action,
            method=method,
            values=values,
            hidden_values=hidden_values,
            reauth_fields=reauth_fields,
        )

    raise ValueError("개인정보 수정 폼 또는 필수 필드(name, birth_date, phone)를 찾지 못했습니다.")


def _fetch_profile(
    session: requests.Session,
    profile_url: str,
    timeout: int,
) -> Tuple[requests.Response, ProfileForm]:
    response = session.get(profile_url, timeout=timeout, allow_redirects=True)
    response.raise_for_status()
    if _is_login_response(response):
        raise RuntimeError("개인정보 수정 페이지 요청이 로그인 페이지로 이동했습니다.")
    return response, _parse_profile_form(response)


def _submit_profile(
    session: requests.Session,
    form: ProfileForm,
    values: Dict[str, str],
    timeout: int,
) -> requests.Response:
    if form.method != "post":
        raise ValueError(f"개인정보 수정 폼의 method가 POST가 아닙니다: {form.method}")

    # CSRF 토큰과 같은 hidden 값은 유지하되 현재 비밀번호/OTP 값은 제공하지 않는다.
    payload = dict(form.hidden_values)
    payload.update({field: values[field] for field in PERSONAL_FIELDS})
    return session.post(
        form.action,
        data=payload,
        timeout=timeout,
        allow_redirects=True,
    )


def _test_phone(original_phone: str) -> str:
    return "010-8888-8888" if original_phone == "010-9999-9999" else "010-9999-9999"


def _same_profile(first: Dict[str, str], second: Dict[str, str]) -> bool:
    return all(first.get(field) == second.get(field) for field in PERSONAL_FIELDS)


def _response_shows_reauth_form(response: requests.Response) -> bool:
    soup = BeautifulSoup(response.text, "html.parser")
    return any(_is_reauth_input(tag) for tag in soup.find_all("input") if tag.get("name"))


def check_insufficient_auth(
    url: str,
    username: str = "student1",
    password: str = "student123",
) -> Dict[str, object]:
    """실제 HTTP 요청으로 개인정보 변경 시 재인증 누락 여부를 진단한다.

    ``vulnerable``은 재인증 정보를 보내지 않은 변경이 실제 반영됐을 때만,
    ``pass``는 명시적인 재인증 절차가 무인증 요청을 거부하고 원본이 유지됐을
    때만 반환한다. 확인에 실패하거나 근거가 부족한 경우 ``unknown``이다.
    """

    try:
        base_url = _normalize_base_url(url)
    except ValueError as exc:
        return _unknown(str(exc))

    profile_url = urljoin(base_url, PROFILE_PATH.lstrip("/"))
    content: List[str] = []
    original: Optional[Dict[str, str]] = None
    profile_form: Optional[ProfileForm] = None
    mutation_attempted = False
    restore_attempted = False
    restore_success = False
    restore_detail = "원본 개인정보를 수집하지 못해 복구를 시도하지 못함"
    result = "unknown"
    reason = "진단이 완료되지 않았습니다."

    with requests.Session() as session:
        session.headers.update({"User-Agent": "moduleproj2-insufficient-auth-scanner/1.0"})

        try:
            login_response, mypage_response = _login_and_verify(
                session,
                base_url,
                username,
                password,
                DEFAULT_TIMEOUT,
            )
            content.append(
                "로그인 및 인증 페이지 접근 성공 "
                f"({_response_summary(login_response)}; {_response_summary(mypage_response)})"
            )

            profile_response, profile_form = _fetch_profile(
                session,
                profile_url,
                DEFAULT_TIMEOUT,
            )
            original = dict(profile_form.values)
            restore_detail = "개인정보 변경 요청 전 중단되어 복구가 필요하지 않음"
            content.append(
                "기존 개인정보(name, birth_date, phone) 수집 성공 "
                f"({_response_summary(profile_response)})"
            )

            if not _same_origin(base_url, profile_form.action):
                raise ValueError("개인정보 수정 폼 action이 Target URL과 다른 origin을 가리킵니다.")

            test_values = dict(original)
            test_values["phone"] = _test_phone(original["phone"])

            # 요청 후 응답 처리 중 예외가 발생해도 서버에서는 변경됐을 수 있다.
            mutation_attempted = True
            change_response = _submit_profile(
                session,
                profile_form,
                test_values,
                DEFAULT_TIMEOUT,
            )

            _, changed_form = _fetch_profile(session, profile_url, DEFAULT_TIMEOUT)
            changed_values = changed_form.values
            phone_changed = changed_values["phone"] == test_values["phone"]
            other_values_preserved = all(
                changed_values[field] == original[field]
                for field in ("name", "birth_date")
            )

            auth_description = (
                ", ".join(profile_form.reauth_fields)
                if profile_form.reauth_fields
                else "없음"
            )
            content.append(
                "재인증 값을 제공하지 않은 개인정보 변경 요청: "
                f"{_response_summary(change_response)}, 폼의 재인증 필드={auth_description}"
            )
            content.append(
                "변경 후 재조회 결과: "
                f"전화번호 변경={'확인' if phone_changed else '미확인'}, "
                f"이름/생년월일 유지={'확인' if other_values_preserved else '미확인'}"
            )

            if phone_changed and other_values_preserved:
                result = "vulnerable"
                reason = (
                    "현재 비밀번호나 OTP 등 재인증 정보를 전송하지 않았는데도 "
                    "서버에서 전화번호 변경이 실제 반영되었습니다."
                )
            elif _same_profile(changed_values, original):
                explicit_reauth_rejection = bool(profile_form.reauth_fields) and (
                    400 <= change_response.status_code < 500
                    or _response_shows_reauth_form(change_response)
                )
                if explicit_reauth_rejection:
                    result = "pass"
                    reason = (
                        "개인정보 수정 폼에 명시적인 재인증 절차가 있고, 재인증 값을 "
                        "제공하지 않은 변경 요청이 반영되지 않았으며 원본 유지가 확인되었습니다."
                    )
                else:
                    reason = (
                        "개인정보 변경은 확인되지 않았지만 재인증 절차가 요청을 거부한 "
                        "것인지 확정할 근거가 부족합니다."
                    )
            else:
                reason = (
                    "변경 후 개인정보가 요청값이나 원본과 정확히 일치하지 않아 "
                    "재인증 절차의 안전성을 확정할 수 없습니다."
                )

        except (requests.RequestException, RuntimeError, ValueError) as exc:
            if not content:
                content.append(f"로그인 또는 대상 페이지 접근 실패: {exc}")
            else:
                content.append(f"진단 중 확인 불가 오류: {exc}")
            reason = f"동적 진단을 완료할 수 없어 판단할 수 없습니다: {exc}"
            result = "unknown"

        finally:
            if mutation_attempted and original is not None and profile_form is not None:
                restore_attempted = True
                try:
                    # 최신 hidden 토큰을 얻을 수 있으면 사용한다. 실패하면 최초 폼으로
                    # 원복을 계속 시도해 서버에 남는 테스트 데이터를 최소화한다.
                    try:
                        _, restore_form = _fetch_profile(
                            session,
                            profile_url,
                            DEFAULT_TIMEOUT,
                        )
                    except (requests.RequestException, RuntimeError, ValueError):
                        restore_form = profile_form

                    restore_response = _submit_profile(
                        session,
                        restore_form,
                        original,
                        DEFAULT_TIMEOUT,
                    )
                    _, restored_form = _fetch_profile(
                        session,
                        profile_url,
                        DEFAULT_TIMEOUT,
                    )
                    restore_success = _same_profile(restored_form.values, original)
                    restore_detail = (
                        f"원본 개인정보 복구/유지 {'성공' if restore_success else '실패'} "
                        f"({_response_summary(restore_response)})"
                    )
                except (requests.RequestException, RuntimeError, ValueError) as exc:
                    restore_detail = f"원본 개인정보 복구 확인 실패: {exc}"

            content.append(restore_detail)

    # 취약 여부와 별개로 테스트 데이터가 남았으면 운영상 중요한 실패이므로 명시한다.
    if mutation_attempted and restore_attempted and not restore_success:
        reason += " 원본 개인정보 복구 성공을 확인하지 못했습니다."

    return _build_result(result, content, reason)


def _main() -> None:
    parser = argparse.ArgumentParser(description="불충분한 인증 절차 동적 진단")
    parser.add_argument("url", nargs="?", default="http://localhost:5000")
    parser.add_argument("--username", default="student1")
    parser.add_argument("--password", default="student123")
    args = parser.parse_args()

    result = check_insufficient_auth(args.url, args.username, args.password)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    _main()
