"""경로, 법령 등록 정보, LLM 설정."""
import os
from pathlib import Path

from dotenv import load_dotenv

MODULE_DIR = Path(__file__).resolve().parent
ROOT = MODULE_DIR.parent                      # C:\module2
CACHE_DIR = MODULE_DIR / "cache"
ENV_FILE = ROOT / ".env"
# .env 탐색 순서: legal_module/.env -> 상위 폴더(vuln_assessment/.env, 팀 공용 위치) -> 그 위.
# 아래 os.getenv보다 먼저 읽어야 OPENAI_MODEL 등이 적용된다. 먼저 읽힌 값이 유지된다.
for _p in (ROOT / ".env", ROOT.parent / ".env", ROOT.parent.parent / ".env"):
    if _p.exists():
        load_dotenv(_p)

# 원문(txt)을 보유한 법령. 키는 law_code 접두어로 쓰인다 (PIPA-29, SAFE-6).
LAW_FILES = {
    "PIPA": ROOT / "개인정보 보호법(법률)(제21445호)(20260911).txt",
    "SAFE": ROOT / "개인정보의 안전성 확보조치 기준(고시)(제2026-9호)(20260701).txt",
}

ISMSP_FILE = ROOT / "ISMS-P 인증기준 안내서(2023.11).txt"
ISMSP_REF = {
    "ref_id": "ISMSP-2023.11",
    "title": "ISMS-P 인증기준 안내서",
    "type": "인증기준",
    "version": "2023.11",
    "effective_date": None,
    "source_file": ISMSP_FILE.name,
}

# ISMS-P 안내서 [관련 법규]에 등장하는 법령 이름 -> 내부 키.
# LAW_FILES에 없는 키는 원문 미보유 -> text는 null, review_note에 사유를 남긴다.
LAW_NAME_TO_KEY = {
    "개인정보 보호법": "PIPA",
    "개인정보의 안전성 확보조치 기준": "SAFE",
    "정보통신망법": "ICNA",
    "정보통신망 이용촉진 및 정보보호 등에 관한 법률": "ICNA",
    "개인정보 처리 방법에 관한 고시": "PIPA-METHOD",
    "개인정보 영향평가에 관한 고시": "PIA-NOTICE",
    "개인정보 국외 이전 운영 등에 관한 규정": "PIPA-TRANSFER",
    "집적정보 통신시설 보호지침": "IDC-GUIDE",
    "소방시설 설치 및 관리에 관한 법률(소방시설법)": "FIRE",
}
LAW_TYPES = {
    "PIPA": "법률", "SAFE": "고시", "ICNA": "법률", "PIPA-METHOD": "고시", "PIA-NOTICE": "고시",
    "PIPA-TRANSFER": "고시", "IDC-GUIDE": "고시", "FIRE": "법률",
}

# 부칙에 따른 시행 예외 (조문 단위 in_force 보정). (in_force, 메모)
IN_FORCE_OVERRIDES = {
    "SAFE": {
        "제18조": (False, "부칙: 2027. 1. 1. 시행 예정"),
        "제15조": (True, "부칙: 제15조제5호는 2027. 1. 1. 시행 예정"),
    }
}

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.5")
# GPT-5 계열(추론 모델)에서만 쓰는 추론 강도. 비우면 모델 기본값. 예: low / medium / high
OPENAI_REASONING_EFFORT = os.getenv("OPENAI_REASONING_EFFORT", "")

# 1M 토큰당 (입력, 캐시된 입력, 출력) 달러. OpenAI 공시 가격 기준(gpt-5.5는 2026-04 발표가)이며
# 바뀔 수 있으니 비용 보고는 참고용. 정확한 청구액은 OpenAI 대시보드 Usage 참고.
PRICE_PER_1M = {
    "gpt-5.5": (5.00, 0.50, 30.00),
    "gpt-5.5-pro": (30.00, 30.00, 180.00),
    "gpt-5": (1.25, 0.125, 10.00),
    "gpt-5-mini": (0.25, 0.025, 2.00),
    "gpt-5-nano": (0.05, 0.005, 0.40),
    "gpt-4.1": (2.00, 0.50, 8.00),
    "gpt-4.1-mini": (0.40, 0.10, 1.60),
    "gpt-4.1-nano": (0.10, 0.025, 0.40),
    "gpt-4o": (2.50, 1.25, 10.00),
    "gpt-4o-mini": (0.15, 0.075, 0.60),
}
CRITERIA_FILE = MODULE_DIR / "criteria.md"   # 팀 공통 판단 기준. 1차·2차 프롬프트에 그대로 들어간다
PROMPT_VERSION = "v4"          # 1차: 취약점 -> ISMS-P 기준 선택 프롬프트 버전 (v4: 판단 기준 criteria.md 포함)
NARROW_PROMPT_VERSION = "n3"   # 2차: 매핑된 조문 안에서 해당 항 선택 프롬프트 버전 (n3: 판단 기준 criteria.md 포함)

# 상위 의무 조문: 값에 적힌 법령 키의 조문이 하나라도 해당하면, LLM이 빼더라도 유지한다.
# 고시(SAFE)는 개인정보 보호법 제29조를 구체화한 기준이라 고시 위반은 곧 제29조 위반이다.
UMBRELLA_RULES = {"PIPA-29": ("SAFE",)}
SCHEMA_VERSION = "1.0"
