# 보고서 엔진

진단 JSON 하나로 경영진용 슬라이드 PDF와 실무진용 상세 보고서 PDF를 만든다. LLM은 한 번만 호출한다.

```
data/ 폴더의 JSON 4개 (scan, context, cases, item_catalog) + 사례 지식베이스(chroma_db)
   │
   ├─ ① facts     코드    통계, 위험 수준 판정, 사례 검색(case_kb), 노출액 계산(exposure)
   ├─ ② llm       1회     문장만 생성 → out/llm_output.json 저장
   ├─ ③ validate  코드    LLM이 지어낸 ID 제거 → out/run_log.json
   └─ ④ render    코드    같은 데이터 → exec.html.j2 / tech.html.j2 → PDF 2개
```

원칙: **판정은 코드, 문장은 AI, 숫자·조문·조치 방법은 원본 데이터.**
판례 금액, 노출액, 법령 조문, 조치 방법은 LLM을 거치지 않고 템플릿이 원본 JSON에서 직접 꺼내 쓴다.
LLM에는 원화 금액을 아예 넘기지 않는다.

## 실행

```bash
# macOS (Apple Silicon) — 처음 한 번
brew install pango python@3.12                   # pango는 PDF용 시스템 라이브러리라 pip가 아니라 brew로 설치
/opt/homebrew/bin/python3.12 -m venv .venv       # 맥 기본 python3(3.9)로 만들면 pango를 못 찾음
source .venv/bin/activate
pip install -r ../../requirements.txt
echo 'export DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib' >> ~/.zshrc && source ~/.zshrc

# .env (프로젝트 폴더에)
# OPENAI_API_KEY=...        임베딩(사례 검색)과 문장 생성에 사용
# LLM_PROVIDER=anthropic    Claude로 문장을 쓰려면 이 줄과 ANTHROPIC_API_KEY 추가

# 사례 시트를 고쳤을 때
python convert_cases.py      # data/cases.xlsx → data/cases.json (검사 포함)
python case_kb.py load       # data/cases.json → data/chroma_db (매번 새로 만듦)

# 보고서 만들기
python engine.py --mock                              # LLM 없이 샘플 문장으로 렌더링 (사례 검색은 실행됨)
python engine.py                                     # 실제 LLM 1회 호출
python engine.py --llm-output out/llm_output.json    # 저장된 LLM 출력 재사용 (템플릿만 고칠 때)
```

Windows에서도 WeasyPrint의 Python 패키지 외에 GTK/Pango 런타임이 필요하다. `libgobject-2.0-0` 또는 `libpango-1.0-0` 로드 오류가 발생하면 GTK/Pango를 설치하고 해당 DLL 경로를 `PATH`에 추가한다.

`cannot load library 'libgobject-2.0-0'` 또는 `'libpango-1.0-0'` 오류가 나면 순서대로 확인:
1. `ls /opt/homebrew/lib | grep -E "libpango-1.0|libgobject-2.0"` 에 아무것도 안 나오면 `brew install pango`
2. 터미널에서 `echo $DYLD_FALLBACK_LIBRARY_PATH` 가 비어 있으면 `export DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib`
3. 그래도 안 되면 `.venv`가 맥 기본 파이썬(경로에 `CommandLineTools`가 보임)으로 만들어진 것. `rm -rf .venv` 후 위의 `/opt/homebrew/bin/python3.12 -m venv .venv`부터 다시

결과물: `out/exec_report.pdf`, `out/tech_report.pdf` (같은 이름의 .html은 브라우저 미리보기용),
`out/exposure_result.json` (노출액 계산 결과), `out/run_log.json` (검증 경고)

## 파일별 역할

| 파일 | 누가 채우나 | 내용 |
|---|---|---|
| `data/scan.json` | 진단 담당 | 진단 결과 + 법령·ISMS-P 매핑 (팀 스키마 1.0) |
| `data/context.json` | 보고서 담당 | 조직명, 회원 수, 처리 개인정보 항목, 표지 안내 문구 등 경영진 보고용 맥락. `exposure_profile`에 노출액 계산용 매출·인증 여부 등 |
| `data/cases.xlsx` | 보고서 담당 | 사례 수집 시트 (드롭다운·검사 포함). 원본은 `data/sources/`의 보도자료 PDF |
| `data/cases.json` | 자동 생성 | `convert_cases.py`가 시트에서 만든 사례 카드. 직접 고치지 않는다 |
| `data/chroma_db/` | 자동 생성 | `case_kb.py load`가 만든 사례 지식베이스 |
| `data/item_catalog.json` | 보고서 담당 | 점검 항목별 판단 기준·조치 방법 (KISA 가이드 기준으로 채우기) |
| `assets/` | 보고서 담당 | 루키즈 로고. 경로는 `context.json`의 `logo`. 파일이 없으면 로고 자리만 비고 정상 렌더링 |

샘플 데이터의 조직명, 사례, 항목 코드(PR, BF, IL), 카탈로그 문구는 모두 예시다.

## 스키마 1.0에 추가 제안한 필드

`findings[].evidence` (선택): 실무진 보고서의 '현황' 칸.
```json
"evidence": { "summary": "한 줄 요약", "detail": "명령어 결과, 요청/응답 원문" }
```
없으면 보고서에 "현황 정보 없음"으로 표시된다.

## 앞단 진단 JSON으로 보고서 만들기

입력은 법적 영향 분석 모듈(`legal_module/module3`)의 출력 JSON이다. 스캐너 결과를 module3에 넣어 나온 파일을 그대로 쓴다.

```bash
# 진단 담당 모듈이 만든 JSON을 data/scans/에 두고
python engine.py --scan data/scans/SCAN-2026-002.json        # 결과: out/SCAN-2026-002/
python engine.py --scan data/scans/SCAN-2026-002.json --llm-output out/SCAN-2026-002/llm_output.json   # 문장 고정 후 재렌더링
```

- `--mock`은 샘플 진단(`data/scan.json`) 전용이다. 새 진단 JSON에는 실제 LLM을 쓰거나 `--llm-output`으로 저장된 문장을 쓴다.
- 결과 폴더는 진단마다 `out/<scan_id>/`로 따로 생긴다.
- 엔진이 알아서 맞추는 것: `evidence`가 문자열이든 `{summary, detail}` 객체든 null이든 읽음, `paragraph`가 있으면 그 항만 표시(원문 전체는 `text_full`), `<개정 …>` 같은 이력 꼬리표는 표시에서만 뗌, `review_note`는 실무진용에 '매핑 검토 메모'로 표시, 고시 조항(`SAFE-…`)은 제29조의 세부 기준이라 노출액에서 따로 세지 않음.
- `data/item_catalog.json`은 KISA '2026 상세가이드' 원문의 판단 기준·조치 방법이다. 웹 21개 항목(CI, SI, DI, EP, IL, XS, CF, SF, BF, IA, IN, PR, PV, FU, FD, IS, SN, CC, AE, AU, WM)과 샘플용 U-01·U-02가 들어 있다.
- 진단 JSON의 `item_id`가 카탈로그에 없으면 (1) 점검 항목 이름이 같은 항목, (2) ID 앞부분이 같은 항목 순서로 연결하고 `[카탈로그]` 줄로 알려준다. 예: `W-03 '불충분한 권한 검증'` → IN(이름), `IL-COMMENT-01` → IL(ID 앞부분). 그래서 스캐너 결과 ID를 카탈로그 코드로 시작하게 만들면(`IL-…`, `BF-…`) 세부 항목이 여러 개여도 자동으로 연결된다. 연결된 항목 이름은 사례 검색의 팀 취약점 기준으로도 쓰인다. 가이드에서 `W-xx`는 Windows 서버 코드라, 웹 항목은 KISA 코드를 쓰는 게 맞다.

## 저장소에 올리지 않는 것

`.gitignore`에 들어 있다: `.env`(API 키), `.venv/`, `__pycache__/`, `out/`, `data/chroma_db/`, `data/cases.json`.
`data/cases.json`과 `data/chroma_db/`는 생성물이라 받은 뒤 `python convert_cases.py && python case_kb.py load`로 만든다.
API 키는 `.env.example`을 `.env`로 복사해서 채운다.

## 사례 검색과 노출액

- **사례 검색 (`case_kb.py`)**: 취약점마다 후보 5개를 등급과 함께 찾는다. 등급은 동일 결함 사례(ISMS-P 기준과 팀 취약점 둘 다 일치) → 같은 취약점 유형 → 관련 통제 사례(ISMS-P만 일치) → 참고 사례 순. 같은 보도자료 사례는 한 건만.
- **사례 인용**: LLM은 위험마다 그 위험에 묶인 취약점의 후보 안에서만 사례를 고른다(참고 사례 제외). 고른 사례가 없거나 후보 밖이면 검증 단계가 지우고, 코드가 가장 높은 등급의 후보를 연결한다. 보고서에는 실제로 인용된 사례만 실린다.
- **노출액 (`exposure.py`)**: 법정 상한(매출의 3%), 10% 특례 요건, 투자 감경(최대 40%)·ISMS-P 감경(최대 30%), 유사 사례 실제 과징금 분포, 우선순위 점수. 결과는 `facts.exposure`로 템플릿에 들어간다.
- 유사 사례 중앙값이 고객사 법정 상한보다 크면 `fine_distribution.warning`이 생긴다. 사례 금액을 고객사 예상 과징금처럼 쓰면 안 된다는 뜻이다.
- 보고서에 나오는 곳: 경영진용 5장 '과징금 노출과 감경 여지'(법정 상한, 투자 감경 예시, 10% 특례, 유사 처분 과징금 최대 4건), 실무진용 부록 4.3~4.5(산정 근거, 조치 우선순위, 가정과 제외 항목). 사례 옆 회색 칩은 사례 등급이다.
- 금액 표기는 템플릿 필터 `krw`가 맡는다 (150000000 → 1억 5,000만 원).

## 바꿀 만한 곳

- 전체 위험 수준 규칙: `engine.py`의 `compute_risk_level`
- 로드맵 단계와 기간: `engine.py`의 `PHASES`
- LLM 바꾸기: `.env`의 `LLM_PROVIDER`(openai | anthropic)와 `LLM_MODEL`. 호출 코드는 `engine.py`의 `call_llm` 하나뿐
- 사례 등급·노출액 규칙: `case_kb.py`의 `search_cases`, `exposure.py` 맨 위 상수
- 디자인: `templates/_common.css.j2`(공통 색상), `exec.html.j2`(16:9 슬라이드), `tech.html.j2`(A4)

## 색 규칙 (루키즈 로고 색 기준)

| 색 | 값 | 쓰는 곳 |
|---|---|---|
| 주황 | `#ED742E` | 경영진용 레이아웃만: 왼쪽 띠, 제목 밑줄, 표 머리선, 결정 번호 |
| 회색 | `#727171` | 보조 글씨, 라벨, '하' 위험도, 중기 단계 |
| 빨강 | `#E2312D` | 꼭 봐야 하는 글씨만: 전체 위험 수준, '상' 위험도, 취약 판정, 처분 결과 |

같은 규칙을 위험도(상 빨강, 중 주황, 하 회색)와 로드맵(즉시, 단기, 중기)에도 쓴다.
실무진용은 주황 레이아웃 없이 회색 계열만 쓰고, 머리글 로고로만 브랜드를 표시한다.

로고는 공식 루키즈 로고를 변형 없이 쓴다. 표지에는 `context.json`의 `disclaimer` 문구(공식 SK쉴더스 보고서가 아니라는 안내)가 들어간다.

팀명("SK쉴더스 루키즈 34기 1석삼조 팀")은 두 템플릿 맨 위의 `{% set team = ... %}`에 고정되어 있다.

## 폰트

Pretendard TTF 버전을 `ReportPretendard`라는 별도 이름으로 등록해서 쓴다 (SIL Open Font License 1.1).

- OTF(CFF) 대신 TTF: OTF로 임베드하면 일부 PDF 뷰어에서 숫자, 하이픈, 쉼표가 사라지는 문제가 있었다
- 별도 이름: 시스템에 설치된 Pretendard와 버전이 섞이면 글자가 깨질 수 있어서
- `font-feature-settings: "calt" 0, "clig" 0`: 숫자·하이픈이 문맥에 따라 대체 글리프로 바뀌지 않게 고정
