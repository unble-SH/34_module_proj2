# 모듈 3: 법적 영향 분석

취약점 판정 결과(JSON)를 받아, 취약 항목마다 해당하는 ISMS-P 인증기준과 법령 조문을 붙여 보고서 모듈로 넘기는 JSON을 만든다.

## 실행

```bash
# 점검 (LLM 미사용): 법령·안내서 txt가 제대로 읽히는지 확인
python -m module3 selftest

# 실행: 입력 JSON -> 출력 JSON (기본 출력 파일명: 입력명_mapped.json)
python -m module3 run module3/samples/input_sample.json -o module3/samples/output_sample.json

# 옵션
#   --model gpt-4.1-mini   사용할 OpenAI 모델 (기본값, 환경변수 OPENAI_MODEL로도 지정)
#   --offline              LLM 호출 없이 cache/ 에 저장된 응답만 사용 (시연 대비)
#   --no-cache             캐시를 무시하고 항상 LLM 호출
```

API 키는 `.env`의 `OPENAI_API_KEY`로 읽는다. 팀 공용 위치인 `vuln_assessment/.env`(이 폴더의 상위)를 먼저 찾고, 없으면 이 폴더의 `.env`를 쓴다.
설치: 저장소 루트의 통합 `requirements.txt`에 필요한 패키지(openai, pydantic, python-dotenv)가 모두 들어 있다. `pip install -r ../../requirements.txt` (이 폴더 기준).

### 입력 형식 두 가지

1. **finding 형식** (`samples/input_test.json`): `findings[]`에 item_id, title, status(취약/양호/수동확인), severity(상/중/하), asset, evidence
2. **스캐너 형식** (`samples/input_scanner_format.json`): `vuln_assessment/scanner/leak_info.py`의 ResponseFormat 목록 그대로.
   `path, content[], category, result(vulnerable/pass/unknown), severity(high/medium/low), reason`.
   목록만 넘겨도 되고 `{"scan_id", "target_url", "results": [...]}`로 감싸도 된다. 자동으로 감지해 finding 형식으로 바꾼다
   (vulnerable→취약, pass→양호, unknown→수동확인 / high→상, medium→중, low→하 / evidence = path + reason + content).
   `item_id`는 category 이름으로 만들며(adapters.py의 CATEGORY_CODES), 앞부분은 보고서 모듈 카탈로그의 KISA 코드와 같다:
   IL 정보 누출, BF 약한 비밀번호 정책, IA 불충분한 인증 절차, IN 불충분한 권한 검증, PR 취약한 비밀번호 복구 절차. 모르는 category는 W-01처럼 나간다.
   스캐너에 새 category를 추가하면 CATEGORY_CODES에도 한 줄 추가할 것.

```bash
python -m module3 run module3/samples/input_scanner_format.json -o out.json --target-url http://localhost:5000/
```

스캐너 코드에서 바로 쓰려면:
```python
from module3.adapters import from_scanner_results
scan_input = from_scanner_results([r.model_dump() for r in results], target_url=url)
```

```bash
# 단위 테스트 (LLM은 가짜 응답으로 대체, API 키·비용 없음): 로더, 조문 매핑, 캐시, 상태 처리, 실패 복구, 스캐너 형식 변환 등 38건
python -m unittest module3.tests.test_module3 -v
```

## 동작

```
입력 findings
  └─ 양호            -> violated_laws: [], isms_p: []
  └─ 취약 / 수동확인
       1. mapper.map    : LLM이 ISMS-P 101개 기준 목록 안에서 해당 기준 1~3개 선택 (+이유)      mapped_by "llm"
       2. builder       : 선택된 기준의 [관련 법규]에 적힌 조문을 법령 txt에서 꺼내 채움           mapped_by "rule"
       3. mapper.narrow : LLM이 진단 근거(evidence)를 보고 그 조문들 안에서 해당 항을 고르고
                          조문별 이유를 씀. 해당 항이 없는 조문은 빼고 review_note에 남김           mapped_by "rule+llm"
       4. 검증          : 조문이 txt에 없거나 제목이 다르면 review_note에 사유, 예정본은 in_force false
```

- LLM은 조문을 추가하지 못한다. 조문 후보는 항상 ISMS-P 인증기준 안내서(2023.11)의 [관련 법규]이고, LLM은 그 안에서 항을 짚고 무관한 조문을 걸러내기만 한다. 항 번호는 원문에 있는 것만 받는다.
- **판단 기준** `module3/criteria.md`가 1차·2차 프롬프트에 그대로 들어간다. "본인 정보를 본인에게 표시한 것은 유출이 아니다" 같은 팀 합의 기준을 여기에 적으면 실행마다 판단이 흔들리는 문제가 줄어든다. 스캐너 판정 프롬프트에도 같은 파일을 쓰는 것을 권한다. 기준을 고치면 config.py의 PROMPT_VERSION / NARROW_PROMPT_VERSION을 올려 캐시를 무효화할 것.
- 실행이 끝나면 같은 유형(title)·같은 판정인 항목끼리 결과를 비교해, 기준·조문이 다르면 각 항목 review_note에 "판단 불일치"를 표시한다. 결과를 바꾸지는 않고 사람이 확인하도록 알린다.
- 2차 판단이 실패하거나(오프라인·API 오류) 응답이 없으면 조문 전체를 유지하고(mapped_by "rule", paragraph null) review_note에 사유를 남긴다.
- 관련 법규가 없는 기준(101개 중 28개)만 선택되면 violated_laws는 빈 배열로 둔다 (팀 합의: LLM으로 채우지 않음).
- 법령 txt는 부칙을 제외하고, 같은 조문이 두 벌이면 `[시행일]` 표기 없는 현행본을 쓴다.

## 데이터 계약 (pydantic)

`schemas.py`에 세 가지 모델이 있다. 다른 모듈에서 이 파일을 import 해서 쓰면 구조를 맞추기 쉽다.

| 모델 | 용도 | 비고 |
|---|---|---|
| `IsmsPMapping` | LLM 구조화 출력 | OpenAI `chat.completions.parse(response_format=IsmsPMapping)`로 받음. 자유 텍스트 파싱 없음 |
| `ScanInput` | 판정 모듈 -> 모듈 3 입력 | 모르는 필드는 허용. 실행 시작 때 검증하고 틀리면 어디가 틀렸는지 출력 |
| `ModuleOutput` | 모듈 3 -> 보고서 모듈 출력 | 필드 고정(extra 금지). 저장 직전에 검증 |

```python
from module3.schemas import ModuleOutput
out = ModuleOutput.model_validate_json(open("output_test.json", encoding="utf-8").read())
out.findings[0].violated_laws[0].law_code   # "PIPA-29"
```

Python 외 언어용 JSON 스키마는 `python -m module3 schema` 로 `module3/schemas/`에 생성된다 (input / output / llm_response).

## 파일

| 파일 | 역할 |
|---|---|
| schemas.py | pydantic 데이터 계약: LLM 응답, 입력, 출력 |
| adapters.py | 스캐너 출력(ResponseFormat 목록) -> 입력(ScanInput) 변환 |
| config.py | 경로, 법령 등록(법령명 -> 키), 시행 예외, 모델 설정 |
| law_loader.py | 법령 txt -> 조문 사전 (부칙 제외, 현행본 선택, in_force) |
| ismsp_loader.py | ISMS-P 안내서 txt -> 기준 사전 (구역별 내용, 관련 법규 파싱) |
| mapper.py | LLM 호출, 응답 검증, 캐시 |
| builder.py | 출력 JSON 조립, 조문 원문 채우기, review_note |
| main.py | CLI (run / selftest) |
| samples/ | 입력 예시와 출력 예시 |
| cache/ | 항목별 LLM 응답 캐시 (git 제외) |

## 출력 필드 규칙

| 필드 | 규칙 |
|---|---|
| law_code | `법령키-조번호`. PIPA-29 = 개인정보 보호법 제29조, SAFE-6 = 안전성 확보조치 기준 제6조, 제28조의2는 PIPA-28의2 |
| ref_id | references 배열의 항목을 가리킴. PIPA-21445, SAFE-2026-9, ISMSP-2023.11 |
| article / article_title | "제29조" / "안전조치의무" (원문 txt 기준) |
| paragraph | LLM이 고른 해당 항. "제3항", 여러 개면 "제1항, 제3항". 항 구분 없는 조문(제29조)이나 항 판단을 못 한 경우 null |
| text | txt에서 복사한 조문 원문 (헤더 줄 포함). 원문 미보유 법령은 null |
| in_force | 현행본 true. 시행 예정 조문 false. 원문 없으면 null |
| mapped_by | isms_p는 "llm". violated_laws는 "rule+llm"(항까지 판단됨) 또는 "rule"(항 판단 없이 조문 전체) |
| reason | violated_laws: LLM이 쓴 조문별 이유 + 괄호 안에 출처(어느 ISMS-P 기준의 관련 법규인지). isms_p: LLM이 쓴 기준 선택 이유 |
| evidence | 판정 모듈이 준 진단 근거. 정식 필드로 항상 존재 (없으면 null) |
| reviewed | 기본 false (사람 검토 전) |
| review_note | 문제가 있을 때만 생김: 원문 없음, 제목 불일치, 시행 예정, 개인정보 미처리 자산, LLM 실패, 항 판단으로 제외한 조문 등 |
| mapping.method | "llm+rule". prompt_version은 "기준선택버전/항판단버전" (예: v3/n1) |

## 비용

- 기본 모델 gpt-5.5 (config.py OPENAI_MODEL, 또는 .env의 OPENAI_MODEL / 실행 옵션 --model). 취약 항목 1건당 LLM 호출 2회: 기준 선택(입력 약 20,200 토큰, 101개 기준 목록 19,400 포함) + 항 판단(입력 약 3,000 토큰, 매핑된 조문 원문). 출력은 호출당 약 60~500 토큰(추론 모델은 추론 토큰이 출력에 포함됨).
- gpt-5.5 단가는 입력 $5 / 캐시 입력 $0.5 / 출력 $30 (1M 토큰당). 첫 호출 약 $0.11, 같은 실행 안의 다음 호출은 기준 목록이 캐시에 걸려 약 $0.02. 취약 5건 실행이면 약 $0.20.
- 비용을 줄이려면 `--model gpt-4.1-mini` (첫 호출 약 $0.008, 이후 약 $0.002, 5건 약 $0.017). 테스트에서 두 모델의 기준 선택 결과는 같았다.
- GPT-5 계열은 temperature를 받지 않아 자동으로 빼고 호출한다. 추론 강도는 .env의 OPENAI_REASONING_EFFORT(low/medium/high)로 지정할 수 있다.
- 실행 로그와 출력 JSON의 `mapping.tokens`에 실제 토큰 수와 예상 비용이 기록된다. 가격표는 config.py의 PRICE_PER_1M (2025년 공시 기준, 참고용).
- 같은 입력을 다시 돌리면 cache/ 의 응답을 써서 호출이 없다.

## 모델 바꾸기

`.env`에 `OPENAI_MODEL=gpt-4.1` 처럼 넣거나 `--model` 옵션. Claude로 바꾸려면 mapper.py의 `_call_llm`만 교체하면 된다.
