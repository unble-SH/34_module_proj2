"""모듈 3 단위 테스트. LLM은 가짜 응답으로 대체하므로 API 키·비용 없이 돈다.

    python -m unittest module3.tests.test_module3 -v
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pydantic import ValidationError

from module3 import builder, main
from module3.ismsp_loader import load_ismsp, parse_law_ref
from module3.law_loader import load_all_laws, norm_title, parse_article_id
from module3.mapper import Mapper
from module3.schemas import IsmsPMapping, ModuleOutput, ScanInput

SAMPLES = Path(__file__).resolve().parent.parent / 'samples'

LAWS = load_all_laws()
ISMSP = load_ismsp()
ASSET = {"id": "WEB01", "name": "웹서버", "handles_personal_data": True}


def finding(**kw):
    f = {"item_id": "W-01", "title": "테스트 취약점", "status": "취약", "severity": "상",
         "asset": dict(ASSET), "evidence": "테스트 근거"}
    f.update(kw)
    return f


class LawLoaderTest(unittest.TestCase):
    def test_pipa_basics(self):
        pipa = LAWS['PIPA']
        self.assertEqual(pipa.get('제1조').title, '목적')                 # 부칙 제1조(시행일)가 아님
        self.assertEqual(pipa.ref_id, 'PIPA-21445')
        self.assertEqual(pipa.effective_date, '2026-09-11')
        self.assertFalse(any(a.title == '시행일' for a in pipa.articles.values()))   # 부칙 제외

    def test_current_version_selected(self):
        pipa = LAWS['PIPA']
        for aid in ('제2조', '제7조의9', '제32조의2', '제37조의2', '제75조'):
            art = pipa.get(aid)
            self.assertTrue(art.in_force, aid)
            self.assertNotIn('[시행일', art.text, aid)
            self.assertIn(aid, pipa.future_versions)
            self.assertIn('[시행일', pipa.future_versions[aid].text)

    def test_future_only_articles(self):
        pipa = LAWS['PIPA']
        for aid in ('제28조의12', '제28조의13', '제28조의14', '제28조의15'):
            self.assertFalse(pipa.get(aid).in_force, aid)
            self.assertEqual(pipa.get(aid).future_date, '2027-03-09')

    def test_candidate_list_is_current_and_unique(self):
        ids = [a for a, _ in LAWS['PIPA'].candidate_list()]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertNotIn('제28조의12', ids)
        self.assertNotIn('제8조', ids)                                       # 삭제된 조문 제외

    def test_safe_overrides(self):
        safe = LAWS['SAFE']
        self.assertEqual(safe.ref_id, 'SAFE-2026-9')
        self.assertFalse(safe.get('제18조').in_force)
        self.assertTrue(safe.get('제15조').in_force)
        self.assertIn('제5호', safe.get('제15조').note)
        self.assertEqual(safe.get('제6조의2').code_suffix, '6의2')

    def test_paragraph_split(self):
        safe, pipa = LAWS['SAFE'], LAWS['PIPA']
        self.assertEqual([p[0] for p in safe.get('제6조').paragraphs()], ['제1항', '제2항', '제3항', '제4항', '제5항'])  # ⑥ 삭제 제외
        self.assertTrue(safe.get('제6조').paragraphs()[2][1].startswith('③'))
        self.assertIn('1. 개인정보처리시스템에 대한 접속 권한', safe.get('제6조').paragraphs()[0][1])   # 호는 항에 붙음
        self.assertEqual(len(safe.get('제5조').paragraphs()), 6)
        self.assertEqual(pipa.get('제29조').paragraphs(), [])                                           # 항 구분 없는 조문
        p34 = pipa.get('제34조').paragraphs()
        self.assertEqual(p34[0][0], '제1항')
        self.assertIn('1. 유출등이 된 개인정보의 항목', p34[0][1])

    def test_helpers(self):
        self.assertEqual(parse_article_id('제12조 (출력·복사시 안전조치)'), '제12조')
        self.assertEqual(parse_article_id('제28조의2(가명정보)'), '제28조의2')
        self.assertEqual(norm_title('출력·복사시 안전조치'), norm_title('출력ㆍ복사시 안전조치'))
        self.assertEqual(norm_title('안전조치 의무'), norm_title('안전조치의무'))


class IsmspLoaderTest(unittest.TestCase):
    def test_counts(self):
        self.assertEqual(len(ISMSP.criteria), 101)
        self.assertEqual(sum(1 for c in ISMSP.criteria.values() if c.related_laws), 73)
        self.assertEqual(ISMSP.unknown_law_names, set())
        self.assertTrue(all(c.standard for c in ISMSP.criteria.values()))

    def test_parse_law_ref(self):
        r = parse_law_ref('- 개인정보의 안전성 확보조치 기준 제5조(접근권한의 관리), 제6조(접근통제), 제12조 (출력·복사시 안전조치)')
        self.assertEqual(r.law_key, 'SAFE')
        self.assertEqual([a for a, _ in r.articles], ['제5조', '제6조', '제12조'])
        r = parse_law_ref('- 개인정보 처리 방법에 관한 고시')
        self.assertEqual((r.law_key, r.articles), ('PIPA-METHOD', []))
        r = parse_law_ref('- 소방시설 설치 및 관리에 관한 법률(소방시설법) 제12조(특정소방대상물에 설치하는 소방시설의 관리 등), 제16조(피난시설, 방화구역 및 방화시설의 관리)')
        self.assertEqual(r.law_key, 'FIRE')
        self.assertEqual(len(r.articles), 2)
        r = parse_law_ref('- 정보통신망법 제48조의3(침해사고의 신고 등), 제48조의4(침해사고의 원인분석 등)')
        self.assertEqual([a for a, _ in r.articles], ['제48조의3', '제48조의4'])

    def test_candidate_text(self):
        text = ISMSP.candidate_text()
        self.assertEqual(len(text.splitlines()), 101)
        self.assertIn('2.6.6 원격접근 통제 | 인증기준:', text)
        self.assertIn('주요 확인사항:', text)


class BuilderTest(unittest.TestCase):
    def sel(self, *ids):
        return [{"criterion_id": i, "relevance": "primary" if n == 0 else "secondary", "reason": "r"} for n, i in enumerate(ids)]

    def test_rule_mapping_and_sort(self):
        out = builder.build_finding(finding(), 0, 'S', self.sel('2.6.3', '2.5.3'), None, ISMSP, LAWS)
        codes = [v['law_code'] for v in out['violated_laws']]
        self.assertEqual(codes, ['PIPA-29', 'SAFE-5', 'SAFE-6', 'SAFE-12'])    # 법령 순, 조문 번호 순 (문자열 정렬이면 12가 5 앞)
        v = out['violated_laws'][0]
        self.assertEqual((v['article'], v['article_title'], v['in_force'], v['mapped_by']), ('제29조', '안전조치의무', True, 'rule'))
        self.assertTrue(v['text'].startswith('제29조(안전조치의무)'))
        self.assertIn('2.6.3', v['reason'])
        self.assertIn('2.5.3', v['reason'])                                     # 두 기준에서 온 조문은 reason에 둘 다
        self.assertNotIn('review_note', v)
        self.assertEqual([c['criterion_id'] for c in out['isms_p']], ['2.6.3', '2.5.3'])
        self.assertEqual(out['finding_id'], 'S-W-01-WEB01')

    def test_missing_law_text_and_title_mismatch(self):
        out = builder.build_finding(finding(), 0, 'S', self.sel('1.1.2'), None, ISMSP, LAWS)
        by_code = {v['law_code']: v for v in out['violated_laws']}
        icna = by_code['ICNA-45의3']
        self.assertIsNone(icna['text'])
        self.assertIsNone(icna['in_force'])
        self.assertIn('원문(txt) 미보유', icna['review_note'])
        self.assertIn('제목 불일치', by_code['PIPA-31']['review_note'])
        self.assertEqual(by_code['PIPA-31']['article_title'], '개인정보 보호책임자의 지정 등')   # 원문 제목 우선
        self.assertTrue(all(v['text'] is not None for v in out['violated_laws'][:3]))      # 원문 있는 것이 앞

    def test_law_without_article(self):
        cid = next(c.id for c in ISMSP.criteria.values() if any(not r.articles for r in c.related_laws))
        out = builder.build_finding(finding(), 0, 'S', self.sel(cid), None, ISMSP, LAWS)
        v = next(v for v in out['violated_laws'] if v['article'] is None)
        self.assertIn('조문은 지정하지 않음', v['review_note'])

    def test_no_related_law_criterion(self):
        out = builder.build_finding(finding(), 0, 'S', self.sel('2.10.3'), None, ISMSP, LAWS)
        self.assertEqual(out['violated_laws'], [])
        self.assertEqual(len(out['isms_p']), 1)
        self.assertIn('[관련 법규]가 없어', out['review_note'])

    def test_narrowing_applies_paragraphs_and_removes(self):
        def narrower(f, candidates):
            self.assertEqual([c['law_code'] for c in candidates], ['PIPA-29', 'SAFE-5', 'SAFE-6', 'SAFE-12'])
            self.assertEqual(candidates[0]['paragraphs'], [])                       # 제29조: 항 구분 없음
            self.assertEqual([p[0] for p in candidates[2]['paragraphs']][:3], ['제1항', '제2항', '제3항'])
            return {"PIPA-29": {"applicable": True, "paragraphs": [], "reason": "본인 확인 없이 타인 정보 조회"},
                    "SAFE-5": {"applicable": True, "paragraphs": ["제1항"], "reason": "권한 차등 부여 미흡"},
                    "SAFE-6": {"applicable": True, "paragraphs": ["제3항", "제1항"], "reason": "권한 없는 자에게 공개"},
                    "SAFE-12": {"applicable": False, "paragraphs": [], "reason": "출력·복사와 무관"}}, None
        out = builder.build_finding(finding(), 0, 'S', self.sel('2.6.3'), None, ISMSP, LAWS, narrower=narrower)
        by = {v['law_code']: v for v in out['violated_laws']}
        self.assertEqual(list(by), ['PIPA-29', 'SAFE-5', 'SAFE-6'])
        self.assertIsNone(by['PIPA-29']['paragraph'])
        self.assertEqual(by['SAFE-5']['paragraph'], '제1항')
        self.assertEqual(by['SAFE-6']['paragraph'], '제3항, 제1항')
        self.assertTrue(all(v['mapped_by'] == 'rule+llm' for v in out['violated_laws']))
        self.assertTrue(by['SAFE-6']['reason'].startswith('권한 없는 자에게 공개'))
        self.assertIn('2.6.3', by['SAFE-6']['reason'])                                  # 출처(관련 법규) 유지
        self.assertIn('SAFE-12', out['review_note'])
        self.assertIn('출력·복사와 무관', out['review_note'])

    def test_narrowing_failure_keeps_rule_result(self):
        def broken(f, candidates):
            raise RuntimeError('boom')
        out = builder.build_finding(finding(), 0, 'S', self.sel('2.6.3'), None, ISMSP, LAWS, narrower=broken)
        self.assertEqual(len(out['violated_laws']), 4)
        self.assertTrue(all(v['mapped_by'] == 'rule' and v['paragraph'] is None for v in out['violated_laws']))
        self.assertIn('항 판단 LLM 호출 실패', out['review_note'])
        out = builder.build_finding(finding(), 0, 'S', self.sel('2.6.3'), None, ISMSP, LAWS,
                                    narrower=lambda f, c: (None, '오프라인'))
        self.assertEqual(len(out['violated_laws']), 4)

    def test_evidence_always_present(self):
        out = builder.build_finding(finding(evidence=None), 0, 'S', self.sel('2.5.4'), None, ISMSP, LAWS)
        self.assertIn('evidence', out)
        self.assertIsNone(out['evidence'])
        good = builder.build_finding(finding(status='양호'), 0, 'S', [], None, ISMSP, LAWS)
        self.assertEqual(good['evidence'], '테스트 근거')

    def test_statuses(self):
        good = builder.build_finding(finding(status='양호'), 0, 'S', [], None, ISMSP, LAWS)
        self.assertEqual((good['violated_laws'], good['isms_p']), ([], []))
        self.assertNotIn('review_note', good)
        odd = builder.build_finding(finding(status='점검불가'), 0, 'S', [], None, ISMSP, LAWS)
        self.assertIn('매핑 대상이 아님', odd['review_note'])
        manual = builder.build_finding(finding(status='수동확인'), 0, 'S', self.sel('2.5.4'), None, ISMSP, LAWS)
        self.assertIn('수동확인', manual['review_note'])
        self.assertTrue(manual['violated_laws'])

    def test_no_personal_data_and_missing_asset(self):
        out = builder.build_finding(finding(asset={"name": "공개 홈페이지", "handles_personal_data": False}), 2, 'S',
                                    self.sel('2.5.4'), None, ISMSP, LAWS)
        self.assertEqual(out['finding_id'], 'S-W-01-A03')
        self.assertTrue(all('개인정보를 처리하지 않음' in v['review_note'] for v in out['violated_laws']))
        out = builder.build_finding(finding(asset=None), 0, 'S', self.sel('2.5.4'), None, ISMSP, LAWS)
        self.assertEqual(out['finding_id'], 'S-W-01-A01')

    def test_references(self):
        refs = builder.build_references(LAWS)
        self.assertEqual([r['ref_id'] for r in refs], ['PIPA-21445', 'SAFE-2026-9', 'ISMSP-2023.11'])


class MapperTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.mapper = Mapper(ISMSP, model='gpt-4.1-mini', cache_dir=Path(self.tmp.name), log=lambda m: None)

    def tearDown(self):
        self.tmp.cleanup()

    def test_validate(self):
        raw = {"isms_p": [
            {"criterion_id": "2.5.3 사용자 인증", "relevance": "secondary", "reason": "a"},
            {"criterion_id": "2.5.4", "relevance": "primary", "reason": "b"},
            {"criterion_id": "2.5.4", "relevance": "primary", "reason": "dup"},
            {"criterion_id": "9.9.9", "relevance": "primary", "reason": "x"},
            "garbage"], "notes": ""}
        picked, note = self.mapper._validate(raw)
        self.assertEqual([p['criterion_id'] for p in picked], ['2.5.4', '2.5.3'])    # primary 먼저, 중복 제거
        self.assertIn('9.9.9', note)
        picked, note = self.mapper._validate({"isms_p": [], "notes": "해당 없음"})
        self.assertEqual(picked, [])
        self.assertIn('찾지 못함', note)
        self.assertIn('해당 없음', note)
        picked, note = self.mapper._validate(["not", "a", "dict"])
        self.assertEqual(picked, [])
        self.assertIn('형식 오류', note)

    def test_cache_roundtrip_and_offline(self):
        fake = ({"isms_p": [{"criterion_id": "2.5.4", "relevance": "primary", "reason": "r"}], "notes": ""},
                {"prompt_tokens": 100, "cached_tokens": 0, "completion_tokens": 10})
        with mock.patch.object(Mapper, '_call_llm', return_value=fake) as call:
            picked, _ = self.mapper.map(finding())
            self.assertEqual(picked[0]['criterion_id'], '2.5.4')
            picked, _ = self.mapper.map(finding())                         # 두 번째는 캐시
            self.assertEqual(call.call_count, 1)
            self.assertEqual((self.mapper.calls, self.mapper.cache_hits, self.mapper.prompt_tokens), (1, 1, 100))
        self.assertEqual(len(list(Path(self.tmp.name).glob('*.json'))), 1)
        cached = json.loads(next(Path(self.tmp.name).glob('*.json')).read_text(encoding='utf-8'))
        self.assertEqual(cached['usage']['prompt_tokens'], 100)
        offline = Mapper(ISMSP, model='gpt-4.1-mini', cache_dir=Path(self.tmp.name), offline=True, log=lambda m: None)
        self.assertEqual(offline.map(finding())[0][0]['criterion_id'], '2.5.4')   # 캐시 있음 -> 사용
        picked, note = offline.map(finding(title='다른 취약점'))                   # 캐시 없음 -> 빈 결과 + 메모
        self.assertEqual(picked, [])
        self.assertIn('오프라인', note)

    def test_cache_key_depends_on_prompt_inputs(self):
        from module3.mapper import _finding_payload
        key = lambda f: Mapper._key(_finding_payload(f))   # noqa: E731
        k1 = key(finding())
        self.assertEqual(k1, key(finding()))
        self.assertNotEqual(k1, key(finding(evidence='다른 근거')))
        self.assertNotEqual(k1, key(finding(asset={"name": "다른 서버", "handles_personal_data": True})))

    def test_umbrella_article_is_kept_when_detail_rule_applies(self):
        def narrower(f, candidates):
            return {"PIPA-29": {"applicable": False, "paragraphs": [], "reason": "포괄 조문이라 직접 일치하지 않음"},
                    "SAFE-5": {"applicable": True, "paragraphs": ["제1항"], "reason": "권한 차등 부여 미흡"},
                    "SAFE-6": {"applicable": False, "paragraphs": [], "reason": "무관"},
                    "SAFE-12": {"applicable": False, "paragraphs": [], "reason": "무관"}}, None
        sel = [{"criterion_id": "2.6.3", "relevance": "primary", "reason": "r"}]
        out = builder.build_finding(finding(), 0, 'S', sel, None, ISMSP, LAWS, narrower=narrower)
        codes = [v['law_code'] for v in out['violated_laws']]
        self.assertEqual(codes, ['PIPA-29', 'SAFE-5'])                       # 고시 조문이 남으면 제29조는 유지
        p29 = out['violated_laws'][0]
        self.assertEqual(p29['mapped_by'], 'rule+llm')
        self.assertIn('제29조', p29['reason'])
        self.assertIn('제29조', out['review_note'])
        self.assertNotIn('PIPA-29 제29조(안전조치의무): 포괄', out['review_note'])   # 제외 목록에는 없음

    def test_narrow_validation_and_cache(self):
        cands = [{"law_code": "PIPA-29", "law_name": "개인정보 보호법", "article": "제29조", "title": "안전조치의무",
                  "text": "제29조(안전조치의무) ...", "paragraphs": []},
                 {"law_code": "SAFE-6", "law_name": "고시", "article": "제6조", "title": "접근통제",
                  "text": "...", "paragraphs": [("제1항", "① a"), ("제2항", "② b"), ("제3항", "③ c")]}]
        raw = {"laws": [
            {"law_code": "SAFE-6", "applicable": True, "paragraphs": ["제3항", "3항", "3", "③", "제9항", "1"], "reason": "r6"},
            {"law_code": "SAFE-99", "applicable": True, "paragraphs": [], "reason": "x"}], "notes": ""}
        fake = (raw, {"prompt_tokens": 50, "cached_tokens": 0, "completion_tokens": 5})
        with mock.patch.object(Mapper, '_call_llm', return_value=fake) as call:
            result, note = self.mapper.narrow(finding(), cands)
            self.assertEqual(result['SAFE-6']['paragraphs'], ['제3항', '제1항'])   # "3항","3","③"은 제3항으로 정규화·중복 제거, 제9항은 없음
            self.assertNotIn('PIPA-29', result)                                  # LLM이 판단 안 한 조문은 결과에 없음 -> 전체 유지
            self.assertIn('SAFE-99', note)
            self.assertIn('제9항', note)
            self.assertIn('PIPA-29', note)
            self.mapper.narrow(finding(), cands)                                 # 캐시
            self.assertEqual(call.call_count, 1)
        self.assertEqual(self.mapper.narrow(finding(), [])[0], {})
        offline = Mapper(ISMSP, model='gpt-4.1-mini', cache_dir=Path(self.tmp.name), offline=True, log=lambda m: None)
        result, note = offline.narrow(finding(title='다른 취약점'), cands)
        self.assertIsNone(result)
        self.assertIn('오프라인', note)
        bad, note = Mapper._validate_narrow(["nope"], cands)
        self.assertIsNone(bad)

    def test_cost_estimate(self):
        self.mapper.prompt_tokens, self.mapper.cached_tokens, self.mapper.completion_tokens = 1_000_000, 500_000, 100_000
        self.assertAlmostEqual(self.mapper.cost_estimate(), 0.5 * 0.40 + 0.5 * 0.10 + 0.1 * 1.60, places=5)
        self.assertIsNone(Mapper(ISMSP, model='unknown-model', cache_dir=Path(self.tmp.name)).cost_estimate())


class AdapterTest(unittest.TestCase):
    def test_scanner_format_conversion(self):
        from module3.adapters import from_scanner_results, looks_like_scanner_output, to_scan_input
        data = json.loads((SAMPLES / 'input_scanner_format.json').read_text(encoding='utf-8'))
        self.assertTrue(looks_like_scanner_output(data))
        self.assertTrue(looks_like_scanner_output(data['results']))
        self.assertFalse(looks_like_scanner_output(json.loads((SAMPLES / 'input_test.json').read_text(encoding='utf-8'))))
        conv = to_scan_input(data)
        ScanInput.model_validate(conv)
        self.assertEqual(conv['scan_id'], 'SCAN-2026-003')
        f1, f2, f3 = conv['findings']
        self.assertEqual((f1['item_id'], f1['status'], f1['severity'], f1['title']), ('IL-COMMENT-01', '취약', '상', '주석 내 정보 누출'))
        self.assertEqual((f2['status'], f2['severity']), ('양호', '하'))
        self.assertEqual((f3['item_id'], f3['status'], f3['severity']), ('IL-ERRORPAGE-01', '취약', '중'))
        self.assertIn('/login 경로에서', f1['evidence'])
        self.assertIn('student1', f1['evidence'])
        self.assertEqual(f1['asset']['name'], '웹 서비스 (localhost:5000)')
        self.assertTrue(f1['asset']['handles_personal_data'])
        conv2 = from_scanner_results([{"category": "주석 내 정보 누출", "result": "unknown", "severity": "weird"},
                                      {"category": "낯선 유형", "result": "vulnerable", "severity": "high"}])
        self.assertEqual([f['item_id'] for f in conv2['findings']], ['IL-COMMENT-01', 'W-01'])
        self.assertEqual((conv2['findings'][0]['status'], conv2['findings'][0]['severity']), ('수동확인', '중'))
        self.assertTrue(conv2['scan_id'].startswith('SCAN-'))
        self.assertEqual(to_scan_input({"scan_id": "X", "findings": []}), {"scan_id": "X", "findings": []})   # 이미 ScanInput이면 그대로


class SchemaTest(unittest.TestCase):
    def test_sample_files_match_contracts(self):
        for name in ('output_test.json', 'output_sample.json'):
            ModuleOutput.model_validate_json((SAMPLES / name).read_text(encoding='utf-8'))
        for name in ('input_sample.json', 'input_test.json'):
            ScanInput.model_validate_json((SAMPLES / name).read_text(encoding='utf-8'))
        from module3.adapters import to_scan_input
        ScanInput.model_validate(to_scan_input(json.loads((SAMPLES / 'input_scanner_format.json').read_text(encoding='utf-8'))))

    def test_llm_response_model(self):
        ok = IsmsPMapping.model_validate({"isms_p": [{"criterion_id": "2.6.6", "relevance": "primary", "reason": "r"}], "notes": ""})
        self.assertEqual(ok.isms_p[0].criterion_id, '2.6.6')
        with self.assertRaises(ValidationError):
            IsmsPMapping.model_validate({"isms_p": [{"criterion_id": "2.6.6", "relevance": "maybe", "reason": "r"}], "notes": ""})
        with self.assertRaises(ValidationError):
            IsmsPMapping.model_validate({"isms_p": "2.6.6"})

    def test_input_contract(self):
        ScanInput.model_validate({"scan_id": "S", "findings": [{"item_id": "W-01", "title": "t", "status": "취약", "extra_field": 1}]})
        with self.assertRaises(ValidationError):
            ScanInput.model_validate({"scan_id": "S", "findings": [{"title": "item_id 없음", "status": "취약"}]})

    def test_output_contract_rejects_drift(self):
        out = json.loads((SAMPLES / 'output_test.json').read_text(encoding='utf-8'))
        out['findings'][0]['violated_laws'][0]['unexpected'] = 1
        with self.assertRaises(ValidationError):
            ModuleOutput.model_validate(out)

    def test_schema_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = main.export_schemas(Path(tmp))
            self.assertEqual([p.name for p in paths], ['input.schema.json', 'output.schema.json', 'llm_response.schema.json'])
            schema = json.loads(paths[1].read_text(encoding='utf-8'))
            self.assertIn('ViolatedLaw', schema['$defs'])


class RunTest(unittest.TestCase):
    def test_run_end_to_end_with_fake_llm(self):
        usage = {"prompt_tokens": 20000, "cached_tokens": 0, "completion_tokens": 50}

        def fake_llm(messages, schema):
            if schema.__name__ == 'IsmsPMapping':
                return {"isms_p": [{"criterion_id": "2.5.3", "relevance": "primary", "reason": "r"}], "notes": ""}, usage
            return {"laws": [{"law_code": "PIPA-29", "applicable": True, "paragraphs": [], "reason": "a"},
                             {"law_code": "SAFE-5", "applicable": True, "paragraphs": ["제6항"], "reason": "b"},
                             {"law_code": "SAFE-6", "applicable": False, "paragraphs": [], "reason": "c"}],
                    "notes": ""}, {"prompt_tokens": 3000, "cached_tokens": 0, "completion_tokens": 80}

        data = {"scan_id": "T", "scan_date": "2026-10-02", "target_system": "t",
                "findings": [finding(), finding(item_id='W-02', status='양호'), finding(item_id='W-03', status='점검불가')]}
        with tempfile.TemporaryDirectory() as tmp:
            inp, outp = Path(tmp) / 'in.json', Path(tmp) / 'out.json'
            inp.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
            with mock.patch.object(Mapper, '_call_llm', side_effect=fake_llm), \
                    mock.patch('module3.mapper.CACHE_DIR', Path(tmp)), \
                    mock.patch.object(main, 'log', lambda m: None):
                out = main.run(inp, outp, model='gpt-4.1-mini', offline=False, use_cache=False)
            self.assertTrue(outp.exists())
            ModuleOutput.model_validate(out)
            self.assertEqual(out['mapping']['method'], 'llm+rule')
            self.assertEqual(out['mapping']['llm_calls'], 2)                   # 취약 1건: 기준 선택 1회 + 항 판단 1회
            self.assertEqual(out['mapping']['tokens']['prompt'], 23000)
            self.assertEqual([r['ref_id'] for r in out['references']], ['PIPA-21445', 'SAFE-2026-9', 'ISMSP-2023.11'])
            f1, f2, f3 = out['findings']
            self.assertEqual([(v['law_code'], v['paragraph'], v['mapped_by']) for v in f1['violated_laws']],
                             [('PIPA-29', None, 'rule+llm'), ('SAFE-5', '제6항', 'rule+llm')])
            self.assertIn('SAFE-6', f1['review_note'])
            self.assertTrue(all('evidence' in f for f in out['findings']))
            self.assertEqual((f2['violated_laws'], f2['isms_p']), ([], []))
            self.assertIn('매핑 대상이 아님', f3['review_note'])

    def test_run_survives_llm_failure(self):
        data = {"scan_id": "T", "findings": [finding()]}
        with tempfile.TemporaryDirectory() as tmp:
            inp, outp = Path(tmp) / 'in.json', Path(tmp) / 'out.json'
            inp.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
            with mock.patch.object(Mapper, '_call_llm', side_effect=RuntimeError('boom')), \
                    mock.patch('module3.mapper.CACHE_DIR', Path(tmp)), \
                    mock.patch.object(main, 'log', lambda m: None):
                out = main.run(inp, outp, model='gpt-4.1-mini', offline=False, use_cache=False)
            f = out['findings'][0]
            self.assertEqual((f['violated_laws'], f['isms_p']), ([], []))
            self.assertIn('LLM 호출 실패', f['review_note'])


if __name__ == '__main__':
    unittest.main()
