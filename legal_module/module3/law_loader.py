"""법령 txt(법제처 원문을 변환한 파일) -> 조문 사전.

규칙 (팀 합의 2026-10-02)
- 부칙(`부칙 <...>` 줄) 이후는 읽지 않는다. 부칙 제1조~제4조가 본문과 번호가 겹치기 때문.
- 같은 조문이 두 벌이면 `[시행일: ...]` 표기가 없는 쪽이 현행본. 현행본만 쓰고 in_force=True.
- 예정본만 있는 조문(예: 제28조의12~15)은 in_force=False로 등록한다.
- 장·절 제목 뒤에 붙은 `[시행일]` 표기는 조문이 아니므로 무시한다.
"""
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .config import LAW_FILES, LAW_TYPES, IN_FORCE_OVERRIDES

ART_RE = re.compile(r'^제(\d+)조(?:의(\d+))?(?:\(([^)]*)\)|\s*(삭제))')
CHAP_RE = re.compile(r'^제\d+(장|절)\s')
BUCHIK_RE = re.compile(r'^부칙\s*<')
SIHANG_RE = re.compile(r'^\[시행일:\s*(\d{4})\.\s*(\d{1,2})\.\s*(\d{1,2})\.\s*\]')
HEADER_RE = re.compile(r'^\[시행\s*(\d{4})\.\s*(\d{1,2})\.\s*(\d{1,2})\.\s*\]\s*\[(.+?)\s*(제[\d\-]+호)')
CIRCLED = '①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳㉑㉒㉓㉔㉕㉖㉗㉘㉙㉚'
ART_HEAD_RE = re.compile(r'^(제\d+조(?:의\d+)?\([^)]*\))\s*(.*)$')


def split_paragraphs(text: str) -> list:
    """조문 원문을 항 단위로 나눈다. -> [(라벨, 원문)]  예: [("제1항", "① ..."), ("제2항", "② ...")]

    헤더 줄 "제6조(접근통제) ① ..."의 ①부터 제1항이 시작하고, 이후 ②③…로 시작하는 줄이 새 항이다.
    호(1. 2.)·목(가. 나.)·[본조신설] 같은 줄은 직전 항에 붙는다. 항 구분이 없는 조문은 빈 목록."""
    lines = text.split('\n')
    paras = []
    cur = None
    m = ART_HEAD_RE.match(lines[0])
    rest = m[2] if m else ''
    if rest and rest[0] in CIRCLED:
        cur = [f"제{CIRCLED.index(rest[0]) + 1}항", [rest]]
        paras.append(cur)
    for line in lines[1:]:
        if line and line[0] in CIRCLED:
            cur = [f"제{CIRCLED.index(line[0]) + 1}항", [line]]
            paras.append(cur)
        elif cur is not None:
            cur[1].append(line)
    return [(label, '\n'.join(ls)) for label, ls in paras]


def norm_title(s: Optional[str]) -> str:
    """제목 비교용 정규화: 공백 제거, 가운뗷점 통일."""
    if not s:
        return ''
    return re.sub(r'\s+', '', s).replace('·', 'ㆍ').replace('･', 'ㆍ').replace('•', 'ㆍ')


def article_id(num: int, sub: Optional[int]) -> str:
    return f"제{num}조" + (f"의{sub}" if sub else '')


def parse_article_id(s: str) -> Optional[str]:
    """'제29조', '제28조의2', '제12조 (…)' 같은 문자열에서 조문 id만 뽑는다."""
    m = re.match(r'^\s*제(\d+)조(?:의(\d+))?', s)
    if not m:
        return None
    return article_id(int(m[1]), int(m[2]) if m[2] else None)


@dataclass
class Article:
    id: str
    num: int
    sub: Optional[int]
    title: Optional[str]
    text: str
    in_force: bool
    future_date: Optional[str] = None
    note: Optional[str] = None

    @property
    def code_suffix(self) -> str:
        """law_code 뒷부분: 제29조 -> '29', 제28조의2 -> '28의2'."""
        return f"{self.num}" + (f"의{self.sub}" if self.sub else '')

    def paragraphs(self) -> list:
        """항 목록 [(라벨, 원문)]. 삭제된 항('⑥ 삭제')은 제외."""
        return [(label, body) for label, body in split_paragraphs(self.text)
                if not re.match(r'^[' + CIRCLED + r']\s*삭제', body)]


@dataclass
class Law:
    key: str
    name: str
    law_type: str
    version: str
    effective_date: str
    source_file: str
    articles: dict = field(default_factory=dict)         # id -> Article (현행본 우선)
    future_versions: dict = field(default_factory=dict)  # id -> Article (예정본, 참고용)
    dropped_duplicates: list = field(default_factory=list)

    @property
    def ref_id(self) -> str:
        m = re.search(r'제([\d\-]+)호', self.version)
        return f"{self.key}-{m[1]}" if m else self.key

    def get(self, aid: str) -> Optional[Article]:
        return self.articles.get(aid)

    def candidate_list(self) -> list:
        """LLM 후보 목록용: 중복 제거된 현행 조문 (번호, 제목)."""
        return [(a.id, a.title) for a in self.articles.values() if a.in_force and a.title]

    def reference(self) -> dict:
        return {
            "ref_id": self.ref_id, "title": self.name, "type": self.law_type,
            "version": self.version, "effective_date": self.effective_date, "source_file": self.source_file,
        }


def parse_law_file(path: Path, key: str) -> Law:
    lines = path.read_text(encoding='utf-8').split('\n')
    name = lines[0].strip()
    hm = HEADER_RE.match(lines[1].strip())
    if not hm:
        raise ValueError(f"{path.name}: 2번째 줄에서 [시행 ...] [... 제N호] 머리말을 찾지 못함")
    effective = f"{hm[1]}-{int(hm[2]):02d}-{int(hm[3]):02d}"
    version = f"{hm[4].strip().rstrip(',')} {hm[5]}"

    blocks = []
    cur = None
    for raw in lines[2:]:
        line = raw.rstrip()
        if BUCHIK_RE.match(line):
            break
        if not line:
            continue
        if CHAP_RE.match(line):
            cur = None
            continue
        am = ART_RE.match(line)
        if am:
            num, sub = int(am[1]), (int(am[2]) if am[2] else None)
            cur = dict(id=article_id(num, sub), num=num, sub=sub, title=am[3], deleted=bool(am[4]),
                       lines=[line], future_date=None)
            blocks.append(cur)
            continue
        sm = SIHANG_RE.match(line)
        if sm:
            if cur is not None:
                cur['future_date'] = f"{sm[1]}-{int(sm[2]):02d}-{int(sm[3]):02d}"
                cur['lines'].append(line)
            continue
        if cur is not None:
            cur['lines'].append(line)

    law = Law(key=key, name=name, law_type=LAW_TYPES.get(key, ''), version=version,
              effective_date=effective, source_file=path.name)
    for b in blocks:
        art = Article(id=b['id'], num=b['num'], sub=b['sub'], title=None if b['deleted'] else b['title'],
                      text='\n'.join(b['lines']), in_force=b['future_date'] is None, future_date=b['future_date'],
                      note='삭제된 조문' if b['deleted'] else None)
        if art.in_force:
            if art.id in law.articles:
                law.dropped_duplicates.append(art.id)
                continue
            law.articles[art.id] = art
        else:
            law.future_versions.setdefault(art.id, art)
    for aid, art in law.future_versions.items():
        if aid not in law.articles:
            art.note = f"{art.future_date} 시행 예정 (현행본 없음)"
            law.articles[aid] = art
    for aid, (inf, note) in IN_FORCE_OVERRIDES.get(key, {}).items():
        if aid in law.articles:
            law.articles[aid].in_force = inf
            law.articles[aid].note = note
    # 조문 번호 순 정렬
    law.articles = dict(sorted(law.articles.items(), key=lambda kv: (kv[1].num, kv[1].sub or 0)))
    return law


def load_all_laws() -> dict:
    laws = {}
    for key, path in LAW_FILES.items():
        if path.exists():
            laws[key] = parse_law_file(path, key)
    return laws


if __name__ == '__main__':
    import sys
    sys.stdout.reconfigure(encoding='utf-8')
    for key, law in load_all_laws().items():
        print(f"[{key}] {law.name} | {law.version} | 시행 {law.effective_date} | ref {law.ref_id}")
        print(f"   조문 {len(law.articles)}개, 예정본 {len(law.future_versions)}개, 버려진 중복 {law.dropped_duplicates}")
        for a in law.articles.values():
            if not a.in_force or a.note:
                print(f"   - {a.id} in_force={a.in_force} note={a.note}")
