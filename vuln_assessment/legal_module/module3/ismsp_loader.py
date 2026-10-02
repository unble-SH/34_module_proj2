"""ISMS-P 인증기준 안내서 txt -> 기준 사전.

txt 형식 (변환 스크립트 출력):
    2.6. 접근통제                 <- 분야 제목
    2.6.6 원격접근 통제            <- 기준 제목
    [인증기준] ... [주요 확인사항] ... [관련 법규] ... [세부 설명] ... [증거자료 예시] ... [결함사례]
"""
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .config import ISMSP_FILE, LAW_NAME_TO_KEY
from .law_loader import article_id

CRIT_RE = re.compile(r'^([123]\.\d{1,2}\.\d{1,2}) (\S.*)$')
DOMAIN_RE = re.compile(r'^(\d+\.\d+)\. (\S.*)$')
SECTION_RE = re.compile(r'^\[(.+)\]$')
LAWREF_ART_RE = re.compile(r'제(\d+)조(?:의(\d+))?\s*\(([^)]*)\)')


@dataclass
class LawRef:
    law_name: str
    law_key: Optional[str]
    articles: list            # [(조문 id, 안내서에 적힌 제목)]
    raw: str


@dataclass
class Criterion:
    id: str
    title: str
    domain_id: str
    domain: str
    sections: dict = field(default_factory=dict)   # 구역 이름 -> 줄 목록
    related_laws: list = field(default_factory=list)

    @property
    def standard(self) -> str:
        return ' '.join(self.sections.get('인증기준', [])).strip()

    @property
    def label(self) -> str:
        return f"{self.id}({self.title})"

    def bullets(self, section: str) -> list:
        return [re.sub(r'^-\s*', '', l) for l in self.sections.get(section, []) if l.startswith('-')]


@dataclass
class IsmsP:
    criteria: dict = field(default_factory=dict)
    unknown_law_names: set = field(default_factory=set)

    def get(self, cid: str) -> Optional[Criterion]:
        return self.criteria.get(cid)

    def candidate_text(self, max_len: int = 160, max_checks: int = 4, check_len: int = 100) -> str:
        """LLM 프롬프트용 101개 기준 목록 (인증기준 요약 + 주요 확인사항 요약)."""
        rows = []
        for c in self.criteria.values():
            std = c.standard
            if len(std) > max_len:
                std = std[:max_len].rstrip() + '…'
            checks = []
            for b in c.bullets('주요 확인사항')[:max_checks]:
                checks.append(b if len(b) <= check_len else b[:check_len].rstrip() + '…')
            row = f"{c.id} {c.title} | 인증기준: {std}"
            if checks:
                row += " | 주요 확인사항: " + ' / '.join(checks)
            rows.append(row)
        return '\n'.join(rows)


def parse_law_ref(line: str) -> LawRef:
    body = re.sub(r'^-\s*', '', line).strip()
    law_name = re.split(r'\s제\d', body)[0].strip()
    arts = [(article_id(int(m[1]), int(m[2]) if m[2] else None), m[3].strip()) for m in LAWREF_ART_RE.finditer(body)]
    return LawRef(law_name=law_name, law_key=LAW_NAME_TO_KEY.get(law_name), articles=arts, raw=body)


def load_ismsp(path: Path = ISMSP_FILE) -> IsmsP:
    out = IsmsP()
    domain_id, domain = '', ''
    crit: Optional[Criterion] = None
    section: Optional[str] = None
    for raw in path.read_text(encoding='utf-8').split('\n'):
        line = raw.rstrip()
        if not line:
            continue
        dm = DOMAIN_RE.match(line)
        if dm and not CRIT_RE.match(line):
            domain_id, domain = dm[1], dm[2]
            crit, section = None, None
            continue
        cm = CRIT_RE.match(line)
        if cm:
            crit = Criterion(id=cm[1], title=cm[2].strip(), domain_id=domain_id, domain=domain)
            out.criteria[crit.id] = crit
            section = None
            continue
        sm = SECTION_RE.match(line)
        if sm and crit is not None:
            section = sm[1]
            crit.sections.setdefault(section, [])
            continue
        if crit is not None and section is not None:
            crit.sections[section].append(line)
    for c in out.criteria.values():
        for l in c.sections.get('관련 법규', []):
            if l.startswith('-'):
                ref = parse_law_ref(l)
                if ref.law_key is None:
                    out.unknown_law_names.add(ref.law_name)
                c.related_laws.append(ref)
    return out


if __name__ == '__main__':
    import sys
    sys.stdout.reconfigure(encoding='utf-8')
    isms = load_ismsp()
    with_law = [c for c in isms.criteria.values() if c.related_laws]
    print(f"기준 {len(isms.criteria)}개, 관련 법규 있는 기준 {len(with_law)}개, 미등록 법령명 {isms.unknown_law_names or '없음'}")
    c = isms.get('2.6.6')
    print(c.label, '|', c.domain, '|', c.standard[:80])
    for r in c.related_laws:
        print('   ', r.law_key, r.law_name, r.articles)
