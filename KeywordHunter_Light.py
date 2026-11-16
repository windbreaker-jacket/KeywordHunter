# -*- coding: utf-8 -*-
#

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from java.lang import String as JString, Thread, Runnable, Boolean
from java.awt import BorderLayout, Color, Font, FlowLayout, GridLayout, Toolkit
from java.awt.datatransfer import DataFlavor
from java.awt.event import ActionListener, MouseAdapter, KeyEvent, InputEvent
from java.util.regex import Pattern
from java.util import Comparator
from javax.swing import (JPanel, JSplitPane, JTabbedPane, JTable, JScrollPane,
                         JButton, JLabel, JTextField, JTextArea, JCheckBox,
                         JComboBox, JMenuItem, JFileChooser, BorderFactory,
                         SwingUtilities, JProgressBar, ListSelectionModel,
                         RowFilter, JOptionPane, JPopupMenu, KeyStroke,
                         AbstractAction, JComponent)
from javax.swing.table import (DefaultTableModel, TableRowSorter,
                               DefaultTableCellRenderer)
from javax.swing.event import (ListSelectionListener, DocumentListener,
                                ChangeListener, TableModelListener)
from javax.swing.text import DefaultHighlighter
from collections import OrderedDict
import re
import csv
import json

TOOL_PROXY = 0x04

NEW_TAB_COLOR = Color(255, 160, 70)    # 새 데이터 들어온 탭
NEW_ROW_COLOR = Color(255, 236, 150)   # 새로 추가된(미확인) 행

PRESETS = OrderedDict([
    (u"Secrets / Credentials", [
        u"AKIA", u"aws_secret", u"x-amz-security-token",
        u"AIza", u"ya29.",
        u"ghp_", u"gho_", u"github_pat_",
        u"xoxb-", u"xoxp-",
        u"sk_live_", u"pk_live_",
        u"-----BEGIN", u"PRIVATE KEY",
        u"api_key", u"apikey", u"secret", u"client_secret",
        u"access_token", u"refresh_token",
        u"password", u"passwd", u"pwd", u"credentials",
        u"authorization:", u"bearer ",
    ]),
    (u"Config / Env Files", [
        u".env", u"config.json", u"settings.py", u"web.config",
        u"application.properties", u".aws/credentials",
        u"DB_PASSWORD", u"DATABASE_URL", u"connectionString",
        u"jdbc:", u"mongodb://", u"redis://",
    ]),
    (u"Debug / Dev Mistakes", [
        u"TODO", u"FIXME",
        u"debug", u"console.log", u"print_r", u"var_dump", u"dd(",
        u"stack trace", u"Exception", u"at java.",
        u"Warning:", u"Notice:", u"Fatal error",
    ]),
    (u"Internal Hosts / IP", [
        u"10.", u"192.168.", u"172.16.",
        u"localhost", u".internal", u".local",
    ]),
    (u"Source Code Mgmt", [
        u".git/", u".svn/", u".hg/", u".bzr/",
    ]),
    (u"Framework / Endpoints", [
        u"/actuator", u"/actuator/health", u"/actuator/env", u"/jolokia",
        u"/graphql", u"__graphql", u"IntrospectionQuery", u"__schema",
        u"gwt.rpc", u".nocache.js",
        u"swagger", u"/api-docs", u"openapi",
    ]),
    (u"Redirect / Hidden Params", [
        u"redirect", u"url", u"next", u"return", u"returnUrl",
        u"callback", u"continue", u"dest", u"redirect_uri",
    ]),
])

# =============================================================================
# i18n
# =============================================================================
LANG = {
    "ko": {
        "lang": u"언어:", "version": u"버전: 1.0", "headers": u"헤더 포함",
        "filter": u"대상 필터", "scope": u"Burp Scope 내 패킷만",
        "find": u"찾기:", "refresh": u"도메인 새로고침", "toggle": u"전체 선택/해제",
        "dom_col": u"도메인", "ext": u"제외 확장자(, 구분):",
        "maxsize": u"최대 응답 크기(byte):", "range": u"검색 범위:", "kw_all": u"전체 선택/해제",
        "range_both": u"요청+응답", "range_req": u"요청만", "range_resp": u"응답만",
        "kw": u"키워드", "col_regex": u"정규식", "col_pkt": u"패킷", "col_match": u"매칭",
        "case": u"대소문자 구분", "variants": u"한글 인코딩 변형 포함",
        "add": u"추가", "del": u"삭제", "paste": u"Paste", "loadfile": u"파일 불러오기",
        "preset": u"프리셋 불러오기", "scan": u"History 스캔",
        "rt_on": u"실시간 ON", "rt_off": u"실시간 OFF", "csv": u"CSV 내보내기",
        "collapse": u"중복 URL 접기", "clear": u"초기화",
        "res_url": u"URL", "res_match": u"매칭", "res_len": u"Length", "res_time": u"Time",
        "vsearch": u"검색:", "vauto": u"자동 스크롤", "wrap": u"줄바꿈",
        "tab_search": u"키워드 검색",
        "col_preset": u"프리셋",
        "s_nokw": u"활성 키워드 없음", "s_done": u"스캔 완료: %d건",
        "s_clear": u"초기화됨", "s_csv": u"CSV 저장: ",
        "s_paste": u"붙여넣기: %d개 추가", "s_file": u"파일에서 %d개 추가",
    },
    "en": {
        "lang": u"Language:", "version": u"Version: 1.0", "headers": u"Include headers",
        "filter": u"Target Filter", "scope": u"In Burp Scope only",
        "find": u"Find:", "refresh": u"Refresh domains", "toggle": u"Select / clear all",
        "dom_col": u"Domain", "ext": u"Exclude extensions (, sep):",
        "maxsize": u"Max response size (byte):", "range": u"Search in:", "kw_all": u"Select/clear all",
        "range_both": u"Request+Response", "range_req": u"Request only",
        "range_resp": u"Response only",
        "kw": u"Keywords", "col_regex": u"Regex", "col_pkt": u"Packets", "col_match": u"Matches",
        "case": u"Case sensitive", "variants": u"Include Korean encoding variants",
        "add": u"Add", "del": u"Delete", "paste": u"Paste", "loadfile": u"Load file",
        "preset": u"Load preset", "scan": u"Scan history",
        "rt_on": u"Realtime ON", "rt_off": u"Realtime OFF", "csv": u"Export CSV",
        "collapse": u"Collapse dup URLs", "clear": u"Clear",
        "res_url": u"URL", "res_match": u"Matches", "res_len": u"Length", "res_time": u"Time",
        "vsearch": u"Search:", "vauto": u"Auto-scroll", "wrap": u"Wrap",
        "tab_search": u"Keyword Search",
        "col_preset": u"Preset",
        "s_nokw": u"No active keyword", "s_done": u"Scan done: %d",
        "s_clear": u"Cleared", "s_csv": u"CSV saved: ",
        "s_paste": u"Pasted: %d added", "s_file": u"%d added from file",
    },
}

# =============================================================================
# 탭별 도움말 (? 버튼)
# =============================================================================
HELP = {
    "ko": {
        "search": (u"키워드 검색", u"""HTTP history에서 키워드로 요청/응답을 검색하는 탭입니다.

[대상 필터] (왼쪽)
- Burp Scope 내 패킷만: 체크 시 Scope 안의 패킷만 대상.
- 도메인 체크리스트: 선택한 도메인만 검색(아무것도 안 고르면 전체). 찾기/새로고침/전체 토글 지원.
- 제외 확장자: 쉼표로 구분한 확장자(jpg,png,css 등)를 결과에서 제외.
- 최대 응답 크기(byte): 이 크기를 넘는 응답은 제외.
- 검색 범위: 요청/응답 중 어디를 볼지. '헤더 포함' 체크 시 헤더까지 검색.

[키워드]
- 추가/삭제/Paste(클립보드 일괄)/파일 불러오기/프리셋.
- 정규식 체크 시 그 키워드를 정규식으로 검색.
- 한 번 클릭=단일 선택, 드래그/Ctrl=다중 선택, 단독 선택 재클릭=해제.
- 전체 선택/해제, 대소문자 구분, 한글 인코딩 변형 포함 옵션.

[동작]
- History 스캔: 현재까지 쌓인 history를 일괄 검색.
- 실시간 ON/OFF: 새로 들어오는 패킷을 자동 검사(이때 Time은 실제 수신 시각).
- 중복 URL 접기: 같은 URL 패킷을 하나로 접기(length가 다르면 ▶로 펼쳐 확인).
- 결과 행 선택 시 요청/응답 뷰어에 키워드가 자동 입력되고 매칭 위치로 스크롤.
- Time: 실시간으로 받은 패킷만 실제 시각이 표시되고, 기존 history 패킷은 비어 있습니다."""),
        "keyword_regex": (u"키워드 / 정규식 사용법", u"""[ 키워드 검색 사용법 ]
- 입력칸에 단어를 쓰고 '추가'를 누르면 키워드가 등록됩니다.
- Paste: 클립보드의 여러 줄 단어를 한 번에 추가.
- 파일 불러오기: 텍스트 파일의 각 줄을 키워드로 추가.
- 프리셋 불러오기: 자주 쓰는 세트(secret/dev/internal/cloud/admin/pii)를 한 번에 추가.
  (추가된 키워드는 '프리셋' 열에 출처가 표시됩니다.)
- 체크박스(✓)로 각 키워드 on/off. '전체 선택/해제'로 한꺼번에.
- 한 번 클릭=단일 선택, 드래그/Ctrl=다중 선택, 단독 선택 재클릭=해제.
- 삭제: 선택된 행 + 체크된 행을 모두 삭제.
- '대소문자 구분', '한글 인코딩 변형 포함' 옵션 지원.
- 'History 스캔'으로 기존 전체 검색, '실시간 ON'으로 새 트래픽 자동 검사.

[ 정규식(Regex) 사용법 ]
키워드 행의 '정규식'을 체크하면 그 키워드를 패턴으로 해석합니다.
값이 매번 바뀌는 토큰·키·개인정보처럼 '모양은 같고 내용은 다른' 것을 찾을 때 유용.

 자주 쓰는 기호
  \\d  숫자        \\w  영문/숫자     .  아무 글자
  +   1개 이상     *   0개 이상      {16} 정확히 16개
  [A-Z] 범위       |   또는         ^ $ 시작/끝

 예시
  AWS 키        AKIA[0-9A-Z]{16}
  이메일        [\\w.\\-]+@[\\w.\\-]+\\.\\w+
  휴대폰        01[016789]-?\\d{3,4}-?\\d{4}
  주민번호      \\d{6}-?[1-4]\\d{6}
  JWT           eyJ[\\w\\-]+\\.[\\w\\-]+\\.[\\w\\-]+
  Bearer 토큰   Bearer\\s+[A-Za-z0-9._\\-]+

참고: 정규식을 켜면 한글 인코딩 변형 검색은 적용되지 않습니다(패턴 검색 우선).
패턴이 잘못되면 그 키워드만 매칭 0으로 처리되고 다른 검색엔 영향 없습니다."""),
    },
    "en": {
        "search": (u"Keyword Search", u"""Search requests/responses in the HTTP history by keyword.

Target Filter (left): scope toggle, domain checklist (only selected domains; none = all), exclude extensions, max response size, search range (+include headers).
Keywords: add/delete/paste/load-file/preset; regex option; single click selects one, drag/Ctrl multi-select, re-click a sole selection to clear.
Actions: scan history, realtime ON/OFF (Time = actual receive time), collapse duplicate URLs. Selecting a row fills the viewer search box with the keyword and scrolls to the match.
Time is shown only for packets captured live; pre-existing history rows are blank."""),
        "keyword_regex": (u"Keyword / Regex usage", u"""[ Keyword search ]
- Type a word and click Add to register a keyword.
- Paste: add many clipboard lines at once. Load file: add each line of a text file.
- Load preset: add a common set (secret/dev/internal/cloud/admin/pii) at once.
  (The 'Preset' column shows where each keyword came from.)
- Checkbox (✓) toggles each keyword; 'Select/clear all' toggles everything.
- Single click = select one, drag/Ctrl = multi-select, re-click a sole selection to clear.
- Delete: removes selected rows + checked rows.
- Options: case sensitive, include Korean encoding variants.
- 'Scan history' searches existing traffic; 'Realtime ON' auto-checks new traffic.

[ Regex ]
Enable 'Regex' on a keyword row to treat it as a pattern — useful for tokens,
keys and PII whose shape is fixed but value changes.

 Common tokens
  \\d digit   \\w word char   . any   +  1+   *  0+   {16} exactly 16
  [A-Z] range   |  or   ^ $  start/end

 Examples
  AWS key   AKIA[0-9A-Z]{16}
  email     [\\w.\\-]+@[\\w.\\-]+\\.\\w+
  JWT       eyJ[\\w\\-]+\\.[\\w\\-]+\\.[\\w\\-]+
  Bearer    Bearer\\s+[A-Za-z0-9._\\-]+

Note: with Regex on, Korean encoding-variant search is skipped. A bad pattern
just yields 0 matches for that keyword and doesn't affect others."""),
    },
}

# =============================================================================
# 디코딩 / 매칭 엔진
# =============================================================================
_CHARSET_RE = re.compile(r'charset\s*=\s*["\']?\s*([A-Za-z0-9_\-]+)', re.I)
_META_RE = re.compile(r'<meta[^>]+charset\s*=\s*["\']?\s*([A-Za-z0-9_\-]+)', re.I)


def _latin1(raw):
    if raw is None:
        return u""
    return unicode(JString(raw, "ISO-8859-1"))


def detect_charset(raw):
    head = _latin1(raw)[:4096]
    m = _CHARSET_RE.search(head) or _META_RE.search(head)
    if m:
        cs = m.group(1).strip().lower()
        if cs in ("euc-kr", "euckr", "ks_c_5601-1987", "cp949"):
            return "MS949"
        return m.group(1)
    return None


def decode_bytes(raw):
    if raw is None:
        return u""
    order = []
    cs = detect_charset(raw)
    if cs:
        order.append(cs)
    for c in ("UTF-8", "MS949"):
        if c not in order:
            order.append(c)
    for c in order:
        try:
            return unicode(JString(raw, c))
        except Exception:
            continue
    return _latin1(raw)


def now_str():
    """현재 로컬 시각(KST 등) 'yyyy-MM-dd HH:mm:ss'. 실시간 수신 시각."""
    from java.text import SimpleDateFormat
    from java.util import Date
    return unicode(SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Date()))


_TIME_ACCESSOR = {}   # className -> java.lang.reflect.Method | None (한 번만 탐색)


def reflect_time(msg):
    """Burp history 항목 내부에 저장된 '프록시 통과 시각'을 reflection으로 획득.

    HTTP history의 Time 컬럼과 동일한 값. 인자 없는 메서드 중 java.util.Date를
    반환하고 이름에 time/date가 든 것만 안전하게 사용. 없으면 None.
    """
    try:
        cls = msg.getClass()
        key = cls.getName()
        if key not in _TIME_ACCESSOR:
            chosen = None
            for m in cls.getMethods():
                if len(m.getParameterTypes()) != 0:
                    continue
                if m.getReturnType().getName() != "java.util.Date":
                    continue
                nm = m.getName().lower()
                if "time" in nm or "date" in nm:
                    chosen = m
                    break
            _TIME_ACCESSOR[key] = chosen
        m = _TIME_ACCESSOR[key]
        if m is None:
            return None
        val = m.invoke(msg, [])
        if val is None:
            return None
        from java.text import SimpleDateFormat
        return unicode(SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(val))
    except Exception:
        return None


def url_ext(url):
    """URL 경로의 확장자(소문자) 반환. 없으면 빈 문자열."""
    u = url.split("?", 1)[0].split("#", 1)[0]
    seg = u.rsplit("/", 1)[-1]
    if "." in seg:
        return seg.rsplit(".", 1)[-1].lower()
    return u""


def korean_variants(kw):
    out = []
    if all(ord(ch) < 128 for ch in kw):
        return out
    out.append(u"".join(u"\\u%04x" % ord(ch) for ch in kw))
    out.append(u"".join(u"\\u%04X" % ord(ch) for ch in kw))
    try:
        out.append(u"".join(u"%%%02X" % b for b in bytearray(kw.encode("utf-8"))))
    except Exception:
        pass
    try:
        enc = JString(kw).getBytes("MS949")
        out.append(u"".join(u"%%%02X" % (b & 0xff) for b in enc))
    except Exception:
        pass
    out.append(u"".join(u"&#%d;" % ord(ch) for ch in kw))
    out.append(u"".join(u"&#x%X;" % ord(ch) for ch in kw))
    return out


def body_start(text):
    """헤더/본문 구분 지점(본문 시작 오프셋). 없으면 0."""
    for sep in ("\r\n\r\n", "\n\n"):
        i = text.find(sep)
        if i >= 0:
            return i + len(sep)
    return 0


def find_offsets(text, kw, is_regex, case_sensitive, use_variants):
    if not text or not kw:
        return []
    spans = []
    flags = 0 if case_sensitive else re.I
    if is_regex:
        try:
            for m in re.finditer(kw, text, flags):
                spans.append((m.start(), m.end()))
        except re.error:
            pass
        return spans
    needles = [kw]
    if use_variants:
        needles += korean_variants(kw)
    hay = text if case_sensitive else text.lower()
    for ndl in needles:
        n = ndl if case_sensitive else ndl.lower()
        if not n:
            continue
        start = 0
        while True:
            i = hay.find(n, start)
            if i < 0:
                break
            spans.append((i, i + len(n)))
            start = i + len(n)
    spans.sort()
    return spans


# =============================================================================
# 결과 레코드
# =============================================================================
class Result(object):
    __slots__ = ("msg", "host", "url", "keyword", "is_regex", "length", "time",
                 "req_text", "resp_text", "req_spans", "resp_spans", "count", "seen")

    def __init__(self, msg, host, url, keyword, is_regex, length, time,
                 req_text, resp_text, req_spans, resp_spans, seen=True):
        self.msg = msg
        self.host = host
        self.url = url
        self.keyword = keyword
        self.is_regex = is_regex
        self.length = length
        self.time = time
        self.req_text = req_text
        self.resp_text = resp_text
        self.req_spans = req_spans
        self.resp_spans = resp_spans
        self.count = len(req_spans) + len(resp_spans)
        self.seen = seen   # False = 실시간으로 새로 추가된 미확인 행


# =============================================================================
# 테이블 모델
# =============================================================================
class KeywordTableModel(DefaultTableModel):
    def getColumnClass(self, c):
        return Boolean if c in (0, 2) else JString
    def isCellEditable(self, r, c):
        return c in (0, 1, 2)


class DomainTableModel(DefaultTableModel):
    def getColumnClass(self, c):
        return Boolean if c == 0 else JString
    def isCellEditable(self, r, c):
        return c == 0


class ReadOnlyTableModel(DefaultTableModel):
    def isCellEditable(self, r, c):
        return False


# =============================================================================
# Pretty 포매팅 (JSON / HTML·XML / JS)
# =============================================================================
def _pretty_markup(s):
    s = re.sub(r">\s*<", ">\n<", s)
    out = []
    depth = 0
    void_re = re.compile(r"<(br|img|hr|meta|link|input|col|area|base)\b", re.I)
    open_re = re.compile(r"^<[^/!?][^>]*[^/]>$")
    for line in s.split("\n"):
        line = line.strip()
        if not line:
            continue
        if line.startswith("</"):
            depth = max(0, depth - 1)
        out.append("  " * depth + line)
        if open_re.match(line) and not void_re.match(line):
            depth += 1
    return "\n".join(out)


def _pretty_js(s):
    """문자열 인식 없는 best-effort JS/CSS 정렬 (가독성 보조용)."""
    out = []
    depth = 0
    buf = []
    for ch in s:
        if ch == "{":
            buf.append(ch)
            out.append("  " * depth + "".join(buf).strip())
            buf = []
            depth += 1
        elif ch == "}":
            if "".join(buf).strip():
                out.append("  " * depth + "".join(buf).strip())
                buf = []
            depth = max(0, depth - 1)
            out.append("  " * depth + "}")
        elif ch == ";":
            buf.append(ch)
            out.append("  " * depth + "".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        out.append("  " * depth + tail)
    return "\n".join(l for l in out if l.strip())


def make_pretty(raw):
    """헤더는 그대로 두고 본문(JSON/HTML/XML/JS)만 보기 좋게 포맷."""
    if not raw:
        return raw
    sep = "\r\n\r\n" if "\r\n\r\n" in raw else ("\n\n" if "\n\n" in raw else None)
    if sep:
        head, body = raw.split(sep, 1)
    else:
        head, body = u"", raw
    b = body.strip()
    pretty = body
    try:
        if b[:1] in ("{", "["):
            pretty = json.dumps(json.loads(b), indent=2, ensure_ascii=False)
        elif b[:1] == "<" or re.search(r"<\s*(html|!doctype|\?xml)", b, re.I):
            pretty = _pretty_markup(b)
        elif ("{" in b and "}" in b and ";" in b
              and (b.count("\n") * 200 < len(b))
              and re.search(r"(function|=>|var |let |const )", b)):
            pretty = _pretty_js(b)
    except Exception:
        pretty = body
    return (head + "\n\n" + pretty) if sep else pretty


# =============================================================================
# 검색칸 내장 뷰어 (Pretty/Raw 탭 + 줄바꿈 + \n + 키워드 자동입력 + 자동 스크롤)
# =============================================================================
class SearchViewer(JPanel):
    LIGHT = Color(255, 240, 150)
    STRONG = Color(255, 150, 60)

    def __init__(self):
        self.setLayout(BorderLayout())

        bar = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        self.wrap_chk = JCheckBox("", True)
        self.wrap_chk.addActionListener(WrapListener(self))
        self.nl_chk = JCheckBox("\\n", False)   # non-printable(CR/탭) 표시
        self.nl_chk.addActionListener(NlListener(self))
        self.lbl = JLabel()
        self.field = JTextField(12)
        self.auto = JCheckBox("", True)
        self.prev_btn = JButton(u"◀", actionPerformed=self._prev)
        self.next_btn = JButton(u"▶", actionPerformed=self._next)
        self.counter = JLabel("0 / 0")
        for c in (self.wrap_chk, self.nl_chk, self.lbl, self.field,
                  self.auto, self.prev_btn, self.next_btn, self.counter):
            bar.add(c)
        self.add(bar, BorderLayout.NORTH)

        self.pretty_area = self._make_area()
        self.raw_area = self._make_area()
        self.tabs = JTabbedPane()
        self.tabs.addTab("Pretty", JScrollPane(self.pretty_area))
        self.tabs.addTab("Raw", JScrollPane(self.raw_area))
        self.tabs.addChangeListener(TabListener(self))
        self.add(self.tabs, BorderLayout.CENTER)

        self.field.getDocument().addDocumentListener(SVFindListener(self))
        self.raw_text = u""
        self.spans = []
        self.idx = -1
        self.regex_mode = False
        self.case = False
        self.variants = True
        self._suppress = False

    def enable_repeater(self, main, get_msg):
        for area in (self.pretty_area, self.raw_area):
            install_repeater(area, main, get_msg)

    def _make_area(self):
        a = JTextArea()
        a.setEditable(False)
        a.setLineWrap(True)
        a.setWrapStyleWord(False)
        a.setFont(Font("Monospaced", Font.PLAIN, 12))
        return a

    def _area(self):
        return self.pretty_area if self.tabs.getSelectedIndex() == 0 else self.raw_area

    def set_labels(self, search_label, auto_label, wrap_label):
        self.lbl.setText(search_label)
        self.auto.setText(auto_label)
        self.wrap_chk.setText(wrap_label)

    def _raw_display(self):
        if not self.nl_chk.isSelected():
            return self.raw_text
        # CR/LF/TAB을 일반 글자 크기의 \r \n \t 로 표시. 줄바꿈은 유지.
        # \x00 을 '실제 줄바꿈' 임시표식으로 써서 중복 치환 방지.
        t = self.raw_text.replace(u"\t", u"\\t")
        t = t.replace(u"\r\n", u"\\r\\n\x00")
        t = t.replace(u"\r", u"\\r")
        t = t.replace(u"\n", u"\\n\x00")
        t = t.replace(u"\x00", u"\n")
        return t

    def load(self, text, term, is_regex, case, variants):
        self.raw_text = text or u""
        self.regex_mode = is_regex
        self.case = case
        self.variants = variants
        self.pretty_area.setText(make_pretty(self.raw_text))
        self.raw_area.setText(self._raw_display())
        self.pretty_area.setCaretPosition(0)
        self.raw_area.setCaretPosition(0)
        self._suppress = True
        self.field.setText(term or u"")
        self._suppress = False
        self._recompute(scroll=True)

    def _on_tab_change(self):
        self._recompute(scroll=self.auto.isSelected())

    def _on_wrap_change(self):
        sel = self.wrap_chk.isSelected()
        self.pretty_area.setLineWrap(sel)
        self.raw_area.setLineWrap(sel)

    def _on_nl_change(self):
        self.raw_area.setText(self._raw_display())
        self.raw_area.setCaretPosition(0)
        if self.tabs.getSelectedIndex() == 1:
            self._recompute(scroll=self.auto.isSelected())

    def _on_field_change(self):
        if self._suppress:
            return
        self.regex_mode = False   # 사용자가 직접 입력하면 리터럴 검색
        self._recompute(scroll=self.auto.isSelected())

    def _recompute(self, scroll):
        term = self.field.getText()
        text = self._area().getText()
        self.spans = find_offsets(text, term, self.regex_mode,
                                  self.case, self.variants)
        self.idx = 0 if self.spans else -1
        self._paint()
        if self.spans and scroll:
            self._scroll_to(0)
        self._counter()

    def _paint(self):
        area = self._area()
        hl = area.getHighlighter()
        hl.removeAllHighlights()
        light = DefaultHighlighter.DefaultHighlightPainter(self.LIGHT)
        strong = DefaultHighlighter.DefaultHighlightPainter(self.STRONG)
        for j, (a, b) in enumerate(self.spans):
            try:
                hl.addHighlight(a, b, strong if j == self.idx else light)
            except Exception:
                pass

    def _scroll_to(self, i):
        if not self.spans:
            return
        self.idx = i % len(self.spans)
        area = self._area()
        s, e = self.spans[self.idx]
        try:
            area.setCaretPosition(e)
            rect = area.modelToView(s)
            if rect:
                area.scrollRectToVisible(rect)
        except Exception:
            pass
        self._paint()
        self._counter()

    def _prev(self, ev):
        if self.spans:
            self._scroll_to(self.idx - 1)

    def _next(self, ev):
        if self.spans:
            self._scroll_to(self.idx + 1)

    def _counter(self):
        total = len(self.spans)
        cur = (self.idx + 1) if self.idx >= 0 else 0
        self.counter.setText("%d / %d" % (cur, total))


# =============================================================================
# 분석 탭 패널 (표 + 상세 텍스트)
# =============================================================================
def _numkey(s):
    m = re.match(r"(\d+)(.*)", unicode(s))
    return (int(m.group(1)), m.group(2)) if m else (0, unicode(s))


class NumComparator(Comparator):
    """'#' 컬럼을 숫자 기준으로 정렬(2-2 같은 값도 안전하게)."""
    def compare(self, a, b):
        ka, kb = _numkey(a), _numkey(b)
        if ka[0] != kb[0]:
            return -1 if ka[0] < kb[0] else 1
        if ka[1] < kb[1]:
            return -1
        if ka[1] > kb[1]:
            return 1
        return 0


class RepeaterAction(AbstractAction):
    def __init__(self, main, get_msg):
        self.main = main
        self.get_msg = get_msg
    def actionPerformed(self, ev):
        self.main._send_repeater(self.get_msg())


def install_repeater_key(component, main, get_msg):
    im = component.getInputMap(JComponent.WHEN_FOCUSED)
    im.put(KeyStroke.getKeyStroke(KeyEvent.VK_R, InputEvent.CTRL_DOWN_MASK),
           "khSendRepeater")
    component.getActionMap().put("khSendRepeater", RepeaterAction(main, get_msg))


class RepeaterPopup(MouseAdapter):
    def __init__(self, main, get_msg, table=None):
        self.main = main
        self.get_msg = get_msg
        self.table = table
    def mousePressed(self, ev):
        self._maybe(ev)
    def mouseReleased(self, ev):
        self._maybe(ev)
    def _maybe(self, ev):
        if not ev.isPopupTrigger():
            return
        if self.table is not None:
            r = self.table.rowAtPoint(ev.getPoint())
            if r >= 0:
                self.table.setRowSelectionInterval(r, r)
        msg = self.get_msg()
        if msg is None:
            return
        menu = JPopupMenu()
        menu.add(JMenuItem("Send to Repeater",
                           actionPerformed=lambda e: self.main._send_repeater(msg)))
        menu.show(ev.getComponent(), ev.getX(), ev.getY())


def install_repeater(component, main, get_msg, table=None):
    install_repeater_key(component, main, get_msg)
    component.addMouseListener(RepeaterPopup(main, get_msg, table))


# =============================================================================
# 메인
# =============================================================================
class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._cb = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("KeywordHunter Light")

        self.results = []
        self.realtime = True   # 실시간 기본 ON
        self.lang = "ko"
        self._filtered = []
        self._display_rows = []
        self._collapse = False
        self._expanded = set()
        self._status = ("", None)
        self._collapse_bg = None
        self._kw_armed_row = -1     # 직전에 '단독 선택'돼 있던 행
        self._kw_suppress = False
        self._kw_loading = False

        self._build_ui()
        self._load_settings()
        self._apply_language()
        self._refresh_domains(None)

        callbacks.customizeUiComponent(self.root)
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        print("KeywordHunter Light loaded")

    # ---- ITab ----
    def getTabCaption(self):
        return "KeywordHunter Light"

    def getUiComponent(self):
        return self.root

    def _t(self, key):
        return LANG[self.lang].get(key, key)

    # =====================================================================
    # UI
    # =====================================================================
    def _build_ui(self):
        self.root = JPanel(BorderLayout())

        top = JPanel(BorderLayout())
        west = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        self.lbl_lang = JLabel()
        self.lang_box = JComboBox([u"한국어", u"English"])
        self.lang_box.addActionListener(LangListener(self))
        west.add(self.lbl_lang)
        west.add(self.lang_box)
        top.add(west, BorderLayout.WEST)
        self.lbl_version = JLabel()
        self.lbl_version.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 10))
        top.add(self.lbl_version, BorderLayout.EAST)
        self.root.add(top, BorderLayout.NORTH)

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        split.setResizeWeight(0.33)
        split.setLeftComponent(self._build_left())
        split.setRightComponent(self._build_right())
        self.root.add(split, BorderLayout.CENTER)

    def _build_left(self):
        left = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        left.setResizeWeight(0.5)
        left.setTopComponent(self._build_filter_panel())
        left.setBottomComponent(self._build_keyword_panel())
        return left

    def _build_filter_panel(self):
        p = JPanel(BorderLayout())
        self.filter_border = BorderFactory.createTitledBorder("")
        p.setBorder(self.filter_border)

        north = JPanel(GridLayout(0, 1, 2, 2))
        self.chk_scope = JCheckBox("", False)
        north.add(self.chk_scope)

        fr = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        self.lbl_find = JLabel()
        self.find_field = JTextField(10)
        self.find_field.getDocument().addDocumentListener(FindListener(self))
        self.btn_refresh = JButton(actionPerformed=self._refresh_domains)
        self.btn_toggle = JButton(actionPerformed=lambda e: self._toggle_all_domains())
        for c in (self.lbl_find, self.find_field, self.btn_refresh, self.btn_toggle):
            fr.add(c)
        north.add(fr)
        p.add(north, BorderLayout.NORTH)

        self.dom_model = DomainTableModel(["", ""], 0)
        self.dom_table = JTable(self.dom_model)
        self.dom_table.getColumnModel().getColumn(0).setMaxWidth(24)
        self.dom_sorter = TableRowSorter(self.dom_model)
        self.dom_table.setRowSorter(self.dom_sorter)
        p.add(JScrollPane(self.dom_table), BorderLayout.CENTER)

        south = JPanel(GridLayout(0, 1, 2, 2))
        extp = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        self.lbl_ext = JLabel()
        self.ext_field = JTextField("jpg, png, woff, otf, avi, mp4, css", 24)
        extp.add(self.lbl_ext)
        extp.add(self.ext_field)
        south.add(extp)

        sz = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        self.lbl_size = JLabel()
        self.max_kb = JTextField("2000000", 8)
        sz.add(self.lbl_size)
        sz.add(self.max_kb)
        south.add(sz)

        rg = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        self.lbl_range = JLabel()
        self.search_in = JComboBox()
        self.chk_headers = JCheckBox("", False)
        rg.add(self.lbl_range)
        rg.add(self.search_in)
        rg.add(self.chk_headers)
        south.add(rg)
        p.add(south, BorderLayout.SOUTH)
        return p

    def _build_keyword_panel(self):
        p = JPanel(BorderLayout())
        self.kw_border = BorderFactory.createTitledBorder("")
        p.setBorder(self.kw_border)

        self.kw_model = KeywordTableModel(["", "", "", "", "", ""], 0)
        self.kw_model.addTableModelListener(KwModelListener(self))
        self.kw_table = JTable(self.kw_model)
        self.kw_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        self._size_kw_columns()
        self.kw_table.getSelectionModel().setSelectionMode(
            ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self.kw_table.getSelectionModel().addListSelectionListener(
            KwSelListener(self))
        self.kw_table.addMouseListener(KwMouseListener(self))
        p.add(JScrollPane(self.kw_table), BorderLayout.CENTER)

        opts = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        self.chk_case = JCheckBox("", False)
        self.chk_kw_all = JCheckBox("", False)
        self.chk_kw_all.addActionListener(KwAllListener(self))
        self.chk_variants = JCheckBox("", True)
        opts.add(self.chk_kw_all)
        opts.add(self.chk_case)
        opts.add(self.chk_variants)

        # 입력칸은 가로로 꽉 차게, 버튼은 GridLayout 으로 균등 배치해
        # 패널 폭이 좁아져도 버튼이 다음 줄로 밀려 잘리지 않게 한다.
        inrow = JPanel(BorderLayout(4, 0))
        self.kw_input = JTextField(10)
        inrow.add(self.kw_input, BorderLayout.CENTER)

        self.btn_add = JButton(actionPerformed=self._add_keyword)
        self.btn_del = JButton(actionPerformed=self._del_keyword)
        self.btn_paste = JButton(actionPerformed=self._paste_keywords)
        self.btn_loadfile = JButton(actionPerformed=self._load_file)
        btnrow = JPanel(GridLayout(1, 4, 4, 0))
        for c in (self.btn_add, self.btn_del, self.btn_paste, self.btn_loadfile):
            btnrow.add(c)

        row2 = JPanel(BorderLayout(4, 0))
        self.preset_box = JComboBox(list(PRESETS.keys()))
        row2.add(self.preset_box, BorderLayout.CENTER)
        self.btn_preset = JButton(actionPerformed=self._load_preset)
        self.btn_kw_help = JButton(
            u"❓", actionPerformed=lambda e: self._show_help("keyword_regex"))
        self.btn_kw_help.setToolTipText("Help")
        pr = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        pr.add(self.btn_preset)
        pr.add(self.btn_kw_help)
        row2.add(pr, BorderLayout.EAST)

        south = JPanel(GridLayout(0, 1, 0, 2))
        south.add(opts)
        south.add(inrow)
        south.add(btnrow)
        south.add(row2)
        p.add(south, BorderLayout.SOUTH)
        return p

    def _build_right(self):
        self.right_tabs = JTabbedPane()
        self.right_tabs.addTab("", self._build_search_panel())
        return self.right_tabs

    def _build_search_panel(self):
        right = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        right.setResizeWeight(0.4)

        top = JPanel(BorderLayout())
        toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        self.btn_scan = JButton(actionPerformed=self._scan_history)
        self.rt_btn = JButton(actionPerformed=self._toggle_realtime)
        self.btn_csv = JButton(actionPerformed=self._export_csv)
        self.btn_clear = JButton(actionPerformed=self._clear)
        self.btn_collapse = JButton(actionPerformed=self._toggle_collapse)
        for b in (self.btn_scan, self.rt_btn, self.btn_csv,
                  self.btn_clear, self.btn_collapse):
            toolbar.add(b)
        self.progress = JProgressBar()
        self.progress.setStringPainted(True)
        toolbar.add(self.progress)
        self.status = JLabel(" ")
        toolbar.add(self.status)

        bar = JPanel(BorderLayout())
        bar.add(toolbar, BorderLayout.WEST)
        self.btn_help = JButton(u"❓", actionPerformed=lambda e: self._show_help("search"))
        self.btn_help.setToolTipText("Help")
        bar.add(self.btn_help, BorderLayout.EAST)
        top.add(bar, BorderLayout.NORTH)

        self.res_model = ReadOnlyTableModel(["#", "Host", "URL", "", "", "", ""], 0)
        self.res_table = JTable(self.res_model)
        self.res_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        self._row_renderer = RowRenderer(self)
        self._size_res_columns()
        self._res_sorter = TableRowSorter(self.res_model)
        self._res_sorter.setComparator(0, NumComparator())
        self.res_table.setRowSorter(self._res_sorter)
        self.res_table.getSelectionModel().setSelectionMode(
            ListSelectionModel.SINGLE_SELECTION)
        self.res_table.getSelectionModel().addListSelectionListener(
            ResSelListener(self))
        self.res_table.addMouseListener(ResMouseListener(self))
        install_repeater(self.res_table, self, self._selected_result_msg, self.res_table)
        self._cur_search_msg = None
        top.add(JScrollPane(self.res_table), BorderLayout.CENTER)
        right.setTopComponent(top)

        viewers = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        viewers.setResizeWeight(0.5)
        self.req_view = SearchViewer()
        self.resp_view = SearchViewer()
        self.req_view.enable_repeater(self, lambda: self._cur_search_msg)
        self.resp_view.enable_repeater(self, lambda: self._cur_search_msg)
        viewers.setLeftComponent(self.req_view)
        viewers.setRightComponent(self.resp_view)
        right.setBottomComponent(viewers)
        return right

    def _selected_result_msg(self):
        vr = self.res_table.getSelectedRow()
        if vr < 0:
            return None
        try:
            mr = self.res_table.convertRowIndexToModel(vr)
        except Exception:
            mr = vr
        if 0 <= mr < len(self._display_rows):
            return self._display_rows[mr]["res"].msg
        return None

    def _send_repeater(self, msg):
        if msg is None:
            return
        try:
            svc = msg.getHttpService()
            self._cb.sendToRepeater(svc.getHost(), svc.getPort(),
                                    svc.getProtocol() == "https",
                                    msg.getRequest(), "KeywordHunter")
        except Exception:
            pass

    # =====================================================================
    # 컬럼 크기 (드래그 리사이즈 가능, 기본 폭은 이름이 잘리지 않게)
    # =====================================================================
    def _size_kw_columns(self):
        cm = self.kw_table.getColumnModel()
        # ✓ / 키워드 / 정규식 / 패킷 / 매칭 / 프리셋
        widths = [30, 180, 60, 55, 55, 90]
        for i, w in enumerate(widths):
            col = cm.getColumn(i)
            col.setMinWidth(24)
            col.setPreferredWidth(w)

    def _size_res_columns(self):
        cm = self.res_table.getColumnModel()
        # # / Host / URL / 키워드 / 매칭 / Length / Time
        widths = [50, 160, 330, 110, 55, 70, 150]
        for i, w in enumerate(widths):
            col = cm.getColumn(i)
            col.setMinWidth(20)
            col.setPreferredWidth(w)
            col.setCellRenderer(self._row_renderer)

    # =====================================================================
    # 언어 적용
    # =====================================================================
    def _apply_language(self):
        t = self._t
        self.lbl_lang.setText(t("lang"))
        self.lbl_version.setText(t("version"))
        self.chk_headers.setText(t("headers"))
        self.filter_border.setTitle(t("filter"))
        self.chk_scope.setText(t("scope"))
        self.lbl_find.setText(t("find"))
        self.btn_refresh.setText(t("refresh"))
        self.btn_toggle.setText(t("toggle"))
        self.lbl_ext.setText(t("ext"))
        self.lbl_size.setText(t("maxsize"))
        self.lbl_range.setText(t("range"))
        self.kw_border.setTitle(t("kw"))
        self.chk_case.setText(t("case"))
        self.chk_kw_all.setText(t("kw_all"))
        self.chk_variants.setText(t("variants"))
        self.btn_add.setText(t("add"))
        self.btn_del.setText(t("del"))
        self.btn_paste.setText(t("paste"))
        self.btn_loadfile.setText(t("loadfile"))
        self.btn_preset.setText(t("preset"))
        self.btn_scan.setText(t("scan"))
        self.rt_btn.setText(t("rt_on") if self.realtime else t("rt_off"))
        self.btn_csv.setText(t("csv"))
        self.btn_collapse.setText(t("collapse"))
        self.btn_clear.setText(t("clear"))
        self.req_view.set_labels(t("vsearch"), t("vauto"), t("wrap"))
        self.resp_view.set_labels(t("vsearch"), t("vauto"), t("wrap"))
        self._render_status()

        for i, key in enumerate(("tab_search",)):
            self.right_tabs.setTitleAt(i, t(key))
        self.btn_kw_help.setText(u"❓")

        idx = max(0, self.search_in.getSelectedIndex())
        self.search_in.removeAllItems()
        for k in ("range_both", "range_req", "range_resp"):
            self.search_in.addItem(t(k))
        self.search_in.setSelectedIndex(idx)

        self.dom_model.setColumnIdentifiers(["", t("dom_col")])
        self.dom_table.getColumnModel().getColumn(0).setMaxWidth(24)
        self.kw_model.setColumnIdentifiers(
            ["", t("kw"), t("col_regex"), t("col_pkt"), t("col_match"),
             t("col_preset")])
        self._size_kw_columns()
        self.res_model.setColumnIdentifiers(
            ["#", "Host", t("res_url"), t("kw"), t("res_match"),
             t("res_len"), t("res_time")])
        self._size_res_columns()
        # setColumnIdentifiers 가 정렬 comparator 를 초기화하므로 다시 지정
        self._res_sorter.setComparator(0, NumComparator())
        self.root.revalidate()
        self.root.repaint()

    def _on_lang_change(self):
        self.lang = "ko" if self.lang_box.getSelectedIndex() == 0 else "en"
        self._apply_language()

    # =====================================================================
    # 도메인
    # =====================================================================
    def _refresh_domains(self, ev):
        existing = {}
        for r in range(self.dom_model.getRowCount()):
            host = unicode(self.dom_model.getValueAt(r, 1))
            existing[host] = bool(self.dom_model.getValueAt(r, 0))
        hosts = set(existing.keys())
        for msg in self._cb.getProxyHistory():
            try:
                hosts.add(msg.getHttpService().getHost())
            except Exception:
                pass
        self.dom_model.setRowCount(0)
        for host in sorted(hosts):
            self.dom_model.addRow([Boolean(existing.get(host, False)), host])

    def _toggle_all_domains(self):
        rows = range(self.dom_table.getRowCount())
        all_checked = True
        for vr in rows:
            mr = self.dom_table.convertRowIndexToModel(vr)
            if not self.dom_model.getValueAt(mr, 0):
                all_checked = False
                break
        target = not all_checked
        for vr in rows:
            mr = self.dom_table.convertRowIndexToModel(vr)
            self.dom_model.setValueAt(Boolean(target), mr, 0)

    def _apply_find(self):
        txt = self.find_field.getText()
        if not txt:
            self.dom_sorter.setRowFilter(None)
        else:
            self.dom_sorter.setRowFilter(
                RowFilter.regexFilter("(?i)" + Pattern.quote(txt), 1))

    def _checked_domains(self):
        out = set()
        for r in range(self.dom_model.getRowCount()):
            if self.dom_model.getValueAt(r, 0):
                out.add(unicode(self.dom_model.getValueAt(r, 1)))
        return out

    def _ext_set(self):
        out = set()
        for p in self.ext_field.getText().split(","):
            p = p.strip().lstrip(".").lower()
            if p:
                out.add(p)
        return out

    # =====================================================================
    # 키워드
    # =====================================================================
    def _existing_keywords(self):
        return set(unicode(self.kw_model.getValueAt(r, 1))
                   for r in range(self.kw_model.getRowCount()))

    def _add_kw_row(self, kw, regex=False, preset=u""):
        self.kw_model.addRow(
            [Boolean(True), kw, Boolean(regex), u"0", u"0", preset])

    def _add_keyword(self, ev):
        txt = self.kw_input.getText().strip()
        if txt and txt not in self._existing_keywords():
            self._add_kw_row(txt)
            self.kw_input.setText("")

    def _del_keyword(self, ev):
        # 선택(하이라이트)된 행 + 체크박스가 켜진 행을 모두 삭제
        targets = set(self.kw_table.getSelectedRows())
        for r in range(self.kw_model.getRowCount()):
            if self.kw_model.getValueAt(r, 0):
                targets.add(r)
        for r in sorted(targets, reverse=True):
            self.kw_model.removeRow(r)

    def _bulk_add(self, lines, preset=u""):
        existing = self._existing_keywords()
        n = 0
        for line in lines:
            kw = line.strip()
            if kw and kw not in existing:
                self._add_kw_row(kw, preset=preset)
                existing.add(kw)
                n += 1
        return n

    def _paste_keywords(self, ev):
        try:
            clip = Toolkit.getDefaultToolkit().getSystemClipboard()
            data = clip.getData(DataFlavor.stringFlavor)
            n = self._bulk_add(unicode(data).splitlines())
            self._set_status("s_paste", n)
        except Exception as e:
            self.status.setText(u"paste error: %s" % e)

    def _load_file(self, ev):
        chooser = JFileChooser()
        if chooser.showOpenDialog(self.root) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        raw = open(path, "rb").read()
        try:
            text = raw.decode("utf-8")
        except Exception:
            text = unicode(JString(raw, "MS949"))
        n = self._bulk_add(text.splitlines())
        self._set_status("s_file", n)

    def _load_preset(self, ev):
        name = self.preset_box.getSelectedItem()
        self._bulk_add(PRESETS.get(name, []), preset=unicode(name))

    def _toggle_all_keywords(self):
        val = self.chk_kw_all.isSelected()
        for r in range(self.kw_model.getRowCount()):
            self.kw_model.setValueAt(Boolean(val), r, 0)

    def _enabled_keywords(self):
        out = []
        for r in range(self.kw_model.getRowCount()):
            if self.kw_model.getValueAt(r, 0):
                kw = unicode(self.kw_model.getValueAt(r, 1)).strip()
                if kw:
                    out.append((kw, bool(self.kw_model.getValueAt(r, 2))))
        return out

    # =====================================================================
    # 필터
    # =====================================================================
    def _passes_filter(self, msg):
        try:
            svc = msg.getHttpService()
            host = svc.getHost()
            analyzed = self._helpers.analyzeRequest(msg)
            url = analyzed.getUrl().toString()
        except Exception:
            return None
        if self.chk_scope.isSelected():
            try:
                if not self._cb.isInScope(analyzed.getUrl()):
                    return None
            except Exception:
                pass
        checked = self._checked_domains()
        if checked and host not in checked:
            return None
        exts = self._ext_set()
        if exts and url_ext(url) in exts:   # 제외할 확장자
            return None
        resp = msg.getResponse()
        if resp is not None:
            try:
                if len(resp) > int(self.max_kb.getText()):
                    return None
            except Exception:
                pass
        return (host, url)

    # =====================================================================
    # 스캔
    # =====================================================================
    def _scan_history(self, ev):
        kws = self._enabled_keywords()
        if not kws:
            self._set_status("s_nokw")
            return
        history = self._cb.getProxyHistory()

        def work():
            total = len(history)
            SwingUtilities.invokeLater(lambda: self.progress.setMaximum(total))
            self.results = []
            for i, msg in enumerate(history):
                self._scan_one(msg, kws, u"")   # history: 실제 캡처 시각 불명 -> 비움
                if i % 20 == 0:
                    v = i
                    SwingUtilities.invokeLater(lambda v=v: self.progress.setValue(v))
            SwingUtilities.invokeLater(self._refresh_all)
            SwingUtilities.invokeLater(lambda: self.progress.setValue(total))
            SwingUtilities.invokeLater(
                lambda: self._set_status("s_done", len(self.results)))

        Thread(RunnableWrap(work)).start()

    def _scan_one(self, msg, kws, default_time, mark_new=False):
        meta = self._passes_filter(msg)
        if meta is None:
            return
        host, url = meta
        tstr = reflect_time(msg) or default_time   # 프록시 통과 시각 우선, 없으면 폴백
        mode = self.search_in.getSelectedIndex()
        case = self.chk_case.isSelected()
        variants = self.chk_variants.isSelected()
        resp_raw = msg.getResponse()
        length = len(resp_raw) if resp_raw else 0
        req_text = decode_bytes(msg.getRequest()) if mode in (0, 1) else u""
        resp_text = decode_bytes(resp_raw) if mode in (0, 2) else u""
        inc_hdr = self.chk_headers.isSelected()

        def spans_for(text, kw, is_rx):
            if not text:
                return []
            if inc_hdr:
                return find_offsets(text, kw, is_rx, case, variants)
            bs = body_start(text)
            return [(a + bs, b + bs)
                    for (a, b) in find_offsets(text[bs:], kw, is_rx, case, variants)]

        for (kw, is_rx) in kws:
            rq = spans_for(req_text, kw, is_rx)
            rs = spans_for(resp_text, kw, is_rx)
            if rq or rs:
                self.results.append(
                    Result(msg, host, url, kw, is_rx, length, tstr,
                           req_text, resp_text, rq, rs, seen=(not mark_new)))


    def _show_help(self, which):
        title, body = HELP[self.lang].get(which, (u"Help", u""))
        area = JTextArea(body)
        area.setEditable(False)
        area.setLineWrap(True)
        area.setWrapStyleWord(True)
        area.setColumns(52)
        area.setRows(20)
        area.setCaretPosition(0)
        JOptionPane.showMessageDialog(
            self.root, JScrollPane(area), title, JOptionPane.INFORMATION_MESSAGE)

    # ---- 실시간 ----
    def _toggle_realtime(self, ev):
        self.realtime = not self.realtime
        self.rt_btn.setText(self._t("rt_on") if self.realtime else self._t("rt_off"))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest or toolFlag != TOOL_PROXY:
            return
        # 도메인 선택 전에는 실시간 검사 안 함 (전체 도메인 자동 스캔 방지)
        if not self._checked_domains():
            return
        # 키워드 검색 탭 실시간
        if self.realtime:
            kws = self._enabled_keywords()
            if kws:
                before = len(self.results)
                self._scan_one(messageInfo, kws, now_str(), mark_new=True)
                if len(self.results) != before:
                    SwingUtilities.invokeLater(self._on_search_realtime_added)

    def _on_search_realtime_added(self):
        self._refresh_all()
        self._mark_tab_new(0)   # 키워드 검색 탭

    def _mark_tab_new(self, idx):
        if idx >= 0 and self.right_tabs.getSelectedIndex() != idx:
            self.right_tabs.setBackgroundAt(idx, NEW_TAB_COLOR)


    # =====================================================================
    # 결과 표시
    # =====================================================================
    def _refresh_all(self):
        self._update_keyword_counts()
        self._filter_results_by_keyword()

    def _update_keyword_counts(self):
        packets, matches = {}, {}
        for res in self.results:
            packets[res.keyword] = packets.get(res.keyword, 0) + 1
            matches[res.keyword] = matches.get(res.keyword, 0) + res.count
        for r in range(self.kw_model.getRowCount()):
            kw = unicode(self.kw_model.getValueAt(r, 1))
            self.kw_model.setValueAt(unicode(packets.get(kw, 0)), r, 3)
            self.kw_model.setValueAt(unicode(matches.get(kw, 0)), r, 4)

    def _filter_results_by_keyword(self):
        rows = self.kw_table.getSelectedRows()
        sel_kws = set(unicode(self.kw_model.getValueAt(r, 1)) for r in rows)
        self._filtered = [res for res in self.results
                          if (not sel_kws) or res.keyword in sel_kws]
        self._rebuild_result_rows()

    def _add_disp(self, label, res, has_exp, expanded, gray, child):
        if has_exp:
            host = (u"▼ " if expanded else u"▶ ") + res.host
        elif child:
            host = u"  " + res.host
        else:
            host = res.host
        url = (u"  " + res.url) if child else res.url
        kw = (u"  " + res.keyword) if child else res.keyword
        self._display_rows.append(
            {"res": res, "gray": gray, "has_exp": has_exp, "url": res.url})
        self.res_model.addRow([label, host, url, kw, unicode(res.count),
                               unicode(res.length), res.time])

    def _rebuild_result_rows(self):
        self.res_model.setRowCount(0)
        self._display_rows = []
        counter = 0
        if not self._collapse:
            for res in self._filtered:
                counter += 1
                self._add_disp(unicode(counter), res, False, False, False, False)
        else:
            groups = OrderedDict()
            for res in self._filtered:
                groups.setdefault(res.url, []).append(res)
            for url, grp in groups.items():
                if len(grp) == 1 or len(set(r.length for r in grp)) == 1:
                    # 단일이거나 length까지 동일 = 완전 중복 -> 하나로 생략
                    counter += 1
                    self._add_disp(unicode(counter), grp[0], False, False, False, False)
                else:
                    # length가 다른 중복 -> 대표행 회색 + 펼침 아이콘
                    counter += 1
                    parent = counter
                    expanded = url in self._expanded
                    self._add_disp(unicode(parent), grp[0], True, expanded, True, False)
                    if expanded:
                        for ci, res in enumerate(grp[1:]):
                            label = u"%d-%d" % (parent, ci + 2)
                            self._add_disp(label, res, False, False, True, True)

    def _toggle_collapse(self, ev):
        self._collapse = not self._collapse
        b = self.btn_collapse
        if self._collapse:
            if self._collapse_bg is None:
                self._collapse_bg = b.getBackground()
            b.setOpaque(True)
            b.setContentAreaFilled(True)
            b.setBackground(Color(110, 140, 185))   # 활성: 진한 색
        else:
            if self._collapse_bg is not None:
                b.setBackground(self._collapse_bg)
        self._rebuild_result_rows()

    def _toggle_expand(self, row):
        if row < 0 or row >= len(self._display_rows):
            return
        ent = self._display_rows[row]
        if not ent["has_exp"]:
            return
        url = ent["url"]
        if url in self._expanded:
            self._expanded.discard(url)
        else:
            self._expanded.add(url)
        self._rebuild_result_rows()

    def _show_selected_result(self):
        vr = self.res_table.getSelectedRow()
        if vr < 0:
            return
        try:
            r = self.res_table.convertRowIndexToModel(vr)
        except Exception:
            r = vr
        if r < 0 or r >= len(self._display_rows):
            return
        res = self._display_rows[r]["res"]
        self._cur_search_msg = res.msg
        if not res.seen:
            res.seen = True   # 확인함 -> 하이라이트 해제
            self.res_table.repaint()
        self.req_view.load(res.req_text, res.keyword, res.is_regex,
                           self.chk_case.isSelected(), self.chk_variants.isSelected())
        self.resp_view.load(res.resp_text, res.keyword, res.is_regex,
                            self.chk_case.isSelected(), self.chk_variants.isSelected())

    # ---- 컨텍스트 메뉴 ----
    def createMenuItems(self, invocation):
        msg = self._selected_result_msg()
        if msg is None:
            return None
        return [JMenuItem("Send to Repeater",
                          actionPerformed=lambda ev: self._send_repeater(msg))]

    # ---- CSV ----
    def _export_csv(self, ev):
        chooser = JFileChooser()
        if chooser.showSaveDialog(self.root) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        if not path.lower().endswith(".csv"):
            path += ".csv"
        f = open(path, "wb")
        try:
            w = csv.writer(f)
            w.writerow(["host", "url", "keyword", "matches", "length", "time"])
            for res in self.results:
                w.writerow([res.host.encode("utf-8"), res.url.encode("utf-8"),
                            res.keyword.encode("utf-8"), res.count, res.length,
                            res.time.encode("utf-8")])
        finally:
            f.close()
        self._set_status("s_csv", path)

    def _clear(self, ev):
        self.results = []
        self._filtered = []
        self._display_rows = []
        self._expanded = set()
        self.res_model.setRowCount(0)
        self.req_view.load(u"", u"", False, False, True)
        self.resp_view.load(u"", u"", False, False, True)
        self._update_keyword_counts()
        self._set_status("s_clear")

    # ---- 상태표시(언어 전환 시에도 갱신) ----
    def _set_status(self, key, arg=None):
        self._status = (key, arg)
        self._render_status()

    def _render_status(self):
        key, arg = self._status
        if not key:
            self.status.setText(" ")
            return
        txt = self._t(key)
        if arg is None:
            self.status.setText(txt)
        else:
            try:
                self.status.setText(txt % arg)
            except Exception:
                self.status.setText(txt + unicode(arg))

    # ---- 설정 ----
    def _on_kw_model_change(self, ev):
        # 키워드(체크/단어/정규식/프리셋)가 바뀜면 세션에 저장한다.
        # 로드 중이거나 구조 변경(헤더), 또는 패킷/매칭 카운트(열 3,4) 변경은 제외한다.
        if getattr(self, "_kw_loading", False):
            return
        if ev.getFirstRow() < 0:
            return
        col = ev.getColumn()
        if col == -1 or col in (0, 1, 2, 5):
            self._save_settings()

    def _save_settings(self):
        rows = []
        for r in range(self.kw_model.getRowCount()):
            rows.append(u"\t".join([
                u"1" if self.kw_model.getValueAt(r, 0) else u"0",
                unicode(self.kw_model.getValueAt(r, 1)),
                u"1" if self.kw_model.getValueAt(r, 2) else u"0",
                unicode(self.kw_model.getValueAt(r, 5) or u"")]))
        self._cb.saveExtensionSetting("keywords", u"\n".join(rows).encode("utf-8"))

    def _load_settings(self):
        data = self._cb.loadExtensionSetting("keywords")
        if not data:
            return
        try:
            data = data.decode("utf-8")
        except Exception:
            pass
        self._kw_loading = True
        try:
            for line in data.splitlines():
                parts = line.split(u"\t")
                if len(parts) >= 3:
                    preset = parts[3] if len(parts) >= 4 else u""
                    self.kw_model.addRow([Boolean(parts[0] == u"1"), parts[1],
                                          Boolean(parts[2] == u"1"), u"0", u"0", preset])
        finally:
            self._kw_loading = False


# =============================================================================
# 리스너 / 유틸
# =============================================================================
class RunnableWrap(Runnable):
    def __init__(self, fn):
        self.fn = fn
    def run(self):
        self.fn()


class LangListener(ActionListener):
    def __init__(self, outer):
        self.outer = outer
    def actionPerformed(self, ev):
        self.outer._on_lang_change()


class KwSelListener(ListSelectionListener):
    def __init__(self, outer):
        self.outer = outer
    def valueChanged(self, ev):
        if not ev.getValueIsAdjusting():
            self.outer._filter_results_by_keyword()


class KwMouseListener(MouseAdapter):
    """일반 클릭=단일 선택, 드래그/Ctrl=다중, 단독 선택된 행 재클릭=해제.

    Swing 기본 선택 처리가 이 리스너보다 먼저 실행되므로, '현재' 선택이 아니라
    직전 인터랙션에서 저장해 둔 _kw_armed_row(직전 단독 선택 행)로 재클릭을 판별한다.
    """
    def __init__(self, outer):
        self.outer = outer

    def mousePressed(self, ev):
        if ev.isControlDown() or ev.isShiftDown():
            self.outer._kw_suppress = False
            return
        tbl = self.outer.kw_table
        row = tbl.rowAtPoint(ev.getPoint())
        if row >= 0 and row == self.outer._kw_armed_row:
            # 직전에 이 행만 선택돼 있었는데 또 눌렀다 -> 해제
            self.outer._kw_suppress = True
            SwingUtilities.invokeLater(tbl.clearSelection)
        else:
            self.outer._kw_suppress = False

    def mouseReleased(self, ev):
        tbl = self.outer.kw_table
        if self.outer._kw_suppress:
            self.outer._kw_armed_row = -1
            self.outer._kw_suppress = False
            return
        self.outer._kw_armed_row = (
            tbl.getSelectedRow() if tbl.getSelectedRowCount() == 1 else -1)


class ResSelListener(ListSelectionListener):
    def __init__(self, outer):
        self.outer = outer
    def valueChanged(self, ev):
        if not ev.getValueIsAdjusting():
            self.outer._show_selected_result()


class ResMouseListener(MouseAdapter):
    def __init__(self, outer):
        self.outer = outer
    def mousePressed(self, ev):
        tbl = self.outer.res_table
        vrow = tbl.rowAtPoint(ev.getPoint())
        col = tbl.columnAtPoint(ev.getPoint())
        if vrow < 0:
            return
        try:
            row = tbl.convertRowIndexToModel(vrow)
        except Exception:
            row = vrow
        ent = self.outer._display_rows[row] if row < len(self.outer._display_rows) else None
        # Host 컬럼(펼침 아이콘)을 누르면 접기/펼치기 토글
        if ent and ent["has_exp"] and col == 1:
            SwingUtilities.invokeLater(lambda: self.outer._toggle_expand(row))


class RowRenderer(DefaultTableCellRenderer):
    GRAY = Color(235, 235, 235)

    def __init__(self, outer):
        self.outer = outer

    def getTableCellRendererComponent(self, table, value, isSelected,
                                      hasFocus, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        gray = False
        unseen = False
        try:
            mrow = table.convertRowIndexToModel(row)
        except Exception:
            mrow = row
        try:
            ent = self.outer._display_rows[mrow]
            gray = ent["gray"]
            unseen = (not ent["res"].seen)
        except Exception:
            pass
        if not isSelected:
            if unseen:
                comp.setBackground(NEW_ROW_COLOR)   # 미확인 새 행 우선
            elif gray:
                comp.setBackground(self.GRAY)
            else:
                comp.setBackground(table.getBackground())
        return comp


class FindListener(DocumentListener):
    def __init__(self, outer):
        self.outer = outer
    def insertUpdate(self, ev):
        self.outer._apply_find()
    def removeUpdate(self, ev):
        self.outer._apply_find()
    def changedUpdate(self, ev):
        self.outer._apply_find()


class SVFindListener(DocumentListener):
    def __init__(self, viewer):
        self.viewer = viewer
    def insertUpdate(self, ev):
        self.viewer._on_field_change()
    def removeUpdate(self, ev):
        self.viewer._on_field_change()
    def changedUpdate(self, ev):
        self.viewer._on_field_change()


class TabListener(ChangeListener):
    def __init__(self, viewer):
        self.viewer = viewer
    def stateChanged(self, ev):
        self.viewer._on_tab_change()


class WrapListener(ActionListener):
    def __init__(self, viewer):
        self.viewer = viewer
    def actionPerformed(self, ev):
        self.viewer._on_wrap_change()


class KwModelListener(TableModelListener):
    def __init__(self, outer):
        self.outer = outer

    def tableChanged(self, ev):
        self.outer._on_kw_model_change(ev)


class KwAllListener(ActionListener):
    def __init__(self, outer):
        self.outer = outer
    def actionPerformed(self, ev):
        self.outer._toggle_all_keywords()


class NlListener(ActionListener):
    def __init__(self, viewer):
        self.viewer = viewer
    def actionPerformed(self, ev):
        self.viewer._on_nl_change()
