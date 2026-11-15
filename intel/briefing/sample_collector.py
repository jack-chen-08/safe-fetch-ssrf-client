"""情报采集演示：唯一出口是 intel.safe_fetch.safe_fetch。

本模块故意不做任何 socket / 请求库调用 —— scripts/check_no_bypass.py 会检查这一点。
新增采集器时照此模式写：定义 Source、调 safe_fetch、只解析 FetchResult.body。
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass

from ..safe_fetch import FetchResult, SafeFetchConfig, Source, safe_fetch

#: 一个来源 = 一个白名单。不要把不同域混进同一个 Source。
EXAMPLE_FEED = Source(
    name="example-rss",
    allowed_hosts=("example.com", "feeds.example.com"),
)


@dataclass(frozen=True)
class BriefItem:
    title: str
    link: str
    published: str
    source: str


def collect_rss(url: str, source: Source = EXAMPLE_FEED, config: SafeFetchConfig | None = None) -> list[BriefItem]:
    """抓取并解析 RSS/Atom。所有 SSRF / 体积 / 类型判断都由 safe_fetch 负责。"""
    result: FetchResult = safe_fetch(url, source, config)
    return parse_feed(result.body, source.name)


def parse_feed(body: bytes, source_name: str) -> list[BriefItem]:
    """解析 RSS 2.0 与 Atom 两种根元素；解析失败返回空列表而非抛出。"""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []

    items: list[BriefItem] = []
    # RSS 2.0: <rss><channel><item>
    for item in root.iter("item"):
        items.append(
            BriefItem(
                title=(item.findtext("title") or "").strip(),
                link=(item.findtext("link") or "").strip(),
                published=(item.findtext("pubDate") or "").strip(),
                source=source_name,
            )
        )
    if items:
        return items

    # Atom: <feed><entry>, 带命名空间
    ns = "{http://www.w3.org/2005/Atom}"
    for entry in root.iter(f"{ns}entry"):
        link_el = entry.find(f"{ns}link")
        items.append(
            BriefItem(
                title=(entry.findtext(f"{ns}title") or "").strip(),
                link=(link_el.get("href") if link_el is not None else "") or "",
                published=(entry.findtext(f"{ns}published") or entry.findtext(f"{ns}updated") or "").strip(),
                source=source_name,
            )
        )
    return items
