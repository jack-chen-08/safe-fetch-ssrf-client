"""【反面样例，仅供 check_no_bypass.py 自证使用，禁止在生产代码中参照】

这个文件故意用四种典型方式绕过 safe_fetch。扫描脚本必须全部抓到，
否则说明闸门本身失效。它位于 tests/fixtures/，不属于 intel/ 扫描范围。
"""

import urllib.request  # 违规 1：直接 import urllib.request

import requests  # 违规 2：第三方请求库


def fetch_with_requests(url):
    return requests.get(url, timeout=5)  # 违规 3：调用 requests.get


def fetch_with_urlopen(url):
    return urllib.request.urlopen(url)  # 违规 4：调用 urlopen
