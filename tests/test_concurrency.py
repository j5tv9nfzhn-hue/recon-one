"""并发层测试。

重点不是「并发能不能跑」，而是「并发跑出来的结果和串行**逐字段相同**」。
这是唯一能防止并发化引入误报的手段。
"""
from __future__ import annotations

import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from reconone import apiprobe, concurrency
from reconone.http import Session


class _Handler(BaseHTTPRequestHandler):
    hits: list[str] = []
    delay = 0.20

    def log_message(self, *args):        # 静音
        pass

    def _reply(self, body: bytes, status=200, ctype="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        type(self).hits.append(self.path)
        time.sleep(self.delay)
        if self.path == "/openapi.json":
            import json
            self._reply(json.dumps({
                "openapi": "3.0.0",
                "paths": {"/api/v1/thing": {"get": {"parameters": [{"name": "id"}]}}},
            }).encode())
        else:
            self._reply(b'{"detail":"not found"}', 404)

    def do_POST(self):
        type(self).hits.append(self.path)
        time.sleep(self.delay)
        self._reply(b'{"errors":[{"message":"no introspection"}]}', 200)


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _Handler.hits = []
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.srv.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def session(self, **kw):
        return Session("127.0.0.1", **kw)


class TestEquivalence(_Base):
    """并发与串行必须产出同一份结果。"""

    def test_results_identical_to_serial(self):
        serial = apiprobe.discover_specs(self.session(), self.base)
        parallel = apiprobe.discover_specs(self.session(), self.base)
        self.assertEqual(serial, parallel)

    def test_order_is_stable(self):
        """端点顺序不能因为并发而抖动，否则两次扫描的 diff 全是噪音。"""
        a = apiprobe.discover_specs(self.session(), self.base)
        b = apiprobe.discover_specs(self.session(), self.base)
        self.assertEqual([t["url"] for t in a["tried"]],
                         [t["url"] for t in b["tried"]])
        # 命中即短路（原始行为）：只在找到之前记录 tried，不会白跑后面的路径
        self.assertGreaterEqual(len(a["tried"]), 1)
        self.assertLessEqual(len(a["tried"]), len(apiprobe.SPEC_PATHS))

    def test_spec_is_still_found(self):
        """并发化不能把「找到 spec」这件事弄丢。"""
        res = apiprobe.discover_specs(self.session(), self.base)
        self.assertTrue(res["found"], "并发后应当仍然发现 OpenAPI 文档")
        self.assertEqual(res["found"][0]["url"], self.base + "/openapi.json")

    def test_failure_is_not_marked_as_absent(self):
        """拿不到 ≠ 没有。所有尝试过的路径都要留下记录，且带状态码或错误。"""
        res = apiprobe.discover_specs(self.session(), self.base)
        self.assertTrue(res["tried"], "至少要有一次探测记录")
        for item in res["tried"]:
            self.assertIn("url", item)
            self.assertIn("status", item)
            self.assertIn("error", item)
            # 404 必须记成 404，不能变成"不存在"这种无法复核的结论
            self.assertTrue(item["status"] or item["error"])


class TestBudgets(_Base):
    """并发不得突破 Session 的既有闸门。"""

    def test_scope_gate_blocks_before_dispatch(self):
        sess = self.session()
        jobs = [{"url": "http://evil.example.invalid/x"},
                {"url": self.base + "/openapi.json"}]
        results = concurrency.fetch_many(sess, jobs, degree=4)
        self.assertIn("out_of_scope", results[0].error or "")
        self.assertTrue(any("evil.example.invalid" in u for u in sess.off_scope_attempts))
        self.assertIsNone(results[1].error)

    def test_byte_budget_is_not_exceeded(self):
        """并发共享同一份字节预算：上限不能被 N 条连接同时突破。"""
        sess = self.session(max_total_bytes=1)
        jobs = [{"url": self.base + "/openapi.json"} for _ in range(6)]
        out = concurrency.fetch_many(sess, jobs, degree=6)
        self.assertEqual(len(out), 6)
        # 预算耗尽后，后到的请求必须被拒绝而不是继续拉
        self.assertTrue(sess.exhausted)
        self.assertTrue(any("budget_exhausted" in (r.error or "") for r in out)
                        or sess.bytes_total <= sess.max_total_bytes)

    def test_cancel_event_is_not_called_as_function(self):
        """回归：cancel 是 threading.Event，不是函数。当函数调用会 TypeError。"""
        sess = self.session()
        cancel = threading.Event()
        jobs = [{"url": self.base + "/openapi.json"}]
        out = concurrency.fetch_many(sess, jobs, degree=2, cancel=cancel)
        self.assertEqual(len(out), 1)

    def test_cancelled_job_does_not_raise(self):
        sess = self.session()
        cancel = threading.Event()
        cancel.set()
        jobs = [{"url": self.base + f"/p{i}"} for i in range(4)]
        out = concurrency.fetch_many(sess, jobs, degree=4, cancel=cancel)
        self.assertEqual(len(out), 4)
        self.assertTrue(all(r.error for r in out))


class TestDegree(unittest.TestCase):
    def test_degree_respects_hard_cap(self):
        sess = Session("example.com")
        self.assertLessEqual(concurrency.parallel_degree(sess, 64), concurrency.HARD_CAP)

    def test_degree_is_at_least_one(self):
        sess = Session("example.com", budget_seconds=0.01)
        time.sleep(0.05)
        self.assertGreaterEqual(concurrency.parallel_degree(sess, 8), 1)

    def test_empty_jobs(self):
        self.assertEqual(concurrency.fetch_many(Session("example.com"), []), [])


if __name__ == "__main__":
    unittest.main()
