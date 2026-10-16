"""使用本地 HTTPS 服务验证 Telegram 凭据发送前的证书检查。

仅依赖 requests、标准库和 openssl；不连接 Telegram、MongoDB 或消息队列。
"""
import ast
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests
from requests.exceptions import ReadTimeout
from urllib3.exceptions import InsecureRequestWarning


ROOT = Path(__file__).resolve().parents[1]


def load_definitions(path, names, env):
    """抽取实际 HTTP/推送实现，避免加载数据库及扫描器依赖。"""
    nodes = []
    for node in ast.parse((ROOT / path).read_text(encoding='utf-8')).body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names:
            nodes.append(node)
        elif isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id in names
                for target in node.targets):
            nodes.append(node)
    module = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    exec(compile(module, str(ROOT / path), 'exec'), env)
    return env


@unittest.skipUnless(shutil.which('openssl'), '本地 TLS 测试需要 openssl')
class TelegramTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temp.cleanup)
        cert = Path(temp.name) / 'localhost.crt'
        key = Path(temp.name) / 'localhost.key'
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(key), '-out', str(cert), '-days', '1',
            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.cert = str(cert)
        cls.received = []
        received = cls.received

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                received.append(json.loads(body))
                response = b'{"ok": true}'
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        cls.port = server.server_port
        thread = threading.Thread(
            target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        thread.start()

        def stop_server():
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()

        cls.addClassCleanup(stop_server)

    def setUp(self):
        self.received.clear()
        self.endpoint = f'https://localhost:{self.port}/sendMessage'
        self.enterContext(patch.dict(os.environ, {
            'REQUESTS_CA_BUNDLE': '', 'CURL_CA_BUNDLE': '',
            'NO_PROXY': 'localhost,127.0.0.1', 'no_proxy': 'localhost,127.0.0.1',
        }))
        self.enterContext(warnings.catch_warnings())
        warnings.simplefilter('ignore', InsecureRequestWarning)
        transport = load_definitions('app/utils/conn.py', {
            'CONTENT_CHUNK_SIZE', 'UA', 'proxies', '_adapter',
            'StatelessSession', 'patch_content', 'http_req',
        }, {
            'requests': requests, 'ReadTimeout': ReadTimeout, 'time': time,
            'Config': SimpleNamespace(PROXY_URL=''),
        })
        self.http_req = transport['http_req']
        self.addCleanup(transport['_adapter'].close)

        def local_request(url, method='get', **kwargs):
            return self.http_req(self.endpoint, method=method, **kwargs)

        sender = load_definitions('app/utils/push.py', {'telegram_send'}, {
            'http_req': local_request, 'logger': Mock(),
        })
        self.telegram_send = sender['telegram_send']

    def test_untrusted_certificate_blocks_notification(self):
        result = self.telegram_send('test message', 'test-token', 'test-chat')
        self.assertEqual(result, {})
        self.assertEqual(self.received, [])

    def test_trusted_certificate_delivers_notification(self):
        with patch.dict(os.environ, {'REQUESTS_CA_BUNDLE': self.cert}):
            result = self.telegram_send('test message', 'test-token', 'test-chat')
        self.assertEqual(result, {'ok': True})
        self.assertEqual(self.received, [{'chat_id': 'test-chat', 'text': 'test message'}])

    def test_hostname_mismatch_blocks_notification_even_with_trusted_ca(self):
        self.endpoint = f'https://127.0.0.1:{self.port}/sendMessage'
        with patch.dict(os.environ, {'REQUESTS_CA_BUNDLE': self.cert}):
            result = self.telegram_send('test message', 'test-token', 'test-chat')
        self.assertEqual(result, {})
        self.assertEqual(self.received, [])

    def test_scan_helper_can_still_access_self_signed_targets(self):
        result = self.http_req(self.endpoint, method='post', json={'scan': 'fixture'})
        self.assertEqual(result.json(), {'ok': True})
        self.assertEqual(self.received, [{'scan': 'fixture'}])


if __name__ == '__main__':
    unittest.main()
