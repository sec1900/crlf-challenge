#!/usr/bin/env python3
"""
CTF Challenge - Login Puzzle
选手不提供源码, 仅提供网络服务. 此文件仅为出题参考.
"""
import http.server, os, re, random, string, threading, time, binascii, urllib.parse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
AUTH_DIR = BASE_DIR / "data" / "auth"
KEY_DIR = BASE_DIR / "data" / "keys"
HOST, PORT = "0.0.0.0", 8666

AUTH_DIR.mkdir(parents=True, exist_ok=True)
KEY_DIR.mkdir(parents=True, exist_ok=True)


def generate_key(session_id):
    """生成密钥 — 注意 flag 格式不透露漏洞名"""
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return f"FLAG{{{session_id}_{rand}}}"


def rot13(text):
    """ROT13 编码辅助函数"""
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(c)
    return "".join(result)


def monitor():
    print(f"[*] 监控启动, 目录: {AUTH_DIR}")
    seen = set()
    while True:
        for f in AUTH_DIR.glob("*.log"):
            if f.name in seen:
                continue
            try:
                content = f.read_text(encoding="utf-8")
                kv = {}
                for line in content.splitlines():
                    line = line.strip()
                    if "=" in line:
                        k, v = line.split("=", 1)
                        kv[k.strip()] = v.strip()
                if kv.get("verified") == "1" and kv.get("email"):
                    seen.add(f.name)
                    key = generate_key(f.stem)
                    # 用 session ID 命名，只有持有 trace cookie 的人知道
                    kf = KEY_DIR / f"{f.stem}.txt"
                    kf.write_text(
                        f"恭喜通关！\n\n密钥: {key}\n追踪文件: {f.name}\n",
                        encoding="utf-8")
                    print(f"\n[+] verified=1 email={kv['email']} key={key}")
            except Exception as e:
                print(f"[-] {f}: {e}")
        time.sleep(3)


# ============================================================
# 提示体系设计
# ============================================================

# ROT13 注释已移除 — 太直白，选手应自己从 sample.txt 推断格式

# 线索2: 登录页 — 隐藏的 verified=0 字段 + ROT13 注释
PAGE_LOGIN = f"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>请登录</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:"Courier New",monospace;background:#111;color:#999;
  display:flex;justify-content:center;align-items:center;min-height:100vh}}
.b{{background:#181818;border:1px solid #333;padding:44px 40px 34px;width:360px;text-align:center}}
.b h1{{font-size:16px;font-weight:400;color:#777;margin-bottom:28px;letter-spacing:2px}}
.b input{{display:block;width:100%;padding:10px 12px;margin:0 0 10px;
  background:#0a0a0a;border:1px solid #2a2a2a;color:#bbb;
  font-family:inherit;font-size:14px;outline:none}}
.b input:focus{{border-color:#555}}
.b button{{width:100%;padding:10px;margin-top:6px;background:#1f1f1f;
  border:1px solid #444;color:#aaa;font-family:inherit;font-size:14px;cursor:pointer}}
.b button:hover{{background:#2a2a2a}}
.msg{{color:#c44;margin-top:18px;font-size:13px;word-break:break-all}}
.fp{{margin-top:24px;font-size:11px}}
.fp a{{color:#555;text-decoration:none}}
.fp a:hover{{color:#888}}
/* 非标准输入可能导致意外行为 */
</style>
</head>
<body>
<div class="b">
<h1>系统登录</h1>
<form method="POST" action="/login">
<input type="text" name="username" placeholder="用户名" autofocus>
<input type="password" name="password" placeholder="密码">
<input type="hidden" name="verified" value="0">
<button type="submit">登 录</button>
</form>%MSG%
<div class="fp"><a href="/forgot">忘记密码?</a></div>
</div>
</body>
</html>"""

# 线索3: 找回密码页 — 暗示日志记录机制
PAGE_FORGOT = """<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<title>找回密码</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:"Courier New",monospace;background:#111;color:#999;
  display:flex;justify-content:center;align-items:center;min-height:100vh}
.b{background:#181818;border:1px solid #333;padding:40px;width:420px;text-align:center}
.b h1{font-size:16px;font-weight:400;color:#777;margin-bottom:20px;letter-spacing:2px}
.b p{font-size:12px;color:#666;line-height:1.8;margin-bottom:24px}
.b input{display:block;width:100%;padding:10px 12px;margin:0 0 10px;
  background:#0a0a0a;border:1px solid #2a2a2a;color:#bbb;
  font-family:inherit;font-size:14px;outline:none}
.b input:focus{border-color:#555}
.b button{width:100%;padding:10px;margin-top:6px;background:#1f1f1f;
  border:1px solid #444;color:#aaa;font-family:inherit;font-size:14px;cursor:pointer}
.b button:hover{background:#2a2a2a}
.b a{color:#555;text-decoration:none;font-size:12px}
.b a:hover{color:#888}
.msg{color:#c44;margin-top:18px;font-size:13px}
</style>
</head>
<body>
<div class="b">
<h1>找回密码</h1>
<p>系统将每次登录的字段逐行写入会话记录。<br>
校验器读取记录文件后，若验证通过则向您发送密钥。<br>
密钥归档于 <code>/keys/</code> 目录。<br>
当前仅支持 <code>email</code> 通道接收。</p>
<form method="POST" action="/forgot">
<input type="text" name="email" placeholder="注册邮箱">
<button type="submit">发送验证</button>
</form>%MSG%
<a href="/">← 返回登录</a>
</div>
</body>
</html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # 强制短连接, 避免 keep-alive 残留

    def setup(self):
        """给连接 socket 设超时, 防止单线程被慢客户端永久阻塞"""
        super().setup()
        self.connection.settimeout(30)

    def log_message(self, fmt, *args):
        print(f"  {self.address_string()} - {args[0]}")

    def do_GET(self):
        try:
            self._do_GET_impl()
        except Exception as e:
            print(f"[-] GET error: {e}")
            try:
                self.send_response(500)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "0")
                self.end_headers()
            except Exception:
                pass

    def _do_GET_impl(self):
        path = urllib.parse.urlparse(self.path).path
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)

        if path == "/":
            msg = qs.get("msg", [""])[0]
            html = PAGE_LOGIN.replace("%MSG%",
                f'<p class="msg">{msg}</p>' if msg else "")
            data = html.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        elif path == "/forgot":
            msg = qs.get("msg", [""])[0]
            html = PAGE_FORGOT.replace("%MSG%",
                f'<p class="msg">{msg}</p>' if msg else "")
            data = html.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        elif path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /backup/\nDisallow: /keys/\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/backup" or path == "/backup/":
            body = (
                "Index of /backup/\n"
                "\n"
                "[   ]  sample.txt            2024-06-22 03:00   78 B\n"
                "[   ]  changelog.txt          2024-06-15 18:22  185 B\n"
                "\n"
                "# 系统自动归档的日志样本，供调试参考\n"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/backup/changelog.txt":
            body = (
                "CHANGELOG - 认证系统更新记录\n"
                "================================\n"
                "\n"
                "v0.3 (2024-06-15)\n"
                "  - 移除调试端点 /debug\n"
                "  - 认证记录迁移至独立存储\n"
                "  - 字段值未做编码处理\n"
                "\n"
                "v0.2 (2024-05-10)\n"
                "  - 新增 email 通知通道\n"
                "  - 修复 session 泄漏问题\n"
                "\n"
                "v0.1 (2024-04-01)\n"
                "  - 初始版本，基础登录功能\n"
                "  - 日志格式: key=value 每行一条\n"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/backup/sample.txt":
            body = (
                b"# Log Format Reference\n"
                b"username=admin\n"
                b"password=********\n"
                b"timestamp=1719000000\n"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path.startswith("/backup/"):
            body = b"Not Found\n"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path.startswith("/keys/"):
            kf = KEY_DIR / os.path.basename(path)
            if kf.exists():
                data = kf.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                body = b"Not Found\n"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        elif path == "/debug":
            body = (
                b"{\n"
                b'  "status": "disabled",\n'
                b'  "reason": "debug mode removed for security",\n'
                b'  "note": "use /backup/ for historical records"\n'
                b"}\n"
            )
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        else:
            body = b"Not Found\n"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_POST(self):
        try:
            self._do_POST_impl()
        except Exception as e:
            print(f"[-] POST error: {e}")
            try:
                self.send_response(500)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "0")
                self.end_headers()
            except Exception:
                pass

    def _do_POST_impl(self):
        path = urllib.parse.urlparse(self.path).path

        if path == "/forgot":
            # 先排空请求体, 再返回响应
            length = int(self.headers.get("Content-Length", 0))
            if length > 0 and length <= 65536:
                self.rfile.read(length)
            self.send_response(302)
            self.send_header("Content-Length", "0")
            self.send_header("Location",
                "/forgot?msg=" + urllib.parse.quote("校验失败 — 该邮箱未在登录记录中出现"))
            self.end_headers()

        elif path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            # 防止恶意超大 Content-Length 导致阻塞
            if length < 0 or length > 65536:
                self.send_response(413)
                self.send_header("Content-Type", "text/plain")
                body = b"Payload Too Large\n"
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            body = self.rfile.read(length).decode("utf-8", errors="replace")
            params = urllib.parse.parse_qs(body)
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]

            sid = binascii.hexlify(os.urandom(8)).decode()
            af = AUTH_DIR / f"{sid}.log"

            content = f"username={username}\npassword={password}\ntimestamp={int(time.time())}\n"
            af.write_text(content, encoding="utf-8")

            self.send_response(302)
            self.send_header("Content-Length", "0")
            self.send_header("Set-Cookie", f"trace={sid}; Path=/")
            self.send_header("X-Log-File", str(af))
            self.send_header("Location",
                "/?msg=" + urllib.parse.quote("失败是成功之母"))
            self.end_headers()
        else:
            body = b"Not Found\n"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def main():
    threading.Thread(target=monitor, daemon=True).start()
    server = http.server.HTTPServer((HOST, PORT), Handler)
    # 设置 accept 超时, 使得 KeyboardInterrupt 能被及时响应
    server.socket.settimeout(1.0)
    print(f"[*] http://127.0.0.1:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] 关闭")
        server.server_close()


if __name__ == "__main__":
    main()
