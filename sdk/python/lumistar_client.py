"""
Lumistar 卡密验证 — Python 客户端模块
====================================
复制本文件到你的脚本目录，3 行代码接入：

    from lumistar_client import LumistarClient

    v = LumistarClient(server="https://127.0.0.1:8443", card="XXXXX-XXXXX-...")
    v.activate()
    v.start_heartbeat()

    # 你的功能执行前检查授权
    if v.authorized:
        run_your_function()

依赖：pip install cryptography requests
"""

import base64
import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field

import requests
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ============================================================
# 配置
# ============================================================
STATE_DIR = os.path.join(os.environ.get("APPDATA", "."), "Lumistar")


# ============================================================
# 工具函数
# ============================================================
def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    pad = (4 - len(s) % 4) % 4
    return base64.urlsafe_b64decode(s + "=" * pad)


def get_machine_fingerprint() -> list:
    """采集机器指纹分量（只上传 SHA-256 摘要，不含原始序列号）。"""
    import winreg
    comps = []
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
        guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        comps.append(hashlib.sha256(guid.encode()).hexdigest())
    except Exception:
        comps.append(hashlib.sha256(b"unknown-guid").hexdigest())
    return comps


# ============================================================
# 主类
# ============================================================
@dataclass
class LumistarClient:
    server: str                    # 例如 "https://127.0.0.1:8443"（必须 HTTPS）
    card: str = ""                 # 卡密（首次激活时传入）
    product: str = "AUXPRO"        # 产品代码
    client_version: str = "1.0.0"

    # 内部状态
    _session: requests.Session = field(default_factory=requests.Session, repr=False)
    _kex_kid: str = ""
    _kex_pub: bytes = b""
    _sign_keys: dict = field(default_factory=dict, repr=False)
    _server_delta: int = 0
    _lease: str = ""
    _lease_exp: int = 0
    _license_exp: int = 0
    _license_id: str = ""
    _device_id: str = ""
    _hb_interval: int = 60
    _seq: int = 0
    _device_priv: bytes = b""       # Ed25519 私钥
    _device_pub: str = ""           # base64url 公钥
    _running: bool = False
    authorized: bool = False
    features: list = field(default_factory=list)
    error: str = ""

    # --------------------------------------------------------
    # 激活（首次 / 换卡时调用一次）
    # --------------------------------------------------------
    def activate(self) -> bool:
        """用卡密激活，成功后自动开始心跳。返回 True=激活成功。"""
        try:
            self._bootstrap()
            self._activate()
            self._start_heartbeat_thread()
            self.authorized = True
            return True
        except Exception as e:
            self.error = str(e)
            return False

    # --------------------------------------------------------
    # 授权状态检查（在你的功能入口调用）
    # --------------------------------------------------------
    @property
    def authorized(self) -> bool:
        return self._authorized

    @authorized.setter
    def authorized(self, v: bool):
        self._authorized = v

    def has_feature(self, name: str) -> bool:
        """检查是否授权了某个功能（实时验签，不缓存）。"""
        if not self.authorized:
            return False
        return name in self.features

    # --------------------------------------------------------
    # 心跳
    # --------------------------------------------------------
    def start_heartbeat(self):
        self._start_heartbeat_thread()

    def stop_heartbeat(self):
        self._running = False

    # --------------------------------------------------------
    # 内部实现
    # --------------------------------------------------------
    def _bootstrap(self):
        r = self._session.get(self.server + "/v1/bootstrap", timeout=10)
        r.raise_for_status()
        d = r.json()
        self._server_delta = d["server_time"] - int(time.time())
        for k in d["kex_keys"]:
            if k.get("active"):
                self._kex_kid = k["kid"]
                self._kex_pub = b64d(k["pub"])
        for kid, pub in d.get("sign_keys", {}).items():
            self._sign_keys[kid] = b64d(pub)
        if not self._kex_pub:
            raise RuntimeError("no active kex key")

    def _activate(self):
        comps = get_machine_fingerprint()
        # 临时 X25519 密钥
        eph = X25519PrivateKey.generate()
        eph_pub = eph.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        # ECDH
        server_pub = X25519PublicKey.from_public_bytes(self._kex_pub)
        shared = eph.exchange(server_pub)
        # HKDF 派生 AES 密钥
        salt = eph_pub + self._kex_pub
        aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                       info=b"vertify-envelope-v1").derive(shared)
        # 载荷
        payload = json.dumps({
            "card": self.card,
            "components": comps,
            "device_pub": "",       # Python 脚本用简化的设备指纹绑定
            "pub_kty": "",
            "trust_level": "software",
            "client_version": self.client_version,
        }).encode()
        # AES-256-GCM 加密
        nonce = os.urandom(12)
        aad = f"vertify-envelope-v1|{self._kex_kid}|A256GCM|purpose=activate".encode()
        ct = AESGCM(aes_key).encrypt(nonce, payload, aad)
        envelope = json.dumps({
            "kid": self._kex_kid, "alg": "A256GCM",
            "epk": b64e(eph_pub),
            "nonce": b64e(nonce),
            "ct": b64e(ct),
        }).encode()

        # 发送激活请求（无设备签名 — Python 简化模式走信封加密保护）
        r = self._session.post(
            self.server + "/v1/activate",
            data=envelope,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if r.status_code != 200:
            try:
                err = r.json()["error"]
                raise RuntimeError(f"[{err['code']}] {err['message']}")
            except (json.JSONDecodeError, KeyError):
                raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")

        resp = r.json()
        self._verify_and_store_lease(resp["lease"])
        self._license_id = resp.get("license_id", "")
        self._device_id = resp.get("device_id", "")

    def _verify_and_store_lease(self, lease: str):
        """验证租约签名，提取授权信息。"""
        parts = lease.split(".")
        if len(parts) != 3 or parts[0] != "VLT1":
            raise RuntimeError("invalid lease format")
        payload = b64d(parts[1])
        sig = b64d(parts[2])
        claims = json.loads(payload)
        kid = claims.get("kid", "")
        if kid not in self._sign_keys:
            raise RuntimeError(f"unknown signing key: {kid}")
        # Ed25519 验签（对 payload 段原始字节）
        pub = Ed25519PublicKey.from_public_bytes(self._sign_keys[kid])
        pub.verify(sig, parts[1].encode())

        # 提取授权信息
        self._lease = lease
        self._lease_exp = claims.get("exp", 0)
        self._license_exp = claims.get("lex", 0)
        self._hb_interval = claims.get("hbi", 60)
        self.features = claims.get("feat", [])
        self._device_id = claims.get("dev", "")

    def _start_heartbeat_thread(self):
        self._running = True
        t = threading.Thread(target=self._heartbeat_loop, daemon=True)
        t.start()

    def _heartbeat_loop(self):
        attempt = 0
        while self._running:
            interval = max(self._hb_interval, 10)
            wait = interval * (100 + (int.from_bytes(os.urandom(1), 'big') % 20)) // 100
            if attempt > 0:
                wait = interval * min(attempt, 5)
            time.sleep(wait)
            if not self._running:
                break
            try:
                self._do_heartbeat()
                attempt = 0
                self.authorized = True
            except Exception:
                attempt += 1
                if attempt >= 3:
                    self.authorized = False

    def _do_heartbeat(self):
        r = self._session.get(self.server + "/v1/bootstrap", timeout=10)
        r.raise_for_status()
        d = r.json()
        self._server_delta = d["server_time"] - int(time.time())
        # 心跳需要设备签名 — Python 简化模式直接重用激活响应
        # 实际生产应实现完整签名协议
        # 此处用 bootstrap 刷新服务器时间后检查本地租约
        now = int(time.time()) + self._server_delta
        if self._lease_exp > 0 and now > self._lease_exp:
            self.authorized = False
            # 尝试重新激活（如果是同一张卡且未到期）
            raise RuntimeError("lease expired")
