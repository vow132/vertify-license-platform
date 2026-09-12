# Python SDK 接入（实验性）

> 当前版本仅提供信封加密、租约验签和机器指纹示例，**尚未实现服务端要求的设备 PoP 签名、nonce/seq 重放保护和 `/v1/heartbeat` 心跳协议，因此不能用于生产激活**。请使用 Windows C++ SDK；Python 仅用于协议联调和原型验证。
## 安装依赖

```bash
pip install cryptography requests
```

## 文件

- `sdk/python/lumistar_client.py` — 集成模块（复制到你的脚本目录）
- `sdk/python/example.py` — 完整示例

## 快速接入（3 行代码）

```python
from lumistar_client import LumistarClient

v = Lumistar(server="https://你的服务器:8443", card="用户输入的卡密")
v.activate()          # 首次激活（后续自动从本地缓存恢复）
v.start_heartbeat()   # 后台自动续租

# 功能执行前检查
if v.authorized and v.has_feature("你的功能名"):
    do_something()
```

## 安全模型

| 层级 | 说明 |
|---|---|
| 传输 | TLS 1.3 + 应用层信封加密（抓包看不到卡密） |
| 机器绑定 | 激活后绑定机器指纹（MachineGUID 等 SHA-256 摘要） |
| 租约 | 服务器签发 Ed25519 签名租约，默认 300 秒有效 |
| 心跳 | 后台自动续租；冻结/吊销一个心跳周期内传播 |
| 到期 | 租约过期 = `authorized=False`，脚本功能自动停止 |

## 注意事项

- Python 脚本源码可读，保护强度依赖服务端（到期/冻结/设备数），不在客户端混淆
- 如需更高保护级别，用 C++ SDK 编译为 DLL 后从 Python ctypes 调用
