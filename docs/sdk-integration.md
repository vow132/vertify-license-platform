# Windows C++ SDK 接入指南

> 面向实际植入脚本/客户端的完整中文操作说明请先阅读：[使用指南.md](使用指南.md)。本文保留 C++ SDK 的 API 细节和最小代码示例。

## 构建产物

- `vertify_sdk`（静态库；MinGW/MSVC 均支持，MSVC 发布构建启用 CFG/ASLR/DEP/GS）
- `activate_demo.exe`（最小接入示例）
- `selftest.exe`（密码学自检：RFC 7748 X25519 向量、RFC 8032 Ed25519 向量、AES-GCM 往返）

> 构建标准：当前 SDK 使用 C++17；不要把文档示例或调用方配置为 C++20 专属特性。

第三方组件：orlp/ed25519（zlib，仅验签子集），见 `third_party/ed25519/NOTICE.md`。

## 最小接入（约 20 行）

```cpp
#include <vertify/license_sdk.h>

// 1. 初始化（进程内一次）
vft_config cfg = {};
cfg.server_url    = "https://api.example.com";   // 仅 HTTPS
cfg.product_code  = "AUXPRO";
cfg.client_version = "1.2.0";                    // 最低版本策略用
vertify::License lic;
lic.init(cfg);

// 2. 首次激活（用户输入卡密；此后本地缓存租约，无需重复激活）
if (lic.state() == VFT_STATE_NOT_ACTIVATED) {
    vft_err_t err = lic.activate(card);          // 信封加密 + 设备签名
    // err == VFT_OK 即激活成功
}

// 3. 心跳（自动续租、抖动、退避；服务端吊销一个心跳周期内传播）
lic.start_heartbeat(on_state_change, nullptr);

// 4. 业务功能门禁（每次调用实时验签，无本地布尔缓存）
if (lic.has_feature("aimbot")) {
    // 授权功能
}
```

## 关键行为

| 行为 | 说明 |
|---|---|
| 设备密钥 | 优先 TPM（NCrypt 平台加密提供程序，ECDSA P-256），无 TPM 回退 DPAPI 保护的软件密钥 |
| 本地状态 | `%APPDATA%\Vertify\<product>\state.bin`，DPAPI（当前用户域）加密、原子写 |
| 心跳 | 启动立即发送首次心跳（重开应用秒级恢复授权）；周期 = 套餐 `heartbeat_interval_seconds` ± 10% 抖动；失败指数退避（最多 5×） |
| 掉线判定 | 租约过期 = `VFT_STATE_STALE`；服务端冻结/吊销 = `VFT_STATE_REVOKED`（回调即时通知） |
| 换机 | 新设备激活受设备名额限制；旧设备 `DeactivateDevice` 或管理员解绑后可重绑 |
| 续费 | `lic.redeem(renewal_card)`；时长叠加到现有到期时间 |
| 重装系统 | 同指纹新密钥：服务端自动轮换设备公钥（不占新名额） |
| 公钥轮换 | 首次 bootstrap TOFU 固定公钥集；高安全场景由宿主注入 `pin_pubkeys` |

## 错误处理

`vft_err_t` 结构化错误码（`vertify_err_str` 提供文案）。业务建议：

- `VFT_E_NETWORK` / `VFT_E_BAD_RESPONSE`：暂时性，提示重试
- `VFT_E_LICENSE_FROZEN/REVOKED/EXPIRED`、`VFT_E_CARD_*`：按运营策略引导（续费/联系客服）
- `VFT_E_DEVICE_LIMIT`：引导解绑旧设备或购买扩容
- `VFT_E_CONCURRENT_LIMIT`：并发名额占用中，提示稍后或下线其它设备
- `VFT_E_RATE_LIMITED` / `VFT_E_BANNED`：静默降级，不要提示细节（对抗枚举）

## 安全注意事项

- **生产环境严禁** `cfg.insecure_skip_tls_verify = 1`。示例程序默认开启证书校验；仅在本地自签名联调时，显式追加 `--insecure-dev-only` 参数才会关闭校验。
- 授权判定必须走 `has_feature`（内部验签），不要缓存其返回值或绕过 SDK 自行判断。
- 状态文件含 DPAPI 保护的材料，随用户域隔离；不要复制到其它机器。
- `DeactivateDevice` 前先 `StopHeartbeat`（示例代码已按此顺序），避免并发使用序列号。
- 如宿主可分发嵌入公钥（编译期固定），设置 `cfg.pin_pubkeys` 可消除 TOFU 信任面。
