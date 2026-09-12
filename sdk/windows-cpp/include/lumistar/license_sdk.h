// Lumistar Windows C++ SDK —— 公共接口（C ABI + C++ RAII 封装）。
//
// 接入方式（最小三步）：
//   1. lumistar_init({server_url, product_code, storage_dir})
//   2. lumistar_activate(card)                       // 信封加密 + 设备签名
//   3. lumistar_has_feature("aimbot")                // 业务功能门禁
//
// 安全模型：
//   - 激活载荷经 X25519 + HKDF + AES-256-GCM 信封加密（TLS 之外的端到端层）
//   - 设备密钥：优先 TPM（NCrypt 平台加密提供程序，ECDSA P-256），否则 BCrypt 软件密钥
//   - 所有请求携带设备签名（PoP）+ nonce + 单调序列号（防重放）
//   - 授权状态 = 服务端签发的短时租约，本地 DPAPI 加密缓存，启动时严格验签
//   - 心跳失败指数退避；租约过期立即返回未授权（服务端吊销一个心跳内传播）
#ifndef VERTIFY_LICENSE_SDK_H
#define VERTIFY_LICENSE_SDK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *vft_handle_t;

// 结构化错误码（业务方可按码处理，不依赖文案）
typedef enum vft_err {
	VFT_OK = 0,
	VFT_E_INVALID_ARG = 1,
	VFT_E_NETWORK = 2,          // 网络失败（可重试）
	VFT_E_BAD_RESPONSE = 3,     // 服务端响应不可信（签名/格式）
	VFT_E_CARD_INVALID = 4,     // 卡密格式错误
	VFT_E_CARD_NOT_FOUND = 5,   // 卡密不存在
	VFT_E_CARD_FROZEN = 6,
	VFT_E_CARD_REVOKED = 7,
	VFT_E_CARD_VOIDED = 8,
	VFT_E_CARD_DEPLETED = 9,
	VFT_E_LICENSE_FROZEN = 10,
	VFT_E_LICENSE_REVOKED = 11,
	VFT_E_LICENSE_EXPIRED = 12,
	VFT_E_DEVICE_LIMIT = 13,    // 设备名额已满（需先解绑）
	VFT_E_CONCURRENT_LIMIT = 14,// 并发名额已满
	VFT_E_DEVICE_UNBOUND = 15,
	VFT_E_REPLAY = 16,
	VFT_E_VERSION_TOO_OLD = 17,
	VFT_E_RATE_LIMITED = 18,
	VFT_E_BANNED = 19,
	VFT_E_CRYPTO = 20,          // 本地密码学错误
	VFT_E_STORAGE = 21,         // 本地存储错误
	VFT_E_INTERNAL = 22,
} vft_err_t;

// 授权状态（从签名租约推导，本地不做任何放宽判断）
typedef enum vft_state {
	VFT_STATE_NOT_ACTIVATED = 0,
	VFT_STATE_ACTIVE = 1,       // 租约有效
	VFT_STATE_STALE = 2,        // 租约过期（心跳失联超过宽限）
	VFT_STATE_REVOKED = 3,      // 服务端已吊销/冻结
	VFT_STATE_ERROR = 4,
} vft_state_t;

typedef struct vft_config {
	const char *server_url;     // 例如 "https://api.example.com"（仅 HTTPS）
	const char *product_code;   // 产品代码
	const char *storage_dir;    // 状态目录（默认 %PROGRAMDATA%\Lumistar）
	const char *client_version; // 客户端版本（最低版本策略用）
	const unsigned char *pin_pubkeys;   // 可选：Ed25519 公钥池（32B * n）
	size_t pin_pubkeys_len;             // n（0 = 使用 bootstrap 分发并持久固定）
	int insecure_skip_tls_verify;       // 仅限本地开发联调！生产必须为 0
} vft_config;

typedef struct vft_activation_result {
	char license_id[64];
	char device_id[64];
	int64_t lease_exp;          // 租约到期（unix 秒）
	int64_t license_exp;        // 许可证到期（0=永久）
} vft_activation_result;

// 状态变化回调（心跳线程触发，勿在回调内调用 SDK）
typedef void (*vft_state_cb)(vft_state_t state, void *user);

// ===== 生命周期 =====
vft_err_t lumistar_init(const vft_config *cfg, vft_handle_t *out);
void      lumistar_shutdown(vft_handle_t h);

// ===== 激活 / 兑换 / 解绑（阻塞式） =====
vft_err_t lumistar_activate(vft_handle_t h, const char *card,
                           vft_activation_result *out /*可空*/);
vft_err_t lumistar_redeem(vft_handle_t h, const char *renewal_card);
vft_err_t lumistar_deactivate(vft_handle_t h); // 自助解绑当前设备

// ===== 心跳 =====
vft_err_t lumistar_start_heartbeat(vft_handle_t h, vft_state_cb cb, void *user);
vft_err_t lumistar_stop_heartbeat(vft_handle_t h);

// ===== 授权查询（业务高频调用） =====
vft_state_t lumistar_get_state(vft_handle_t h);
// 功能门禁：每次调用实时验证租约签名/有效期/绑定，不缓存布尔值
int         lumistar_has_feature(vft_handle_t h, const char *feature);
// 当前租约剩余秒数（负值=已过期）
int64_t     lumistar_lease_remaining(vft_handle_t h);

// ===== 工具 =====
const char *lumistar_err_str(vft_err_t err);
// 自检：RFC 7748 X25519 向量 + RFC 8032 Ed25519 向量 + AES-GCM 往返
vft_err_t   lumistar_selftest(void);

#ifdef __cplusplus
} // extern "C"

// ===== C++ RAII 封装 =====
#include <string>
namespace lumistar {

class License {
public:
	License() = default;
	~License() { shutdown(); }
	License(const License &) = delete;
	License &operator=(const License &) = delete;

	vft_err_t init(const vft_config &cfg) { return lumistar_init(&cfg, &h_); }
	void shutdown() { if (h_) { lumistar_shutdown(h_); h_ = nullptr; } }
	bool ok() const { return h_ != nullptr; }

	vft_err_t activate(const std::string &card, vft_activation_result *out = nullptr) {
		return lumistar_activate(h_, card.c_str(), out);
	}
	vft_err_t redeem(const std::string &card) { return lumistar_redeem(h_, card.c_str()); }
	vft_err_t deactivate() { return lumistar_deactivate(h_); }
	vft_err_t start_heartbeat(vft_state_cb cb = nullptr, void *user = nullptr) {
		return lumistar_start_heartbeat(h_, cb, user);
	}
	vft_err_t stop_heartbeat() { return lumistar_stop_heartbeat(h_); }

	vft_state_t state() const { return lumistar_get_state(h_); }
	bool has_feature(const std::string &f) const { return lumistar_has_feature(h_, f.c_str()) == 1; }
	int64_t lease_remaining() const { return lumistar_lease_remaining(h_); }

private:
	vft_handle_t h_ = nullptr;
};

} // namespace lumistar
#endif // __cplusplus

#endif // VERTIFY_LICENSE_SDK_H
