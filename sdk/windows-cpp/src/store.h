// 本地状态存储：DPAPI（当前用户域）加密的 JSON 状态文件。
// 内容：设备公钥/私钥blob（软件密钥时）、许可证绑定、租约、序列号、固定公钥集。
#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace vertify {

struct SdkState {
	// 设备身份
	std::string backend;      // "tpm" | "software"
	std::string pub_b64;      // 65B 非压缩点
	std::vector<uint8_t> enc_priv; // DPAPI 保护的软件私钥 blob（TPM 时为空）

	// 绑定与租约
	std::string license_id;
	std::string device_id;
	std::string lease;        // VLT1.x.y
	int64_t lease_exp = 0;
	int64_t license_exp = 0;
	int64_t hb_interval = 60;
	int64_t seq = 0;

	// 信任锚（TOFU 固定的服务端公钥集）
	std::vector<std::string> pinned_sign_keys; // kid|base64url_pub

	bool has_binding() const { return !license_id.empty() && !device_id.empty(); }
};

class StateStore {
public:
	bool load(const std::string &dir, SdkState &out);      // 不存在返回 true 且空状态
	bool save(const std::string &dir, const SdkState &st); // 原子写（临时文件+替换）
};

// DPAPI（当前用户域）加解密，供软件设备私钥等敏感数据持久化。
bool dpapi_protect(const std::vector<uint8_t> &in, std::vector<uint8_t> &out);
bool dpapi_unprotect(const std::vector<uint8_t> &in, std::vector<uint8_t> &out);

} // namespace vertify
