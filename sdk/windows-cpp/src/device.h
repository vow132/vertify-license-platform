// 设备密钥：优先 TPM（NCrypt 平台加密提供程序），无 TPM 回退 BCrypt 软件密钥。
// 统一输出：65B 非压缩公钥（0x04||X||Y）+ 摘要签名（DER）。
#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

namespace lumistar {

class DeviceKey {
public:
	enum Backend { NONE, TPM, SOFTWARE };

	bool generate_or_load(); // TPM 尝试 → 软件回退
	bool restore_software(const std::vector<uint8_t> &privBlob, const std::string &pubB64);
	void clear();

	const std::vector<uint8_t> &public_point() const { return pub_; } // 65B
	const std::string &pub_b64() const { return pubB64_; }
	Backend backend() const { return backend_; }

	// 软件私钥 blob 导出（BCRYPT_ECCPRIVATE_BLOB，供 DPAPI 加密持久化）
	bool export_private_blob(std::vector<uint8_t> &blob) const;

	// 对 SHA-256 摘要做 ECDSA-P256 签名（DER 编码）
	bool sign_digest(const uint8_t digest[32], std::vector<uint8_t> &der);

private:
	bool try_tpm();
	bool try_software();
	void set_pub(const std::vector<uint8_t> &pub);

	Backend backend_ = NONE;
	NCRYPT_KEY_HANDLE tpmKey_ = 0;
	BCRYPT_KEY_HANDLE swKey_ = nullptr;
	std::vector<uint8_t> pub_;
	std::string pubB64_;
};

} // namespace lumistar
