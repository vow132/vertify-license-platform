// CNG 密码学封装：SHA-256、HMAC、HKDF、AES-256-GCM、ECDSA P-256、随机数。
#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <windows.h>
#include <bcrypt.h>

namespace vertify {

struct Cng {
	static std::vector<uint8_t> random(size_t n);
	static std::vector<uint8_t> sha256(const uint8_t *data, size_t len);
	static std::vector<uint8_t> hmac_sha256(const uint8_t *key, size_t keyLen,
	                                        const uint8_t *data, size_t len);
	// HKDF-SHA256（RFC 5869）
	static std::vector<uint8_t> hkdf_sha256(const uint8_t *salt, size_t saltLen,
	                                        const uint8_t *info, size_t infoLen,
	                                        size_t outLen,
	                                        const uint8_t *ikm, size_t ikmLen);

	// AES-256-GCM 加密（客户端封装方向）。nonce 必须 12 字节。
	static bool aes_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
	                            const uint8_t *pt, size_t ptLen,
	                            const uint8_t *aad, size_t aadLen,
	                            std::vector<uint8_t> &out /* ct||tag */);

	// ECDSA P-256（设备密钥，软件 BCrypt；TPM 路径见 device.h）
	struct KeyPair {
		BCRYPT_KEY_HANDLE h = nullptr;
		std::vector<uint8_t> pub; // 65B: 0x04||X||Y（非压缩点）
		bool ok() const { return h != nullptr; }
	};
	static bool p256_generate(KeyPair &out);
	// 对 SHA-256 摘要签名，输出 DER(r,s)（BCrypt PAD_NONE 语义）
	static bool p256_sign(BCRYPT_KEY_HANDLE h, const uint8_t digest[32],
	                      std::vector<uint8_t> &der);
	static void p256_free(KeyPair &k);
};

} // namespace vertify
