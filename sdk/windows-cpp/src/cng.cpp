#include "cng.h"
#include <ntstatus.h>

// MinGW（w64devkit）头文件缺失的声明与常量（bcrypt.dll 实际提供）：
#ifndef BCRYPT_PAD_NONE
#define BCRYPT_PAD_NONE ((LPCWSTR)NULL)
#endif

#pragma comment(lib, "bcrypt.lib")

namespace lumistar {

std::vector<uint8_t> Cng::random(size_t n) {
	std::vector<uint8_t> out(n);
	BCryptGenRandom(nullptr, out.data(), (ULONG)out.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	return out;
}

std::vector<uint8_t> Cng::sha256(const uint8_t *data, size_t len) {
	std::vector<uint8_t> out(32);
	BCRYPT_ALG_HANDLE alg = nullptr;
	BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
	BCryptHash(alg, nullptr, 0, (PUCHAR)data, (ULONG)len, out.data(), (ULONG)out.size());
	BCryptCloseAlgorithmProvider(alg, 0);
	return out;
}

std::vector<uint8_t> Cng::hmac_sha256(const uint8_t *key, size_t keyLen,
                                      const uint8_t *data, size_t len) {
	std::vector<uint8_t> out(32);
	BCRYPT_ALG_HANDLE alg = nullptr;
	BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	BCryptHash(alg, (PUCHAR)key, (ULONG)keyLen, (PUCHAR)data, (ULONG)len, out.data(), (ULONG)out.size());
	BCryptCloseAlgorithmProvider(alg, 0);
	return out;
}

// RFC 5869：PRK = HMAC(salt, IKM)；OKM = T(1..N)（T(i)=HMAC(PRK, T(i-1)|info|i)）
std::vector<uint8_t> Cng::hkdf_sha256(const uint8_t *salt, size_t saltLen,
                                      const uint8_t *info, size_t infoLen,
                                      size_t outLen,
                                      const uint8_t *ikm, size_t ikmLen) {
	auto prk = hmac_sha256(salt, saltLen, ikm, ikmLen);
	std::vector<uint8_t> okm;
	std::vector<uint8_t> t;
	uint8_t counter = 1;
	while (okm.size() < outLen) {
		std::vector<uint8_t> msg = t;
		msg.insert(msg.end(), info, info + infoLen);
		msg.push_back(counter++);
		t = hmac_sha256(prk.data(), prk.size(), msg.data(), msg.size());
		okm.insert(okm.end(), t.begin(), t.end());
	}
	okm.resize(outLen);
	return okm;
}

bool Cng::aes_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                          const uint8_t *pt, size_t ptLen,
                          const uint8_t *aad, size_t aadLen,
                          std::vector<uint8_t> &out) {
	BCRYPT_ALG_HANDLE alg = nullptr;
	NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
	if (st != 0) return false;
	wchar_t mode[] = BCRYPT_CHAIN_MODE_GCM;
	BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)mode, sizeof(mode), 0);

	BCRYPT_KEY_HANDLE hk = nullptr;
	st = BCryptGenerateSymmetricKey(alg, &hk, nullptr, 0, (PUCHAR)key, 32, 0);
	if (st != 0) {
		BCryptCloseAlgorithmProvider(alg, 0);
		return false;
	}

	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
	memset(&info, 0, sizeof(info));
	info.cbSize = sizeof(info);
	info.dwInfoVersion = 1;
	uint8_t tag[16];
	info.pbNonce = (PUCHAR)nonce;
	info.cbNonce = 12;
	info.pbTag = tag;
	info.cbTag = sizeof(tag);
	info.pbAuthData = (PUCHAR)aad;
	info.cbAuthData = (ULONG)aadLen;

	out.assign(ptLen + sizeof(tag), 0);
	ULONG written = 0;
	st = BCryptEncrypt(hk, (PUCHAR)pt, (ULONG)ptLen, &info, nullptr, 0,
	                   out.data(), (ULONG)ptLen, &written, 0);
	memcpy(out.data() + ptLen, tag, sizeof(tag));

	BCryptDestroyKey(hk);
	BCryptCloseAlgorithmProvider(alg, 0);
	return st == 0;
}

// ===== ECDSA P-256 =====

bool Cng::p256_generate(KeyPair &out) {
	BCRYPT_ALG_HANDLE alg = nullptr;
	if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) != 0)
		return false;
	NTSTATUS st = BCryptGenerateKeyPair(alg, &out.h, 256, 0);
	if (st == 0) st = BCryptFinalizeKeyPair(out.h, 0);
	if (st == 0) {
		// 导出非压缩点：BCRYPT_ECCKEY_BLOB{magic,cbKey=32}+X+Y
		ULONG size = 0;
		st = BCryptExportKey(out.h, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &size, 0);
		if (st == 0) {
			std::vector<uint8_t> blob(size);
			st = BCryptExportKey(out.h, nullptr, BCRYPT_ECCPUBLIC_BLOB, blob.data(), size, &size, 0);
			if (st == 0 && size >= 8 + 64) {
				out.pub.assign(65, 0x04);
				memcpy(out.pub.data() + 1, blob.data() + 8, 64);
			}
		}
	}
	BCryptCloseAlgorithmProvider(alg, 0);
	if (st != 0) {
		if (out.h) BCryptDestroyKey(out.h);
		out.h = nullptr;
		return false;
	}
	return true;
}

bool Cng::p256_sign(BCRYPT_KEY_HANDLE h, const uint8_t digest[32],
                    std::vector<uint8_t> &der) {
	ULONG size = 0;
	NTSTATUS st = BCryptSignHash(h, nullptr, (PUCHAR)digest, 32,
	                             nullptr, 0, &size, 0);
	if (st != 0) return false;
	der.resize(size);
	st = BCryptSignHash(h, nullptr, (PUCHAR)digest, 32,
	                    der.data(), size, &size, 0);
	der.resize(size);
	return st == 0;
}

void Cng::p256_free(KeyPair &k) {
	if (k.h) {
		BCryptDestroyKey(k.h);
		k.h = nullptr;
	}
}

} // namespace lumistar
