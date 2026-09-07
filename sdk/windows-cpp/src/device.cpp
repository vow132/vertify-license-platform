#include "device.h"
#include "util.h"
#include "cng.h"
#include <ntstatus.h>
#ifndef BCRYPT_ECDSA_ALGORITHM
#define BCRYPT_ECDSA_ALGORITHM L"ECDSA"
#endif
#ifndef BCRYPT_PAD_NONE
#define BCRYPT_PAD_NONE ((LPCWSTR)NULL)
#endif
#ifndef NCRYPTBUFFER_BCRYPT_PUBLIC_BLOB
#define NCRYPTBUFFER_BCRYPT_PUBLIC_BLOB ((LPCWSTR)0x00000001) // MinGW 头缺失；值与 WinSDK 一致
#endif

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")

namespace vertify {

void DeviceKey::set_pub(const std::vector<uint8_t> &pub) {
	pub_ = pub;
	pubB64_ = b64url_encode(pub.data(), pub.size());
}

bool DeviceKey::try_tpm() {
	NCRYPT_PROV_HANDLE prov = 0;
	// 微软平台加密提供程序 = TPM backed（Windows 10+，需设备具备 TPM 2.0）
	SECURITY_STATUS st = NCryptOpenStorageProvider(&prov, MS_PLATFORM_CRYPTO_PROVIDER, 0);
	if (st != ERROR_SUCCESS) return false;

	const wchar_t *keyName = L"VertifyDeviceKey";
	NCRYPT_KEY_HANDLE key = 0;
	st = NCryptOpenKey(prov, &key, keyName, 0, 0);
	if (st != ERROR_SUCCESS) {
		st = NCryptCreatePersistedKey(prov, &key, NCRYPT_ECDSA_P256_ALGORITHM, keyName, 0, 0);
		if (st == ERROR_SUCCESS) {
			DWORD len = 256;
			NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, (PBYTE)&len, sizeof(len), 0);
			st = NCryptFinalizeKey(key, 0);
		}
	}
	if (st != ERROR_SUCCESS) {
		NCryptFreeObject(prov);
		return false;
	}

	ULONG size = 0;
	st = NCryptExportKey(key, 0, NCRYPTBUFFER_BCRYPT_PUBLIC_BLOB, nullptr, nullptr, 0, &size, 0);
	if (st == ERROR_SUCCESS) {
		std::vector<uint8_t> blob(size);
		st = NCryptExportKey(key, 0, NCRYPTBUFFER_BCRYPT_PUBLIC_BLOB, nullptr,
		                     blob.data(), size, &size, 0);
		if (st == ERROR_SUCCESS && size >= 8 + 64) {
			pub_.assign(65, 0x04);
			memcpy(pub_.data() + 1, blob.data() + 8, 64);
		}
	}
	if (pub_.size() != 65) {
		NCryptFreeObject(key);
		NCryptFreeObject(prov);
		return false;
	}
	tpmKey_ = key;
	NCryptFreeObject(prov); // key 对 provider 持有独立引用
	backend_ = TPM;
	pubB64_ = b64url_encode(pub_.data(), pub_.size());
	return true;
}

bool DeviceKey::try_software() {
	Cng::KeyPair kp;
	if (!Cng::p256_generate(kp)) return false;
	swKey_ = kp.h;
	set_pub(kp.pub);
	backend_ = SOFTWARE;
	return true;
}

bool DeviceKey::generate_or_load() {
	if (try_tpm()) return true;
	return try_software();
}

bool DeviceKey::restore_software(const std::vector<uint8_t> &privBlob, const std::string &pubB64) {
	BCRYPT_ALG_HANDLE alg = nullptr;
	if (BCryptOpenAlgorithmProvider(&alg, L"ECDSA_P256", nullptr, 0) != 0)
		return false;
	BCRYPT_KEY_HANDLE hk = nullptr;
	NTSTATUS st = BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPRIVATE_BLOB, &hk,
	                                  (PUCHAR)privBlob.data(), (ULONG)privBlob.size(), 0);
	BCryptCloseAlgorithmProvider(alg, 0);
	if (st != 0) return false;
	swKey_ = hk;
	backend_ = SOFTWARE;
	pubB64_ = pubB64;
	std::vector<uint8_t> pub;
	if (b64url_decode(pubB64, pub) && pub.size() == 65) pub_ = pub;
	return true;
}

void DeviceKey::clear() {
	if (tpmKey_) {
		NCryptFreeObject(tpmKey_);
		tpmKey_ = 0;
	}
	if (swKey_) {
		BCryptDestroyKey(swKey_);
		swKey_ = nullptr;
	}
	backend_ = NONE;
	pub_.clear();
	pubB64_.clear();
}

bool DeviceKey::export_private_blob(std::vector<uint8_t> &blob) const {
	if (backend_ != SOFTWARE || !swKey_) return false;
	ULONG size = 0;
	NTSTATUS st = BCryptExportKey(swKey_, nullptr, BCRYPT_ECCPRIVATE_BLOB,
	                              nullptr, 0, &size, 0);
	if (st != 0) return false;
	blob.resize(size);
	st = BCryptExportKey(swKey_, nullptr, BCRYPT_ECCPRIVATE_BLOB, blob.data(), size, &size, 0);
	blob.resize(size);
	return st == 0;
}

bool DeviceKey::sign_digest(const uint8_t digest[32], std::vector<uint8_t> &der) {
	if (backend_ == TPM && tpmKey_) {
		ULONG size = 0;
		SECURITY_STATUS st = NCryptSignHash(tpmKey_, nullptr, (PBYTE)digest, 32,
		                                    nullptr, 0, &size, 0);
		if (st != ERROR_SUCCESS) return false;
		der.resize(size);
		st = NCryptSignHash(tpmKey_, nullptr, (PBYTE)digest, 32, der.data(), size, &size, 0);
		der.resize(size);
		return st == ERROR_SUCCESS;
	}
	if (backend_ == SOFTWARE && swKey_) {
		return Cng::p256_sign(swKey_, digest, der);
	}
	return false;
}

} // namespace vertify
