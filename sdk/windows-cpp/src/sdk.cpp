// SDK 核心实现 + 全部 C API。
#include "util.h"
#include "cng.h"
#include "http.h"
#include "device.h"
#include "store.h"
#include <lumistar/license_sdk.h>
#include "internal_decl.h"
extern "C" {
#include "../third_party/ed25519/src/ed25519.h"
}
#include <bcrypt.h>
#include <string.h>
#include <time.h>
#include <mutex>
#include <map>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <sstream>

namespace lumistar {

// ===== 指纹分量采集（只上传 SHA-256 摘要，不含原始序列号） =====

static std::string reg_sz(HKEY root, const char *path, const char *value) {
	HKEY k;
	if (RegOpenKeyExA(root, path, 0, KEY_READ, &k) != ERROR_SUCCESS) return "";
	char buf[256] = {};
	DWORD size = sizeof(buf);
	RegQueryValueExA(k, value, nullptr, nullptr, (BYTE *)buf, &size);
	RegCloseKey(k);
	return std::string(buf);
}

static std::vector<std::string> collect_components() {
	std::vector<std::string> comps;
	auto add = [&](const std::string &raw) {
		auto h = Cng::sha256((const uint8_t *)raw.data(), raw.size());
		comps.push_back(to_hex(h.data(), h.size()));
	};
	add(reg_sz(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid"));
	DWORD volSerial = 0;
	char fs[32] = {};
	GetVolumeInformationA("C:\\", nullptr, 0, &volSerial, nullptr, nullptr, fs, sizeof(fs));
	add(std::to_string(volSerial) + "|" + fs);
	add(reg_sz(HKEY_LOCAL_MACHINE,
	           "SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "ComputerHardwareId"));
	return comps;
}

// ===== 租约验签 =====

struct LeaseClaims {
	std::string lic, dev, prod, status, jti;
	std::vector<std::string> feat;
	int64_t iat = 0, exp = 0, lex = 0, pol = 0, hbi = 0, grace = 0;
};

bool verify_lease(const std::string &token,
                         const std::map<std::string, std::vector<uint8_t>> &pins,
                         LeaseClaims &out) {
	if (token.rfind("VLT1.", 0) != 0) return false;
	size_t p2 = token.find('.', 5);
	if (p2 == std::string::npos) return false;
	std::string payloadB64 = token.substr(5, p2 - 5);
	std::string sigB64 = token.substr(p2 + 1);

	std::vector<uint8_t> payload, sig;
	if (!b64url_decode(payloadB64, payload) || !b64url_decode(sigB64, sig)) return false;
	if (sig.size() != 64) return false;

	JsonValue j;
	if (!Json::parse(std::string(payload.begin(), payload.end()), j)) return false;
	std::string kid = j.get_str("kid");
	auto it = pins.find(kid);
	if (it == pins.end()) return false;

	// 关键：对传输中的第二段原始字节验签（与服务端签发字节完全一致）
	if (ed25519_verify(sig.data(), (const unsigned char *)payloadB64.data(),
	                   payloadB64.size(), it->second.data()) != 1)
		return false;

	out.lic = j.get_str("lic");
	out.dev = j.get_str("dev");
	out.prod = j.get_str("prod");
	out.status = j.get_str("st");
	out.jti = j.get_str("jti");
	out.iat = j.get_i64("iat");
	out.exp = j.get_i64("exp");
	out.lex = j.get_i64("lex");
	out.pol = j.get_i64("pol");
	out.hbi = j.get_i64("hbi", 60);
	out.grace = j.get_i64("grace");
	auto *f = j.find("feat");
	if (f && f->type == JsonValue::ARR)
		for (auto &x : f->arr)
			if (x.type == JsonValue::STR) out.feat.push_back(x.str);
	return true;
}

// ===== 设备签名头（PoP） =====

std::string device_auth_header(DeviceKey &key, const std::string &method,
                                      const std::string &path, const std::string &body,
                                      int64_t ts, const std::string &nonce, int64_t seq) {
	std::string msg = "v1|" + method + "|" + path + "|" + std::to_string(ts) + "|" +
	                  nonce + "|" + std::to_string(seq) + "|";
	auto bh = Cng::sha256((const uint8_t *)body.data(), body.size());
	msg.append((const char *)bh.data(), bh.size());
	auto digest = Cng::sha256((const uint8_t *)msg.data(), msg.size());
	std::vector<uint8_t> der;
	if (!key.sign_digest(digest.data(), der)) return "";
	if (getenv("VFT_DEBUG")) {
		if (getenv("VFT_DEBUG")) fprintf(stderr, "[dbg] pub=%s\n", key.pub_b64().c_str());
		if (getenv("VFT_DEBUG")) fprintf(stderr, "[dbg] digest=%s\n", to_hex(digest.data(), 32).c_str());
		if (getenv("VFT_DEBUG")) fprintf(stderr, "[dbg] sig=%s\n", b64url_encode(der.data(), der.size()).c_str());
	}
	return "v1 pub=" + key.pub_b64() + " ts=" + std::to_string(ts) +
	       " nonce=" + nonce + " seq=" + std::to_string(seq) +
	       " sig=" + lumistar::b64url_encode(der.data(), der.size());
}

// ===== 信封封装（X25519 + HKDF + AES-256-GCM，与 envelope.go 对应） =====

vft_err_t map_server_error(long status, const std::string &code) {
	if (code == "CARD_NOT_FOUND") return VFT_E_CARD_NOT_FOUND;
	if (code == "CARD_INVALID") return VFT_E_CARD_INVALID;
	if (code == "CARD_FROZEN") return VFT_E_CARD_FROZEN;
	if (code == "CARD_REVOKED") return VFT_E_CARD_REVOKED;
	if (code == "CARD_VOIDED") return VFT_E_CARD_VOIDED;
	if (code == "CARD_DEPLETED") return VFT_E_CARD_DEPLETED;
	if (code == "CARD_NOT_USABLE") return VFT_E_CARD_NOT_FOUND; // 服务端泛化码
	if (code == "LICENSE_FROZEN") return VFT_E_LICENSE_FROZEN;
	if (code == "LICENSE_REVOKED") return VFT_E_LICENSE_REVOKED;
	if (code == "LICENSE_VOIDED") return VFT_E_LICENSE_REVOKED;
	if (code == "LICENSE_EXPIRED") return VFT_E_LICENSE_EXPIRED;
	if (code == "DEVICE_LIMIT") return VFT_E_DEVICE_LIMIT;
	if (code == "CONCURRENT_LIMIT") return VFT_E_CONCURRENT_LIMIT;
	if (code == "DEVICE_NOT_FOUND" || code == "DEVICE_UNBOUND") return VFT_E_DEVICE_UNBOUND;
	if (code == "REPLAY_DETECTED" || code == "SEQ_REGRESSION") return VFT_E_REPLAY;
	if (code == "VERSION_TOO_OLD") return VFT_E_VERSION_TOO_OLD;
	if (code == "RATE_LIMITED") return VFT_E_RATE_LIMITED;
	if (code == "BANNED") return VFT_E_BANNED;
	return VFT_E_INTERNAL;
}

static bool seal_envelope(const std::string &kid, const std::string &serverPubB64,
                          const std::string &purpose, const std::string &plaintext,
                          std::string &outJson) {
	std::vector<uint8_t> spk;
	if (!b64url_decode(serverPubB64, spk) || spk.size() != 32) return false;

	uint8_t scalar[32];
	auto rnd = Cng::random(32);
	memcpy(scalar, rnd.data(), 32);
	scalar[0] &= 248; scalar[31] &= 127; scalar[31] |= 64;

	uint8_t epk[32], shared[32];
	x25519_public(epk, scalar);
	x25519_scalarmult(shared, scalar, spk.data());

	std::vector<uint8_t> salt(epk, epk + 32);
	salt.insert(salt.end(), spk.begin(), spk.end());
	const char *info = "vertify-envelope-v1";
	auto key = Cng::hkdf_sha256(salt.data(), salt.size(), (const uint8_t *)info, strlen(info),
	                            32, shared, 32);

	std::string aad = std::string("vertify-envelope-v1|") + kid + "|A256GCM|purpose=" + purpose;
	auto nonce = Cng::random(12);
	std::vector<uint8_t> ct;
	bool ok = Cng::aes_gcm_encrypt(key.data(), nonce.data(),
	                               (const uint8_t *)plaintext.data(), plaintext.size(),
	                               (const uint8_t *)aad.data(), aad.size(), ct);
	memset(scalar, 0, sizeof(scalar));
	memset(shared, 0, sizeof(shared));
	if (!ok) return false;

	std::ostringstream o;
	o << "{\"kid\":\"" << kid << "\",\"alg\":\"A256GCM\","
	  << "\"epk\":\"" << b64url_encode(epk, 32) << "\","
	  << "\"nonce\":\"" << b64url_encode(nonce.data(), 12) << "\","
	  << "\"ct\":\"" << b64url_encode(ct.data(), ct.size()) << "\"}";
	outJson = o.str();
	return true;
}

// ===== 实现 =====

struct SdkImpl {
	vft_config cfg{};
	std::string dir;
	SdkState st;
	StateStore store;
	DeviceKey devKey;
	HttpClient *http = nullptr;
	std::map<std::string, std::vector<uint8_t>> pins;
	int64_t serverDelta = 0;
	std::mutex pinsMu; // 保护 pins/serverDelta（心跳线程与主线程并发访问）

	std::map<std::string, std::vector<uint8_t>> pins_snapshot() {
		std::lock_guard<std::mutex> lk(pinsMu);
		return pins;
	}
	int64_t server_delta() {
		std::lock_guard<std::mutex> lk(pinsMu);
		return serverDelta;
	}
	void set_server_delta(int64_t d) {
		std::lock_guard<std::mutex> lk(pinsMu);
		serverDelta = d;
	}
	std::string activeKexKid;
	std::string activeKexPub;

	std::mutex mu;
	std::thread hbThread;
	std::atomic<bool> hbRun{false};
	std::condition_variable hbCv;
	std::mutex hbMtx;
	vft_state_cb cb = nullptr;
	void *cbUser = nullptr;

		~SdkImpl() {
			hbRun = false;
			hbCv.notify_all();
			if (hbThread.joinable()) hbThread.join();
			delete http;
			devKey.clear();
		}

	bool save_state() { return store.save(dir, st); }

	bool ensure_device_key() {
		// 已有软件私钥（DPAPI 解密后的 blob）→ 恢复
		if (st.backend == "software" && !st.enc_priv.empty() && !st.pub_b64.empty()) {
			std::vector<uint8_t> privBlob;
			if (dpapi_unprotect(st.enc_priv, privBlob) &&
			    devKey.restore_software(privBlob, st.pub_b64)) {
				return true;
			}
		}
		if (!devKey.generate_or_load()) return false;
		st.backend = devKey.backend() == DeviceKey::TPM ? "tpm" : "software";
		st.pub_b64 = devKey.pub_b64();
		if (devKey.backend() == DeviceKey::SOFTWARE) {
			std::vector<uint8_t> blob;
			if (devKey.export_private_blob(blob)) {
				dpapi_protect(blob, st.enc_priv);
			}
		}
		return save_state();
	}

	bool bootstrap(bool mergePins = false) {
		HttpResult r = http->request({"GET", cfg.server_url + std::string("/v1/bootstrap")});
		if (!r.ok()) return false;
		JsonValue j;
		if (!Json::parse(r.body, j)) return false;
		int64_t stime = j.get_i64("server_time");
		set_server_delta(stime - (int64_t)time(nullptr));

		auto *kex = j.find("kex_keys");
		if (!kex || kex->type != JsonValue::ARR) return false;
		for (auto &k : kex->arr) {
			if (k.get_bool("active")) {
				activeKexKid = k.get_str("kid");
				activeKexPub = k.get_str("pub");
			}
		}
		if (activeKexKid.empty()) return false;

		auto *sk = j.find("sign_keys");
		// 信任锚：首次 TOFU 固定；此后仅在「密钥轮换窗口」追加新 kid（只增不减），
		// 任何情况下都不替换既有固定集——被移除的旧公钥在密码学上仍然有效。
		if (st.pinned_sign_keys.empty()) {
			if (sk && sk->type == JsonValue::OBJ) {
				for (auto &kv : sk->obj) {
					st.pinned_sign_keys.push_back(kv.first + "|" + kv.second.str);
				}
				save_state();
			}
		} else if (mergePins && sk && sk->type == JsonValue::OBJ) {
			bool changed = false;
			for (auto &kv : sk->obj) {
				std::string entry = kv.first + "|" + kv.second.str;
				bool exists = false;
				for (auto &e : st.pinned_sign_keys)
					if (e == entry) { exists = true; break; }
				if (!exists) {
					st.pinned_sign_keys.push_back(entry);
					changed = true;
				}
			}
			if (changed) save_state();
		}
		// 若宿主显式提供 pin 集合（最强模式），以宿主为准
		if (cfg.pin_pubkeys && cfg.pin_pubkeys_len > 0) {
			st.pinned_sign_keys.clear();
			for (size_t i = 0; i < cfg.pin_pubkeys_len; i++) {
				uint8_t id[8] = {};
				memcpy(id, cfg.pin_pubkeys + i * 32, 8);
				st.pinned_sign_keys.push_back("host" + to_hex(id, 8) + "|" +
				                              b64url_encode(cfg.pin_pubkeys + i * 32, 32));
			}
		}
		rebuild_pins();
		return true;
	}

	void rebuild_pins() {
		std::lock_guard<std::mutex> lk(pinsMu);
		pins.clear();
		for (auto &e : st.pinned_sign_keys) {
			auto bar = e.find('|');
			if (bar == std::string::npos) continue;
			std::vector<uint8_t> pub;
			if (b64url_decode(e.substr(bar + 1), pub) && pub.size() == 32)
				pins[e.substr(0, bar)] = pub;
		}
	}

	std::string server_url() const { return std::string(cfg.server_url); }

	// 统一 POST：自动带设备签名头
	vft_err_t post_signed(const std::string &path, std::string &body, std::string &resp,
	                      bool bumpSeq) {
		int64_t ts = (int64_t)time(nullptr) + server_delta();
		std::string nonce = lumistar::gen_nonce_b64();
		int64_t seq = bumpSeq ? ++st.seq : 0;
		std::string hdr = lumistar::device_auth_header(devKey, "POST", path, body, ts, nonce, seq);
		if (hdr.empty()) return VFT_E_CRYPTO;
		if (getenv("VFT_DEBUG")) fprintf(stderr, "[dbg] hdr=%s\n", hdr.c_str());

		HttpRequest req;
		req.method = "POST";
		req.url = server_url() + path;
		req.body = body;
		req.headers.emplace_back("X-Vft-Device-Auth", hdr);
		req.headers.emplace_back("Content-Type", "application/json");
		HttpResult r = http->request(req);

		if (r.status == 0) return VFT_E_NETWORK; // 网络失败：序列号已消耗但服务端要求严格递增？
		// 注意：seq 在本地已自增；网络失败后下一次请求会用更大 seq，满足单调性
		if (!r.ok()) {
			if (getenv("VFT_DEBUG")) fprintf(stderr, "[dbg] http %ld body=%.200s\n", r.status, r.body.c_str());
			JsonValue j;
			std::string code;
			if (Json::parse(r.body, j)) code = j.find("error") ? j.find("error")->get_str("code") : j.get_str("code");
			return map_server_error(r.status, code);
		}
		resp = r.body;
		if (bumpSeq) save_state();
		return VFT_OK;
	}

	// 从激活/心跳响应提取并验证租约，更新本地状态。
	// 密钥轮换窗口：若本地仍持有有效的旧租约（信任链连续），而新租约由未固定的
	// 新 kid 签发，则从 bootstrap 追加新 kid 后重试验证一次（只增不减）。
	vft_err_t adopt_lease(const std::string &respJson) {
		JsonValue j;
		if (!Json::parse(respJson, j)) return VFT_E_BAD_RESPONSE;
		std::string lease = j.get_str("lease");
		lumistar::LeaseClaims claims;
		auto pinsSnap = pins_snapshot();
		if (!lumistar::verify_lease(lease, pinsSnap, claims)) {
			if (holds_valid_lease()) {
				bootstrap(true);
				pinsSnap = pins_snapshot();
				if (!lumistar::verify_lease(lease, pinsSnap, claims)) return VFT_E_BAD_RESPONSE;
			} else {
				return VFT_E_BAD_RESPONSE;
			}
		}
		mu.lock();
		st.lease = lease;
		st.license_id = claims.lic;
		st.device_id = claims.dev;
		st.lease_exp = claims.exp;
		st.license_exp = claims.lex;
		st.hb_interval = claims.hbi > 0 ? claims.hbi : 60;
		mu.unlock();
		save_state();
		return VFT_OK;
	}

	// 本地缓存的租约是否仍是有效签名（与状态无关，仅验签+时间）
	bool holds_valid_lease() {
		mu.lock();
		std::string lease = st.lease;
		mu.unlock();
		if (lease.empty()) return false;
		lumistar::LeaseClaims c;
		if (!lumistar::verify_lease(lease, pins_snapshot(), c)) return false;
		return ((int64_t)time(nullptr) + server_delta()) <= c.exp;
	}

	vft_state_t current_state() {
		mu.lock();
		std::string lease = st.lease;
		mu.unlock();
		if (lease.empty()) return VFT_STATE_NOT_ACTIVATED;
		lumistar::LeaseClaims claims;
		if (!lumistar::verify_lease(lease, pins_snapshot(), claims)) return VFT_STATE_ERROR;
		if (claims.status != "active") return VFT_STATE_REVOKED;
		int64_t now = (int64_t)time(nullptr) + server_delta();
		if (claims.lex > 0 && now > claims.lex) return VFT_STATE_REVOKED;
		if (now > claims.exp + claims.grace) return VFT_STATE_STALE;
		return VFT_STATE_ACTIVE;
	}

	void heartbeat_loop() {
		int64_t attempt = 0;
		while (hbRun) {
			std::string devID, ver;
			{
				std::lock_guard<std::mutex> lk(mu);
				devID = st.device_id;
				ver = cfg.client_version ? cfg.client_version : "";
			}
			// 先立即心跳（应用重启/网络恢复后立刻续租，不让用户干等一个间隔）
			if (!devID.empty()) {
				std::string body = "{\"device_id\":\"" + devID + "\",\"client_version\":\"" + ver + "\"}";
				std::string resp;
				vft_err_t err = post_signed("/v1/heartbeat", body, resp, true);
					if (err == VFT_OK) {
						err = adopt_lease(resp);
						attempt = 0;
						vft_state_cb stateCb = nullptr;
						void *stateUser = nullptr;
						{
							std::lock_guard<std::mutex> cbLock(hbMtx);
							stateCb = cb;
							stateUser = cbUser;
						}
						if (stateCb) stateCb(VFT_STATE_ACTIVE, stateUser);
					} else if (err == VFT_E_NETWORK || err == VFT_E_BAD_RESPONSE) {
						attempt++;
						vft_state_cb stateCb = nullptr;
						void *stateUser = nullptr;
						{
							std::lock_guard<std::mutex> cbLock(hbMtx);
							stateCb = cb;
							stateUser = cbUser;
						}
						if (attempt >= 2 && stateCb) stateCb(VFT_STATE_STALE, stateUser);
					} else {
					// 服务端明确拒绝（冻结/吊销/名额等）：立即生效
					attempt = 0;
						vft_state_cb stateCb = nullptr;
						void *stateUser = nullptr;
						{
							std::lock_guard<std::mutex> cbLock(hbMtx);
							stateCb = cb;
							stateUser = cbUser;
						}
						if (stateCb) stateCb(VFT_STATE_REVOKED, stateUser);
				}
			}
			// 计算下次等待：间隔 ±10% 抖动；失败退避 1x..5x
			int64_t interval = 60;
			{
				std::lock_guard<std::mutex> lk(mu);
				interval = st.hb_interval > 0 ? st.hb_interval : 60;
			}
			auto jitter = Cng::random(1);
			int64_t jitterPct = jitter.empty() ? 0 : (jitter[0] % 20);
			int64_t waitSec = interval * (100 + jitterPct) / 100;
			if (attempt > 0) {
				waitSec = interval * (attempt > 5 ? 5 : attempt);
			}
			std::unique_lock<std::mutex> lk(hbMtx);
			hbCv.wait_for(lk, std::chrono::seconds(waitSec));
		}
	}
};

// ===== C API（全局作用域，C 链接） =====
} // namespace lumistar

struct vft_handle_t_ {
	lumistar::SdkImpl *impl;
};

extern "C" {

typedef lumistar::SdkImpl SdkImpl;
typedef lumistar::HttpClient HttpClient;
typedef lumistar::Cng Cng;
// 供 C API 使用的命名空间内工具（同 TU 内可见）
static lumistar::SdkImpl *vft_impl_of(vft_handle_t h) { return h ? ((vft_handle_t_ *)h)->impl : nullptr; }

static std::string s_err_ok = "ok";

const char *lumistar_err_str(vft_err_t err) {
	switch (err) {
	case VFT_OK: return "ok";
	case VFT_E_INVALID_ARG: return "invalid argument";
	case VFT_E_NETWORK: return "network failure";
	case VFT_E_BAD_RESPONSE: return "untrusted server response";
	case VFT_E_CARD_INVALID: return "invalid card format";
	case VFT_E_CARD_NOT_FOUND: return "card not found";
	case VFT_E_CARD_FROZEN: return "card frozen";
	case VFT_E_CARD_REVOKED: return "card revoked";
	case VFT_E_CARD_VOIDED: return "card voided";
	case VFT_E_CARD_DEPLETED: return "card depleted";
	case VFT_E_LICENSE_FROZEN: return "license frozen";
	case VFT_E_LICENSE_REVOKED: return "license revoked";
	case VFT_E_LICENSE_EXPIRED: return "license expired";
	case VFT_E_DEVICE_LIMIT: return "device limit reached";
	case VFT_E_CONCURRENT_LIMIT: return "concurrent limit reached";
	case VFT_E_DEVICE_UNBOUND: return "device unbound";
	case VFT_E_REPLAY: return "replay rejected";
	case VFT_E_VERSION_TOO_OLD: return "client version too old";
	case VFT_E_RATE_LIMITED: return "rate limited";
	case VFT_E_BANNED: return "banned";
	case VFT_E_CRYPTO: return "local crypto error";
	case VFT_E_STORAGE: return "local storage error";
	default: return "internal error";
	}
}

vft_err_t lumistar_init(const vft_config *cfg, vft_handle_t *out) {
	if (!cfg || !cfg->server_url || !cfg->product_code || !out) return VFT_E_INVALID_ARG;
	if (strncmp(cfg->server_url, "https://", 8) != 0) return VFT_E_INVALID_ARG; // 禁明文
	auto *impl = new SdkImpl();
	impl->cfg = *cfg;
	if (cfg->storage_dir && cfg->storage_dir[0]) {
		impl->dir = cfg->storage_dir;
	} else {
		char p[MAX_PATH] = {};
		GetEnvironmentVariableA("APPDATA", p, sizeof(p));
		impl->dir = std::string(p) + "\\Lumistar\\" + cfg->product_code;
	}
	impl->http = new HttpClient(cfg->server_url, cfg->insecure_skip_tls_verify != 0);
	if (!impl->http->valid()) {
		delete impl;
		return VFT_E_INVALID_ARG;
	}
	impl->store.load(impl->dir, impl->st);
	if (getenv("VFT_DEBUG")) fprintf(stderr, "[dbg] store loaded\n");
	if (!impl->ensure_device_key()) {
		if (getenv("VFT_DEBUG")) fprintf(stderr, "[dbg] ensure FAILED\n");
		delete impl;
		return VFT_E_CRYPTO;
	}
	if (getenv("VFT_DEBUG")) fprintf(stderr, "[dbg] key ok, bootstrap\n");
	if (!impl->bootstrap()) {
		if (getenv("VFT_DEBUG")) fprintf(stderr, "[dbg] bootstrap FAILED\n");
		// 无网络时可继续用已缓存的租约（过期即 STALE）
		impl->rebuild_pins();
		if (impl->pins_snapshot().empty()) {
			delete impl;
			return VFT_E_NETWORK;
		}
	}
	*out = new vft_handle_t_{impl};
	return VFT_OK;
}

void lumistar_shutdown(vft_handle_t h) {
	if (!h) return;
	auto *impl = ((vft_handle_t_ *)h)->impl;
	impl->hbRun = false;
	impl->hbCv.notify_all();
	if (impl->hbThread.joinable()) {
		impl->hbThread.join();
	}
	delete impl;
	delete ((vft_handle_t_ *)h);
}

static std::string json_escape(const std::string &s) {
	std::string out;
	out.reserve(s.size() + 8);
	for (unsigned char c : s) {
		switch (c) {
		case '"': out += "\\\""; break;
		case '\\': out += "\\\\"; break;
		case '\n': out += "\\n"; break;
		case '\r': out += "\\r"; break;
		case '\t': out += "\\t"; break;
		default: if (c < 0x20) { char b[7]; snprintf(b, sizeof(b), "\\u%04x", c); out += b; } else out += char(c);
		}
	}
	return out;
}

extern "C" vft_err_t lumistar_activate(vft_handle_t h, const char *card, vft_activation_result *out) {
	if (!h || !card) return VFT_E_INVALID_ARG;
	auto *impl = ((vft_handle_t_ *)h)->impl;
	if (!impl->bootstrap()) return VFT_E_NETWORK;

	auto comps = lumistar::collect_components();
	std::ostringstream payload;
	payload << "{\"card\":\"" << json_escape(card) << "\",\"components\":[";
	for (size_t i = 0; i < comps.size(); i++) {
		if (i) payload << ",";
		payload << "\"" << json_escape(comps[i]) << "\"";
	}
	payload << "],\"device_pub\":\"" << impl->devKey.pub_b64() << "\","
	        << "\"pub_kty\":\"p256\",\"trust_level\":\""
		        << (impl->st.backend == "tpm" ? "tpm" : "software") << "\","
		        << "\"client_version\":\"" << json_escape(impl->cfg.client_version ? impl->cfg.client_version : "") << "\"}";

	std::string env;
	if (!lumistar::seal_envelope(impl->activeKexKid, impl->activeKexPub, "activate", payload.str(), env))
		return VFT_E_CRYPTO;

	std::string empty = "";
	std::string resp;
	vft_err_t err = impl->post_signed("/v1/activate", env, resp, false);
	if (err != VFT_OK) return err;
	err = impl->adopt_lease(resp);
	if (err != VFT_OK) return err;

	if (out) {
		memset(out, 0, sizeof(*out));
		strncpy(out->license_id, impl->st.license_id.c_str(), sizeof(out->license_id) - 1);
		strncpy(out->device_id, impl->st.device_id.c_str(), sizeof(out->device_id) - 1);
		out->lease_exp = impl->st.lease_exp;
		out->license_exp = impl->st.license_exp;
	}
	return VFT_OK;
}

vft_err_t lumistar_redeem(vft_handle_t h, const char *renewal_card) {
	if (!h || !renewal_card) return VFT_E_INVALID_ARG;
	auto *impl = ((vft_handle_t_ *)h)->impl;
	if (!impl->bootstrap()) return VFT_E_NETWORK;
	std::string payload = std::string("{\"card\":\"") + renewal_card + "\"}";
	std::string env;
	if (!lumistar::seal_envelope(impl->activeKexKid, impl->activeKexPub, "redeem", payload, env))
		return VFT_E_CRYPTO;
	std::string resp;
	vft_err_t err = impl->post_signed("/v1/redeem", env, resp, true);
	if (err != VFT_OK) return err;
	return impl->adopt_lease(resp);
}

vft_err_t lumistar_deactivate(vft_handle_t h) {
	if (!h) return VFT_E_INVALID_ARG;
	auto *impl = ((vft_handle_t_ *)h)->impl;
	std::string body = "{\"device_id\":\"" + impl->st.device_id + "\"}";
	std::string resp;
	vft_err_t err = impl->post_signed("/v1/deactivate", body, resp, true);
	if (err == VFT_OK) {
		impl->st.license_id.clear();
		impl->st.device_id.clear();
		impl->st.lease.clear();
		impl->save_state();
	}
	return err;
}

vft_err_t lumistar_start_heartbeat(vft_handle_t h, vft_state_cb cb, void *user) {
	if (!h) return VFT_E_INVALID_ARG;
	auto *impl = ((vft_handle_t_ *)h)->impl;
	std::lock_guard<std::mutex> lk(impl->hbMtx);
	if (impl->hbRun) return VFT_E_INTERNAL;
	impl->cb = cb;
	impl->cbUser = user;
	impl->hbRun = true;
	impl->hbThread = std::thread([impl]() { impl->heartbeat_loop(); });
	return VFT_OK;
}

vft_err_t lumistar_stop_heartbeat(vft_handle_t h) {
	if (!h) return VFT_E_INVALID_ARG;
	auto *impl = ((vft_handle_t_ *)h)->impl;
	{
		std::lock_guard<std::mutex> lk(impl->hbMtx);
		if (!impl->hbRun) return VFT_OK;
		impl->hbRun = false;
	}
	impl->hbCv.notify_all();
	if (impl->hbThread.joinable()) impl->hbThread.join();
	return VFT_OK;
}

vft_state_t lumistar_get_state(vft_handle_t h) {
	if (!h) return VFT_STATE_ERROR;
	return ((vft_handle_t_ *)h)->impl->current_state();
}

int lumistar_has_feature(vft_handle_t h, const char *feature) {
	if (!h || !feature) return 0;
	auto *impl = ((vft_handle_t_ *)h)->impl;
	std::string lease;
	std::string dev;
	{
		std::lock_guard<std::mutex> lk(impl->mu);
		lease = impl->st.lease;
		dev = impl->st.device_id;
	}

	lumistar::LeaseClaims claims;
	if (!lumistar::verify_lease(lease, impl->pins_snapshot(), claims)) return 0; // 签名必须有效
	if (claims.status != "active") return 0;                        // 服务端状态
	int64_t now = (int64_t)time(nullptr) + impl->server_delta();
	if (now > claims.exp) return 0;                                 // 租约必须未过期
	if (claims.lex > 0 && now > claims.lex) return 0;               // 许可证必须未过期
	if (claims.dev != dev) return 0;                                // 绑定必须匹配
	for (auto &f : claims.feat)
		if (f == feature) return 1;
	return 0;
}

int64_t lumistar_lease_remaining(vft_handle_t h) {
	if (!h) return 0;
	auto *impl = ((vft_handle_t_ *)h)->impl;
	impl->mu.lock();
	int64_t exp = impl->st.lease_exp;
	impl->mu.unlock();
	return exp - ((int64_t)time(nullptr) + impl->server_delta());
}

vft_err_t lumistar_selftest(void) {
	// RFC 7748 §5.2 测试向量 1
	static const unsigned char scalar1[32] = {
		0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b,
		0x82, 0x46, 0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18,
		0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4};
	static const unsigned char u1[32] = {
		0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4,
		0x24, 0xb1, 0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b,
		0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c};
	static const unsigned char expect1[32] = {
		0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d,
		0xf2, 0x8d, 0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7,
		0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52};
	unsigned char out[32];
	lumistar::x25519_scalarmult(out, scalar1, u1);
	if (memcmp(out, expect1, 32) != 0) return VFT_E_CRYPTO;

	// RFC 7748 §6.1 X25519 端到端向量
	static const unsigned char alicep[32] = {
		0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72,
		0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
		0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a};
	static const unsigned char bobpub[32] = {
		0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2,
		0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
		0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f};
	static const unsigned char shared_expect[32] = {
		0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4,
		0x80, 0x35, 0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
		0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42};
	lumistar::x25519_scalarmult(out, alicep, bobpub);
	if (memcmp(out, shared_expect, 32) != 0) return VFT_E_CRYPTO;

	// RFC 8032 §7.1 Ed25519 验签向量（TEST 1，空消息；与 Go crypto/ed25519 一致性已交叉验证）
	static const unsigned char msg1[1] = {0}; // 空消息
	static const unsigned char pub1[32] = {
		0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3,
		0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
		0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};
	static const unsigned char sig1[64] = {
		0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc,
		0x80, 0x6e, 0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
		0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15,
		0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
		0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
		0x8e, 0x7a, 0x10, 0x0b};
	if (ed25519_verify(sig1, msg1, 0, pub1) != 1) return VFT_E_CRYPTO;

	// AES-GCM 往返
	auto key = Cng::random(32);
	auto nonce = Cng::random(12);
	std::vector<uint8_t> ct;
	if (!Cng::aes_gcm_encrypt(key.data(), nonce.data(), (const uint8_t *)"test", 4,
	                          (const uint8_t *)"aad", 3, ct))
		return VFT_E_CRYPTO;
	if (ct.size() != 4 + 16) return VFT_E_CRYPTO;

	return VFT_OK;
}

} // extern "C"
