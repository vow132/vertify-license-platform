// 最小接入示例：初始化 → 激活 → 心跳 → 功能门禁。
#include <vertify/license_sdk.h>
#include <stdio.h>
#include <windows.h>
#include <string.h>

static void on_state(vft_state_t state, void *user) {
	(void)user;
	const char *s = "unknown";
	switch (state) {
	case VFT_STATE_ACTIVE: s = "ACTIVE"; break;
	case VFT_STATE_STALE: s = "STALE（心跳失联）"; break;
	case VFT_STATE_REVOKED: s = "REVOKED（服务端已处置）"; break;
	case VFT_STATE_ERROR: s = "ERROR"; break;
	default: s = "NOT_ACTIVATED"; break;
	}
	printf("[state] %s\n", s);
}

int main(int argc, char **argv) {
	setvbuf(stdout, NULL, _IONBF, 0);
	if (vertify_selftest() != VFT_OK) {
		printf("selftest FAILED\n");
		return 1;
	}
	printf("selftest ok (X25519/Ed25519/AES-GCM)\n");

	const char *server = argc > 1 ? argv[1] : "https://127.0.0.1:8080";
	const char *card = argc > 2 ? argv[2] : "";
	bool insecure_dev_only = argc > 3 && strcmp(argv[3], "--insecure-dev-only") == 0;

	vft_config cfg = {};
	cfg.server_url = server;
	cfg.product_code = "AUXPRO";
	cfg.client_version = "1.0.0";
	cfg.insecure_skip_tls_verify = insecure_dev_only ? 1 : 0;
	if (insecure_dev_only) {
		printf("WARNING: TLS certificate verification is disabled for local development only.\n");
	}
	// cfg.storage_dir = "D:\\data\\vertify";  // 默认 %PROGRAMDATA%\\Vertify\\AUXPRO

	vertify::License lic;
	vft_err_t ierr = lic.init(cfg);
	if (ierr != VFT_OK) {
		printf("init failed: %s (code=%d)\n", vertify_err_str(ierr), ierr);
		return 1;
	}

	if (card[0]) {
		vft_activation_result r = {};
		vft_err_t err = lic.activate(card, &r);
		if (err == VFT_OK) {
			printf("activated: license=%s device=%s\n", r.license_id, r.device_id);
		} else {
			printf("activate failed: %s\n", vertify_err_str(err));
			return 1;
		}
	} else if (lic.state() == VFT_STATE_NOT_ACTIVATED) {
		printf("usage: activate_demo <server_url> <card> [--insecure-dev-only]\n");
		return 1;
	}

	lic.start_heartbeat(on_state, nullptr);

	// 业务功能门禁示例（每次调用实时验签，无本地放宽）
	for (int i = 0; i < 3; i++) {
		printf("feature[aimbot]=%d feature[esp]=%d lease_remaining=%llds\n",
		       lic.has_feature("aimbot"), lic.has_feature("esp"),
		       (long long)lic.lease_remaining());
		Sleep(2000);
	}

	lic.stop_heartbeat();
	return 0;
}
