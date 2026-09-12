// 自检入口（与 demo 复用同一 SDK 库）。
#include <lumistar/license_sdk.h>
#include <stdio.h>

int main() {
	vft_err_t r = lumistar_selftest();
	printf("selftest: %s\n", r == VFT_OK ? "PASS" : "FAIL");
	return r == VFT_OK ? 0 : 1;
}
