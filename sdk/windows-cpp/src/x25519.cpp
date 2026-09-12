// X25519（RFC 7748）—— 复用 orlp fe.c 域算术（p = 2^255-19，与 Ed25519 同域）
// 的蒙哥马利阶梯实现。正确性由 RFC 7748 官方向量保证（见 lumistar_selftest）。

#include <string.h>
#include <stdint.h>

extern "C" {
#include "../third_party/ed25519/src/fe.h"
}

namespace lumistar {

static void clamp_scalar(unsigned char k[32]) {
	k[0] &= 248;
	k[31] &= 127;
	k[31] |= 64;
}

// a24 * E：RFC 7748 推荐 a24=121665
static void fe_mul_a24(fe out, const fe e) {
	fe a24;
	unsigned char a24b[32];
	memset(a24b, 0, sizeof(a24b));
	a24b[0] = 121665 & 0xff;
	a24b[1] = (121665 >> 8) & 0xff;
	a24b[2] = (121665 >> 16) & 0xff;
	fe_frombytes(a24, a24b);
	fe_mul(out, e, a24);
}

// RFC 7748 §5 X25519 标量乘
void x25519_scalarmult(unsigned char out[32],
                       const unsigned char scalar[32],
                       const unsigned char u_in[32]) {
	unsigned char k[32];
	unsigned char u[32];
	memcpy(k, scalar, 32);
	memcpy(u, u_in, 32);
	clamp_scalar(k);
	u[31] &= 127;

	fe x1, x2, z2, x3, z3;
	fe a, aa, b, bb, e, c, d, da, cb, t0;

	fe_frombytes(x1, u);
	fe_1(x2);
	fe_0(z2);
	fe_copy(x3, x1);
	fe_1(z3);

	unsigned int swap = 0;
	for (int pos = 254; pos >= 0; pos--) {
		unsigned int kt = (k[pos >> 3] >> (pos & 7)) & 1U;
		swap ^= kt;
		fe_cswap(x2, x3, swap);
		fe_cswap(z2, z3, swap);
		swap = kt;

		fe_add(a, x2, z2);
		fe_sq(aa, a);
		fe_sub(b, x2, z2);
		fe_sq(bb, b);
		fe_sub(e, aa, bb);
		fe_add(c, x3, z3);
		fe_sub(d, x3, z3);
		fe_mul(da, d, a);
		fe_mul(cb, c, b);

		fe_add(t0, da, cb);
		fe_sq(x3, t0);
		fe_sub(t0, da, cb);
		fe_sq(t0, t0);
		fe_mul(z3, x1, t0);

		fe_mul(x2, aa, bb);
		fe_mul_a24(t0, e);
		fe_add(t0, aa, t0);
		fe_mul(z2, e, t0);
	}
	fe_cswap(x2, x3, swap);
	fe_cswap(z2, z3, swap);

	fe_invert(z2, z2);
	fe_mul(x2, x2, z2);
	fe_tobytes(out, x2);
}

// 公钥 = 标量乘基点 9
void x25519_public(unsigned char pub[32], const unsigned char scalar[32]) {
	const unsigned char base[32] = {9};
	x25519_scalarmult(pub, scalar, base);
}

} // namespace lumistar
