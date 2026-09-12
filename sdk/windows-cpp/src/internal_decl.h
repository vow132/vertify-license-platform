// SDK 内部跨翻译单元声明。
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace lumistar {

// x25519.cpp
void x25519_scalarmult(unsigned char out[32], const unsigned char scalar[32],
                       const unsigned char u_in[32]);
void x25519_public(unsigned char pub[32], const unsigned char scalar[32]);

} // namespace lumistar
