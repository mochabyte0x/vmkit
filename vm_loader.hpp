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


#pragma once

/*
 vmkit: a header-only, freestanding VM template for IR-bytecode loaders.

 What you get out of the box:
   * Single header. No CRT, no STL allocators, no exceptions, no RTTI.
   * Plays nicely with /NODEFAULTLIB and -nostdlib++.
   * Zero-cost dispatch through a constexpr 256-entry function-pointer table.
   * Adding an opcode means adding a Handler<Op> specialization. No giant
     switch to keep editing every time.

 The pattern in three lines:
   1. Builder emits a sequence of fixed-size Op records, optionally XOR-encrypted.
   2. Loader hands the blob to Vm::execute, which decrypts, decodes, dispatches.
   3. Per-opcode behavior lives in Handler<Op> specializations on your side.

 Usage:
   enum class MyOp : std::uint8_t { Alloc = 0, Write = 1, Exec = 2 };
   struct MyContext { ... whatever state your loader needs ... };

   template<> struct vmkit::Handler<MyOp::Alloc> {
       static void execute(MyContext& ctx, const vmkit::Op<MyOp>& op) noexcept;
   };
   // ... and so on for Write, Exec ...

   vmkit::Vm<MyOp, MyContext, vmkit::DefaultConfig,
             vmkit::OpcodeList<MyOp::Alloc, MyOp::Write, MyOp::Exec>> vm;
   vm.execute(blob_span, ctx, seed);

 One constraint worth knowing: the opcode enum's underlying type must fit in
 a uint8_t (0..255). The dispatch table is exactly 256 entries: same size as
 the opcode reverse map used for randomization ^^.

*/

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace vmkit {

// Op: a single fixed-size IR operation.
// Tune slot counts via template params; default 8x u32 + 4x u64 covers most loaders.
template <typename Opcode, std::size_t U32Slots = 8, std::size_t U64Slots = 4>
struct alignas(8) Op {
    Opcode        opcode;
    std::uint32_t u32[U32Slots];
    std::uint64_t u64[U64Slots];
};

// Handler: primary template, intentionally undefined.
// User specializes once per opcode. A missing specialization for a listed
// opcode is a hard compile error (see static_assert in Vm::dispatch_to).
template <auto Opcode>
struct Handler;

// OpcodeList: pack of opcode values the VM should know how to dispatch.
// Anything not in this list maps to unknown_op (a no-op).
template <auto... Ops>
struct OpcodeList {};

// HasHandler: concept used for compile-time validation.
template <auto Op_, typename Ctx, typename OpT>
concept HasHandler = requires(Ctx& ctx, const OpT& op) {
    Handler<Op_>::execute(ctx, op);
};

// xor_codec: minimal in-place XOR for bytecode and context blobs.
namespace xor_codec {

constexpr void apply(std::span<std::uint8_t>       data,
                     std::span<const std::uint8_t> key) noexcept {
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] ^= key[i % key.size()];
    }
}

} // namespace xor_codec

// api_hash: Jenkins-OAAT with seed rotation, evaluated at compile time.
// Use:  constexpr auto h = vmkit::api_hash::oaat("NtAllocateVirtualMemory");
namespace api_hash {

constexpr std::uint32_t oaat(const char* s, std::uint32_t seed = 1) noexcept {
    std::uint32_t h = 0;
    for (std::size_t i = 0; s[i] != '\0'; ++i) {
        h += static_cast<std::uint8_t>(s[i]);
        h += h << seed;
        h ^= h >> 6;
    }
    h += h << 3;
    h ^= h >> 11;
    h += h << 15;
    return h;
}

} 

// Reverse opcode map: 256-byte table for opcode randomization.
// Builder writes the forward (real -> randomized) map into bytecode;
// runtime applies the inverse here before dispatch.
using OpcodeReverseMap = std::array<std::uint8_t, 256>;

constexpr OpcodeReverseMap identity_reverse_map() noexcept {
    OpcodeReverseMap m{};
    for (std::size_t i = 0; i < 256; ++i) {
        m[i] = static_cast<std::uint8_t>(i);
    }
    return m;
}

// DefaultConfig: disabled-by-default obfuscation flags.
// Inherit and override flags + hooks for the features you want.
struct DefaultConfig {
    // Feature flags
    static constexpr bool opcode_randomization      = false;
    static constexpr bool bytecode_xor_encrypted    = false;
    static constexpr bool per_op_context_encryption = false;

    // Reverse map used iff opcode_randomization is true
    static constexpr OpcodeReverseMap opcode_reverse_map = identity_reverse_map();

    // Hooks: called only when their corresponding flag is true.
    // bytecode_xor_encrypted -> decrypt_bytecode
    static void decrypt_bytecode(std::span<std::uint8_t> /*blob*/,
                                 std::uint32_t /*seed*/) noexcept {}

    // per_op_context_encryption -> {encrypt,decrypt}_context
    template <typename Ctx>
    static void encrypt_context(Ctx& /*ctx*/, std::uint32_t /*op_index*/) noexcept {}

    template <typename Ctx>
    static void decrypt_context(Ctx& /*ctx*/, std::uint32_t /*op_index*/) noexcept {}
};

// Vm: the dispatcher. Specialized on the OpcodeList for per-opcode validation.
template <typename Opcode,
          typename Ctx,
          typename Cfg = DefaultConfig,
          typename Ops = OpcodeList<>>
class Vm;

template <typename Opcode, typename Ctx, typename Cfg, auto... Ops>
class Vm<Opcode, Ctx, Cfg, OpcodeList<Ops...>> {
public:
    using OpType     = Op<Opcode>;
    using Dispatcher = void (*)(Ctx&, const OpType&) noexcept;

    // Execute a (possibly encrypted) bytecode blob.
    // blob is mutable because in-place decryption may rewrite it.
    void execute(std::span<std::uint8_t> blob,
                 Ctx&                    ctx,
                 std::uint32_t           seed = 0) const noexcept {
        if constexpr (Cfg::bytecode_xor_encrypted) {
            Cfg::decrypt_bytecode(blob, seed);
        }

        const std::size_t count = blob.size() / sizeof(OpType);
        const auto*       ops   = reinterpret_cast<const OpType*>(blob.data());

        for (std::size_t i = 0; i < count; ++i) {
            if constexpr (Cfg::per_op_context_encryption) {
                if (i > 0) {
                    Cfg::decrypt_context(ctx, static_cast<std::uint32_t>(i));
                }
            }

            const OpType& op  = ops[i];
            std::uint8_t  raw = static_cast<std::uint8_t>(op.opcode);
            if constexpr (Cfg::opcode_randomization) {
                raw = Cfg::opcode_reverse_map[raw];
            }

            dispatch_table[raw](ctx, op);

            if constexpr (Cfg::per_op_context_encryption) {
                Cfg::encrypt_context(ctx, static_cast<std::uint32_t>(i + 1));
            }
        }

        if constexpr (Cfg::per_op_context_encryption) {
            if (count > 0) {
                Cfg::decrypt_context(ctx, static_cast<std::uint32_t>(count));
            }
        }
    }

private:
    template <auto Op_>
    static void dispatch_to(Ctx& ctx, const OpType& op) noexcept {
        static_assert(HasHandler<Op_, Ctx, OpType>, "vmkit: missing Handler<Op> specialization for a listed opcode");
        Handler<Op_>::execute(ctx, op);
    }

    static void unknown_op(Ctx& /*ctx*/, const OpType& /*op*/) noexcept {}

    static constexpr std::array<Dispatcher, 256> build_table() noexcept {
        std::array<Dispatcher, 256> t{};
        for (auto& f : t) {
            f = &unknown_op;
        }
        ((t[static_cast<std::size_t>(Ops)] = &dispatch_to<Ops>), ...);
        return t;
    }

    static constexpr std::array<Dispatcher, 256> dispatch_table = build_table();
};

} 
