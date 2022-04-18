#pragma once
#include <cstdint>
#include <iosfwd>
#include <string>

namespace haval
{

    namespace detail
    {

        // a HAVAL word = 32 bits
        using word_t = std::uint32_t;

        // current version number
        constexpr word_t version = 1;

        struct haval_context {
            // number of bits in a message
            word_t count[2];
            // current state of fingerprint
            word_t fingerprint[8];
            // buffer for a 32-word block
            word_t block[32];
            // unhashed chars (No.<128)
            std::uint8_t remainder[32 * 4];
        };

    } // namespace detail

    template<unsigned int pass_cnt, unsigned int fpt_len>
    class haval
    {
        static_assert(pass_cnt >= 3, "");
        static_assert(pass_cnt <= 5, "");

        static_assert(fpt_len >= 128, "");
        static_assert(fpt_len <= 256, "");
        static_assert(fpt_len % 32 == 0, "");

    public:
        using size_type = std::size_t;

        static constexpr size_type result_size = fpt_len >> 3;

    public:
        // initialization
        void start();
        // updating routine
        void update(const void* data, size_type data_len);
        // finalization
        void end_to(void* data);
        std::string end();

        // hash a block
        static std::string hash(const void* data, size_type data_len);
        // hash a string
        static std::string hash(const std::string& data);
        // hash a stream
        static std::string hash(std::istream& stream);

    private:
        void hash_block();

    private:
        detail::haval_context m_context;
    };

} // namespace haval