#pragma once
#ifndef MATH_NERD_SHA1_HPP
#define MATH_NERD_SHA1_HPP
#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

/** \file sha1.hpp
    \brief SHA-1 Hash Implementation - Educational purposes only, DO NOT USE!
*/

namespace math_nerd
{
    namespace sha1
    {
        using Word = std::uint32_t;
        using Byte = std::uint8_t;

        constexpr std::size_t WORD_BYTES  { sizeof( Word ) };
        constexpr std::size_t WORD_BITS   { WORD_BYTES *  8 };
        constexpr std::size_t BLOCK_BITS  {  WORD_BITS * 16 };
        constexpr std::size_t BLOCK_BYTES { BLOCK_BITS /  8 };
        constexpr std::size_t BLOCK_WORDS { BLOCK_BYTES / WORD_BYTES };
        constexpr std::size_t ROUND_COUNT { 80 };
        constexpr std::size_t DIGEST_SIZE {  5 };
        constexpr std::size_t STAGE_ROUNDS{ 20 };

        constexpr std::array DEFAULT_DIGEST{ 0x67452301u, 0xEFCDAB89u, 0x98BADCFEU, 0x10325476u, 0xC3D2E1F0u };
        constexpr std::array ROUND_CONSTANT{ 0x5A827999u, 0x6ED9EBA1u, 0x8F1BBCDCu, 0xCA62C1D6u };

        enum Digest
        {
            A,
            B,
            C,
            D,
            E
        };

        [[nodiscard]]
        constexpr auto left_rotate( Word const word, std::size_t const shift )
        {
            return (word << shift) | (word >> (WORD_BITS - shift));
        }

        [[nodiscard]]
        constexpr auto pad( std::string_view input )
        {
            std::size_t padded_size{ input.size() - (input.size() % BLOCK_BYTES)};

            if ( input.size() % BLOCK_BYTES < BLOCK_BYTES - 8 )
            {
                padded_size += BLOCK_BYTES;
            }
            else
            {
                padded_size += 2 * BLOCK_BYTES;
            }

            std::vector<Byte> byte_vector( padded_size );

            std::copy( std::begin( input ), std::end( input ), std::begin( byte_vector ) );

            byte_vector[input.size()] = static_cast<Byte>(0x80);

            for ( auto i{ input.size() + 1 }; i < padded_size - 8; ++i )
            {
                byte_vector[i] = static_cast<Byte>(0x0);
            }

            std::uint64_t bitsize{ input.size() * 8 };

            for ( auto i{ 0u }; i < 8; ++i )
            {
                byte_vector[padded_size - 8 + i] =
                    static_cast<Byte>((bitsize >> (BLOCK_BYTES - 8 * (i + 1))) & 0xFF);
            }

            return byte_vector;
        }

        [[nodiscard]]
        constexpr auto make_schedule( std::vector<Byte> const &input, std::size_t block )
        {
            std::array<Word, ROUND_COUNT> schedule{};

            // Building the block.
            for ( auto word{ 0u }; word < BLOCK_WORDS; ++word )
            {
                schedule[word] = 0;

                for ( auto byte{ 0u }; byte < WORD_BYTES; ++byte )
                {
                    schedule[word] = (schedule[word] << 8) +
                                      input[block * BLOCK_BYTES +
                                             word *  WORD_BYTES +
                                             byte];
                }
            }

            // Build the rest of the schedule.
            for ( auto word{ BLOCK_WORDS }; word < ROUND_COUNT; ++word )
            {
                schedule[word] = left_rotate( schedule[word - 16]
                                            ^ schedule[word - 14]
                                            ^ schedule[word - 8]
                                            ^ schedule[word - 3], 1 );
            }

            return schedule;
        }

        constexpr auto process( std::array<Word, ROUND_COUNT> const &schedule,
                                std::array<Word, DIGEST_SIZE>       &digest,
                                std::size_t const                    round )
        {
            constexpr auto f1 = []( Word const B, Word const C, Word const D )
            {
                return (B & C) | ((~B) & D);
            };

            constexpr auto f2 = []( Word const B, Word const C, Word const D )
            {
                return B ^ C ^ D;
            };

            constexpr auto f3 = []( Word const B, Word const C, Word const D )
            {
                return (B & C) | (B & D) | (C & D);
                // Compiler optimizes to (B & (C | D)) | (C & D) for us.
            };

            auto newE{ digest[E] + schedule[round] + left_rotate(digest[A], 5) };

            switch ( round / STAGE_ROUNDS )
            {
                case 0:
                {
                    newE += f1( digest[B], digest[C], digest[D] ) + ROUND_CONSTANT[0];
                    break;
                }

                case 1:
                {
                    newE += f2( digest[B], digest[C], digest[D] ) + ROUND_CONSTANT[1];
                    break;
                }

                case 2:
                {
                    newE += f3( digest[B], digest[C], digest[D] ) + ROUND_CONSTANT[2];
                    break;
                }

                case 3:
                {
                    newE += f2( digest[B], digest[C], digest[D] ) + ROUND_CONSTANT[3];
                    break;
                }
            }

            digest[E] = digest[D];
            digest[D] = digest[C];
            digest[C] = left_rotate( digest[B], 30 );
            digest[B] = digest[A];
            digest[A] = newE;
        }

        [[nodiscard]]
        constexpr auto nibble_to_hex( Word nibble ) -> char
        {
            return ((nibble < 10) ? ('0' + nibble) : ('a' + (nibble - 10)));
        }

        [[nodiscard]]
        constexpr auto word_to_hex( Word const word )
        {
            std::string hex{};

            for ( auto shift{ 0u }; shift <= WORD_BITS - 4; shift += 4 )
            {
                hex += nibble_to_hex( (word >> (WORD_BITS - 4 - shift)) & 0xF);
            }

            return hex;
        }

        [[nodiscard]]
        constexpr auto digest_to_hex( std::array<Word, DIGEST_SIZE> const &digest )
        {
            std::string hex{};

            for ( auto const word : digest )
            {
                hex += word_to_hex( word );
            }

            return hex;
        }

        [[nodiscard]]
        constexpr auto hash( std::string input )
        {
            auto padded_input{ pad( input ) };

            auto block_count{ padded_input.size() / BLOCK_BYTES };

            auto digest{ DEFAULT_DIGEST };

            for ( auto i{ 0u }; i < block_count; ++i )
            {
                std::array<Word, ROUND_COUNT> message_schedule{ make_schedule(padded_input, i) };

                auto temp_digest{ digest };

                for ( auto round{ 0u }; round < ROUND_COUNT; ++round )
                {
                    process( message_schedule, digest, round );
                }

                constexpr auto const add = []( auto first, auto second )
                {
                    return first + second;
                };

                std::transform( std::begin(digest), std::end(digest), std::begin(temp_digest),
                                std::begin(digest), add);
            }

            return digest_to_hex( digest );
        }

    } // namespace sha1

} // namespace math_nerd

#endif // MATH_NERD_SHA1_HPP
