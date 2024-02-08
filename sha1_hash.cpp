#include <format>
#include <iostream>
#include <span>
#include "sha1.hpp"

using namespace math_nerd;

auto main(int argc, char **argv) -> int
{
    static_assert(sha1::hash( "The quick brown fox jumps over the lazy dog" ) == "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
    static_assert(sha1::hash( "huh" )                                         == "5a9213b1f721b28fad5d446d00c74cbf6e107439");

    if ( argc > 1 )
    {
        for ( auto const &str : std::span(argv + 1, argv + argc) )
        {
            std::cout << std::format( "SHA-1 of {}: {}\n", str, sha1::hash( str ) );
        }
    }

    return EXIT_SUCCESS;
}
