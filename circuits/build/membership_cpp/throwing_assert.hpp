// throwing_assert.hpp - Replace assert() with an exception-throwing version
#ifndef THROWING_ASSERT_HPP
#define THROWING_ASSERT_HPP

#include <stdexcept>
#include <string>

// Undefine the standard assert if it exists
#ifdef assert
#undef assert
#endif

// Define a throwing assert
#define assert(expr) \
    do { \
        if (!(expr)) { \
            throw std::runtime_error( \
                std::string("Assertion failed: ") + #expr + \
                " at " + __FILE__ + ":" + std::to_string(__LINE__) \
            ); \
        } \
    } while(0)

#endif // THROWING_ASSERT_HPP
