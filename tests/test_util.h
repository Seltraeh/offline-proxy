/**
* @file test_util.h
* @brief Minimal check macros for the content provider tests (no framework dependency).
*/
#pragma once

#include <stdio.h>
#include <string>

namespace t {

struct Counters { int passed = 0; int failed = 0; int skipped = 0; };
inline Counters& counters() { static Counters c; return c; }

inline void Check(bool ok, const char* expr, const char* file, int line, const std::string& detail = std::string())
{
    if (ok)
        ++counters().passed;
    else
    {
        ++counters().failed;
        printf("FAIL  %s:%d  %s%s%s\n", file, line, expr, detail.empty() ? "" : "  -- ", detail.c_str());
    }
}

inline void Skip(const char* what, const char* why)
{
    ++counters().skipped;
    printf("SKIP  %s  (%s)\n", what, why);
}

} // namespace t

#define CHECK(cond) ::t::Check(!!(cond), #cond, __FILE__, __LINE__)
#define CHECK_MSG(cond, msg) ::t::Check(!!(cond), #cond, __FILE__, __LINE__, (msg))
#define CHECK_EQ(a, b) ::t::Check((a) == (b), #a " == " #b, __FILE__, __LINE__)
