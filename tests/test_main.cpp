/**
* @file test_main.cpp
* @brief Content provider tests: pure core, provider semantics against a fake
* broker, hook logic with fake game functions, the getTexture thunk ABI, and
* the signature table against the real supported client binaries (read-only).
*
*   content_provider_tests.exe            (BF_APPX_DIR=<extracted Appx> for the binary checks)
*/
#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <psapi.h>

#include <detours/detours.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <fstream>
#include <functional>
#include <limits>
#include <map>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "cp_core.h"
#include "cp_gate_flash_internal.h"
#include "cp_name_fit_internal.h"
#include "cp_hooks_internal.h"
#include "cp_log.h"
#include "cp_provider.h"
#include "cp_signatures.h"
#include "cp_startup_internal.h"
#include "fake_broker.h"
#include "test_util.h"
#include "../OfflineMod.win32/xml_save_dedupe_logic.h"

using namespace cp;

namespace {

std::vector<uint8_t> Bytes(const std::string& s) { return std::vector<uint8_t>(s.begin(), s.end()); }
std::string Str(const std::vector<uint8_t>& v) { return std::string(v.begin(), v.end()); }
//! A well-formed identity for hand-written index rows ("sha256:" + 64 x c, c a lower-case hex digit).
std::string Dg(char c) { return "sha256:" + std::string(64, c); }

std::vector<uint8_t> RandomBytes(size_t n, unsigned seed)
{
    std::mt19937 rng(seed);
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i)
        v[i] = static_cast<uint8_t>(rng());
    return v;
}

std::vector<uint8_t> ReadFileBytes(const std::string& path)
{
    std::ifstream in(path.c_str(), std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

std::string TempDir()
{
    char buf[MAX_PATH];
    GetTempPathA(MAX_PATH, buf);
    std::string d = std::string(buf) + "offlinemod_content_tests";
    CreateDirectoryA(d.c_str(), nullptr);
    return d;
}

// ------------------------------------------------------------------ names ----

void TestNames()
{
    CHECK(IsSafeFlatName("MapVillage.sam", 14));
    const char* bad[] = { "", ".", "..", "a/b", "a\\b", "C:x", "a\x01" "b", "name.", "name ", "a*b", "a?b", "a|b", "a\"b" };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i)
        CHECK_MSG(!IsSafeFlatName(bad[i], strlen(bad[i])), std::string("accepted ") + bad[i]);
    std::string longName(256, 'a');
    CHECK(!IsSafeFlatName(longName.c_str(), longName.size()));

    const char* protectedNames[] = { "userdefault.xml", "xmlfileprocessor.xml", "ver1_u1xchi09.dat", "abcdef.dat",
                                     "thumbs.db", ".ds_store", "pack.zip", "manifest.json", "x.ini", "y.tmp" };
    for (size_t i = 0; i < sizeof protectedNames / sizeof protectedNames[0]; ++i)
        CHECK_MSG(IsProtectedStateName(protectedNames[i]), protectedNames[i]);
    CHECK(!IsProtectedStateName("mapvillage.sam"));
    CHECK(!IsProtectedStateName("unit_cgg_60956.csv"));
    CHECK(!IsProtectedStateName("unit_anime_60956.png"));

    const std::string prefix = FoldPath("C:\\Users\\X\\AppData\\Local\\Packages\\gumi.BraveFrontier_99p3jr0gh0z6w\\LocalState\\");
    std::string name;
    CHECK(SplitLocalStatePath("c:/users/x/appdata/local/packages/gumi.bravefrontier_99p3jr0gh0z6w/localstate/MapVillage.sam", prefix, name)
          && name == "MapVillage.sam");
    CHECK(SplitLocalStatePath("C:\\Users\\X\\AppData\\Local\\Packages\\gumi.BraveFrontier_99p3jr0gh0z6w\\LocalState\\unit_anime_60956.png", prefix, name)
          && name == "unit_anime_60956.png");
    CHECK(!SplitLocalStatePath("C:\\Users\\X\\AppData\\Local\\Packages\\gumi.BraveFrontier_99p3jr0gh0z6w\\LocalState\\Telemetry\\a.png", prefix, name));
    CHECK(!SplitLocalStatePath("C:\\Users\\X\\AppData\\Local\\Packages\\gumi.BraveFrontier_99p3jr0gh0z6w\\LocalState\\..\\RoamingState\\a.png", prefix, name));
    CHECK(!SplitLocalStatePath("C:\\Users\\X\\AppData\\Local\\Packages\\gumi.BraveFrontier_99p3jr0gh0z6w\\LocalStateX\\a.png", prefix, name));
    CHECK(!SplitLocalStatePath("C:\\Users\\X\\AppData\\Local\\Packages\\gumi.BraveFrontier_99p3jr0gh0z6w\\LocalState\\", prefix, name));
    CHECK(!SplitLocalStatePath("MapVillage.sam", prefix, name));
    CHECK(!SplitLocalStatePath("C:\\Program Files\\WindowsApps\\gumi\\Assets\\Resources\\MapVillage.sam", prefix, name));
}

// -------------------------------------------------------------- byte forms ----

std::string TextMode(const std::string& in)
{
    std::vector<uint8_t> v(in.begin(), in.end());
    const size_t n = MsvcTextModeTranslate(v.empty() ? nullptr : &v[0], v.size(), v.empty() ? nullptr : &v[0]);
    return std::string(v.begin(), v.begin() + n);
}

//! What this test binary's own CRT returns for fopen("r") + fread of the same bytes.
std::string CrtTextRead(const std::string& bytes)
{
    const std::string path = TempDir() + "\\textmode.bin";
    FILE* f = nullptr;
    fopen_s(&f, path.c_str(), "wb");
    fwrite(bytes.data(), 1, bytes.size(), f);
    fclose(f);
    fopen_s(&f, path.c_str(), "r");
    std::string out(bytes.size() + 8, '\0');
    const size_t n = fread(&out[0], 1, out.size(), f);
    fclose(f);
    out.resize(n);
    return out;
}

void TestByteForms()
{
    CHECK_EQ(TextMode("a\r\nb\r\nc"), std::string("a\nb\nc"));
    CHECK_EQ(TextMode("a\rb"), std::string("a\rb"));
    CHECK_EQ(TextMode("a\r"), std::string("a\r"));
    CHECK_EQ(TextMode(std::string("ab\x1a" "cd", 5)), std::string("ab"));
    CHECK_EQ(TextMode("\r\n\r\n"), std::string("\n\n"));
    CHECK_EQ(TextMode(""), std::string());
    const char* samples[] = { "x,y,w,h\r\n1,2,3,4\r\n", "lone\rcr\r\n\rmix\n\r\n", "\r\r\n\n\r", "eof\x1a" "after\r\n" };
    for (size_t i = 0; i < sizeof samples / sizeof samples[0]; ++i)
        CHECK_MSG(TextMode(samples[i]) == CrtTextRead(samples[i]), std::string("text mode differs from the CRT for sample ") + std::to_string(i));
    const std::string real = std::string(BF_TEST_FIXTURES) + "\\..\\..\\..\\BF-WorkingDirRust\\deploy\\game_content\\content\\unit\\cgg\\unit_cgg_60956.csv";
    std::vector<uint8_t> csv = ReadFileBytes(real);
    if (!csv.empty())
        CHECK_MSG(TextMode(Str(csv)) == CrtTextRead(Str(csv)), "unit_cgg_60956.csv: provider text mode == CRT text mode");
    else
        t::Skip("text mode vs CRT on unit_cgg_60956.csv", "server checkout not beside the proxy");

    // FileCrypt: a cached PNG starts 89 51 52 50 (observed in LocalState).
    uint8_t png[8] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
    FileCryptEncode(png, 8);
    CHECK(png[0] == 0x89 && png[1] == 0x51 && png[2] == 0x52 && png[3] == 0x50);
    std::vector<uint8_t> r = RandomBytes(300000, 7), copy = r;   // > 65536: i*i wraps 32 bits
    FileCryptEncode(&copy[0], copy.size());
    CHECK(copy != r);
    FileCryptDecode(&copy[0], copy.size());
    CHECK(copy == r);
    // The game computes the scramble with a 32-bit imul; only the low byte of
    // i*i matters, which a size_t product gives identically.
    bool sameLowByte = true;
    for (uint32_t i = 65530; i < 70000; ++i)
        sameLowByte = sameLowByte && static_cast<uint8_t>(i * i) == static_cast<uint8_t>(static_cast<uint32_t>(i) * static_cast<uint32_t>(i));
    CHECK(sameLowByte);

    const std::string d = Sha256Tag(reinterpret_cast<const uint8_t*>("abc"), 3);
    CHECK_EQ(d, std::string("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

// ---------------------------------------------------------------- protocol ----

void TestProtocol()
{
    StatusInfo st;
    std::string err;
    CHECK(ParseStatus("bfcp 2\nenabled 1\nready 1\nepoch ab\ngeneration 7\nend\n", st, err) && st.enabled && st.ready
          && st.epoch == "ab" && st.generation == 7);
    CHECK(!ParseStatus("bfcp 2\nenabled 1\n", st, err));
    CHECK(!ParseStatus("<html>", st, err));
    CHECK_MSG(!ParseStatus("bfcp 1\nenabled 1\nready 1\nepoch ab\ngeneration 7\nend\n", st, err),
              "a version-1 broker (no identities, no version-bound reads) is declined");

    CHECK(IsDigestTag(Dg('a')) && IsDigestTag(Dg('0')));
    CHECK(!IsDigestTag("sha256:" + std::string(63, 'a')) && !IsDigestTag("sha256:" + std::string(65, 'a')));
    CHECK(!IsDigestTag("sha256:" + std::string(64, 'A')) && !IsDigestTag("sha256:" + std::string(64, 'g')));
    CHECK(!IsDigestTag("sha512:" + std::string(64, 'a')) && !IsDigestTag(""));

    IndexSnapshot snap;
    const std::string good = "bfcp 2\r\nepoch e\r\ngeneration 3\r\nfull 1\r\n"
                             "F\t1\t338618\tMapVillage.sam\tsam/MapVillage/MapVillage.sam\t" + Dg('1') + "\r\n"
                             "C\tmapvillage_111x55.png\ta/MapVillage_111x55.png\tb/MapVillage_111x55.png\r\nend\r\n";
    CHECK(ParseIndex(good, snap, err) && snap.full && snap.generation == 3 && snap.files.size() == 1
          && snap.files["mapvillage.sam"].rel == "sam/MapVillage/MapVillage.sam"
          && snap.files["mapvillage.sam"].digest == Dg('1') && snap.collisions.count("mapvillage_111x55.png"));
    const std::string d = "\t" + Dg('2');
    const std::string rejects[] = {
        "bfcp 2\nepoch e\ngeneration 3\nfull 1\n",                                              // truncated
        "bfcp 2\nepoch e\ngeneration 3\nfull 1\nF\t1\t10\tA.png" + d + "\nend\n",                // short row
        "bfcp 2\nepoch e\ngeneration 3\nfull 1\nF\t1\t10\tA.png\tdir/A.png\nend\n",              // no identity
        "bfcp 2\nepoch e\ngeneration 3\nfull 1\nF\t1\t10\tA.png\tdir/A.png\tsha256:abc\nend\n",  // bad identity
        "bfcp 2\nepoch e\ngeneration 3\nfull 1\nF\t1\t10\tA.png\tdir/A.png" + d + d + "\nend\n", // extra column
        "bfcp 2\nepoch e\ngeneration 3\nfull 1\nF\t1\t10\tA.png\tdir/B.png" + d + "\nend\n",     // name != basename
        "bfcp 2\nepoch e\ngeneration 3\nfull 1\nF\t1\t10\tA.png\t../A.png" + d + "\nend\n",      // traversal
        "bfcp 2\nepoch e\ngeneration 3\nfull 1\nF\t1\t10\tA.png\tdir\\A.png" + d + "\nend\n",    // backslash
        "bfcp 2\nepoch e\ngeneration 3\nfull 1\nF\tx\t10\tA.png\tdir/A.png" + d + "\nend\n",     // bad number
        "bfcp 2\nepoch e\ngeneration 3\nfull 1\nZ\tsomething\nend\n",                            // unknown row
        "bfcp 2\ngeneration 3\nfull 1\nend\n",                                                   // no epoch
        "bfcp 1\nepoch e\ngeneration 3\nfull 1\nend\n",                                          // old protocol
    };
    for (size_t i = 0; i < sizeof rejects / sizeof rejects[0]; ++i)
        CHECK_MSG(!ParseIndex(rejects[i], snap, err), std::string("accepted bad index ") + std::to_string(i));
}

void TestIndexApply()
{
    ContentIndex idx;
    IndexSnapshot full;
    std::string err;
    CHECK(ParseIndex("bfcp 2\nepoch e1\ngeneration 2\nfull 1\n"
                     "F\t1\t3\ta.png\tx/a.png\t" + Dg('a') + "\nF\t2\t4\tb.csv\ty/b.csv\t" + Dg('b')
                     + "\nF\t1\t5\tUserDefault.xml\tz/UserDefault.xml\t" + Dg('c') + "\nend\n", full, err));
    idx.Apply(full);
    IndexEntry e;
    CHECK(idx.Lookup("a.png", &e) == Ownership::Present && e.rel == "x/a.png" && e.digest == Dg('a'));
    CHECK(idx.Lookup("b.csv") == Ownership::Present);
    CHECK_MSG(idx.Lookup("userdefault.xml") == Ownership::NotOwned, "a protected name is never owned, even if listed");
    CHECK(idx.Lookup("c.png") == Ownership::NotOwned);

    IndexSnapshot delta;
    CHECK(ParseIndex("bfcp 2\nepoch e1\ngeneration 4\nfull 0\nF\t4\t3\ta.png\tx/a.png\t" + Dg('d') + "\nD\t3\tb.csv\nend\n",
                     delta, err));
    std::vector<std::string> changed = idx.Apply(delta);
    CHECK(std::find(changed.begin(), changed.end(), "a.png") != changed.end());
    CHECK(std::find(changed.begin(), changed.end(), "b.csv") != changed.end());
    CHECK_MSG(idx.Lookup("b.csv") == Ownership::Absent, "a removed owned name is a tombstone, not handed back to the cache");

    IndexSnapshot coll;
    CHECK(ParseIndex("bfcp 2\nepoch e1\ngeneration 5\nfull 0\nD\t5\ta.png\nC\ta.png\tone/a.png\ttwo/a.png\nend\n", coll, err));
    changed = idx.Apply(coll);
    CHECK(idx.Lookup("a.png") == Ownership::NotOwned);
    CHECK(std::find(changed.begin(), changed.end(), "a.png") != changed.end());

    IndexSnapshot revive;
    CHECK(ParseIndex("bfcp 2\nepoch e1\ngeneration 6\nfull 0\nF\t6\t4\tb.csv\ty/b.csv\t" + Dg('b') + "\nend\n", revive, err));
    idx.Apply(revive);
    CHECK(idx.Lookup("b.csv") == Ownership::Present);

    // Identity alone: same generation, size and path but another digest is a change.
    IndexSnapshot ident;
    CHECK(ParseIndex("bfcp 2\nepoch e1\ngeneration 6\nfull 0\nF\t6\t4\tb.csv\ty/b.csv\t" + Dg('e') + "\nend\n", ident, err));
    changed = idx.Apply(ident);
    CHECK_MSG(std::find(changed.begin(), changed.end(), "b.csv") != changed.end() && idx.Lookup("b.csv", &e) == Ownership::Present
              && e.digest == Dg('e'), "a new identity is a change even with the same generation and size");

    IndexSnapshot restart;
    CHECK(ParseIndex("bfcp 2\nepoch e2\ngeneration 1\nfull 1\nF\t1\t4\tb.csv\ty/b.csv\t" + Dg('e') + "\nend\n", restart, err));
    changed = idx.Apply(restart);
    CHECK_MSG(std::find(changed.begin(), changed.end(), "b.csv") != changed.end(),
              "a broker restart (new epoch) invalidates everything served before");
    CHECK_EQ(idx.Epoch(), std::string("e2"));

    // An incomplete bundle: its members are absent (never handed back to the
    // client cache) until the broker offers them again.
    IndexSnapshot incomplete;
    CHECK(ParseIndex("bfcp 2\nepoch e2\ngeneration 2\nfull 0\n"
                     "X\t2\tb.csv\tbundle u incomplete (missing c.png)\nend\n", incomplete, err));
    changed = idx.Apply(incomplete);
    CHECK(idx.Lookup("b.csv") == Ownership::Absent);
    CHECK(std::find(changed.begin(), changed.end(), "b.csv") != changed.end());
    IndexSnapshot complete;
    CHECK(ParseIndex("bfcp 2\nepoch e2\ngeneration 3\nfull 0\nF\t3\t4\tb.csv\ty/b.csv\t" + Dg('e') + "\nend\n", complete, err));
    idx.Apply(complete);
    CHECK(idx.Lookup("b.csv") == Ownership::Present);
    CHECK(!ParseIndex("bfcp 2\nepoch e2\ngeneration 3\nfull 0\nX\tz\tb.csv\twhy\nend\n", complete, err));
    CHECK(!ParseIndex("bfcp 2\nepoch e2\ngeneration 3\nfull 0\nX\t3\ta/b.csv\twhy\nend\n", complete, err));
}

// -------------------------------------------------------------- byte cache ----

BlobPtr MakeBlob(size_t n, uint8_t fill)
{
    std::shared_ptr<Blob> b = std::make_shared<Blob>();
    b->bytes.assign(n, fill);
    return b;
}

void TestByteCache()
{
    ByteCache c(100, 60);
    c.Put("a", MakeBlob(40, 1));
    c.Put("b", MakeBlob(40, 2));
    CHECK(c.Get("a"));                 // a is now most recent
    c.Put("c", MakeBlob(40, 3));       // evicts b (least recent)
    CHECK(c.Get("a") && !c.Get("b") && c.Get("c"));
    CHECK(c.Bytes() <= 100);
    c.Put("big", MakeBlob(61, 4));     // larger than one entry may be
    CHECK(!c.Get("big"));
    c.Evict("a");
    CHECK(!c.Get("a"));
    std::mt19937 rng(3);
    size_t maxSeen = 0;
    for (int i = 0; i < 2000; ++i)
    {
        c.Put("k" + std::to_string(rng() % 50), MakeBlob(rng() % 60, 9));
        maxSeen = (std::max)(maxSeen, c.Bytes());
    }
    CHECK_MSG(maxSeen <= 100, "the RAM cache never exceeds its byte bound");
    c.Clear();
    CHECK(c.Bytes() == 0 && c.Entries() == 0);

    // Single flight: eight concurrent misses on one path fetch once.
    ByteCache sf(1 << 20, 1 << 20);
    std::atomic<int> fetches(0);
    std::vector<std::thread> threads;
    std::atomic<int> same(0);
    BlobPtr first;
    std::mutex m;
    for (int i = 0; i < 8; ++i)
        threads.push_back(std::thread([&] {
            std::string err;
            BlobPtr b = sf.GetOrFetch("p", [&](std::string&) { ++fetches; Sleep(80); return MakeBlob(10, 5); }, err);
            std::lock_guard<std::mutex> g(m);
            if (!first)
                first = b;
            if (b == first)
                ++same;
        }));
    for (size_t i = 0; i < threads.size(); ++i)
        threads[i].join();
    CHECK_EQ(fetches.load(), 1);
    CHECK_EQ(same.load(), 8);
    CHECK(sf.Coalesced() == 7);

    // A failed fetch is reported to every waiter and not cached.
    std::string err;
    BlobPtr bad = sf.GetOrFetch("q", [&](std::string& e) { e = "boom"; return BlobPtr(); }, err);
    CHECK(!bad && err == "boom");
    int calls = 0;
    sf.GetOrFetch("q", [&](std::string&) { ++calls; return MakeBlob(1, 1); }, err);
    CHECK_EQ(calls, 1);

    // Scene tokens: a fetch that completes after the token moved on still
    // answers its callers (including a waiter that joined it) but is not
    // cached; the same key fetched under the current token is.
    ByteCache tc(1 << 20, 1 << 20);
    tc.SetToken(1);
    CHECK(tc.GetOrFetch("k1", [&](std::string&) { return MakeBlob(5, 1); }, err, nullptr, 1) && tc.Get("k1"));
    HANDLE started = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    BlobPtr late, joined;
    std::thread leader([&] {
        std::string e;
        late = tc.GetOrFetch("k2", [&](std::string&) {
            SetEvent(started);
            WaitForSingleObject(release, 5000);
            return MakeBlob(7, 2);
        }, e, nullptr, 1);
    });
    CHECK(WaitForSingleObject(started, 5000) == WAIT_OBJECT_0);
    const uint64_t coalescedBefore = tc.Coalesced();
    std::thread waiter([&] {
        std::string e;
        joined = tc.GetOrFetch("k2", [&](std::string&) { return MakeBlob(1, 9); }, e, nullptr, 2);
    });
    for (int i = 0; i < 2000 && tc.Coalesced() == coalescedBefore; ++i)
        Sleep(1);
    tc.SetToken(2);
    SetEvent(release);
    leader.join();
    waiter.join();
    CHECK_MSG(late && late->bytes.size() == 7 && joined == late,
              "an outstanding fetch still answers its callers, and a waiter of the same key shares it");
    CHECK_MSG(!tc.Get("k2") && tc.Dropped() == 1, "a fetch that outlived its scene token is not cached");
    CHECK_MSG(tc.GetOrFetch("k2", [&](std::string&) { return MakeBlob(7, 3); }, err, nullptr, 2) && tc.Get("k2"),
              "the same key fetched under the current token is cached");
    tc.SetToken(1);
    CHECK_MSG(tc.GetOrFetch("k4", [&](std::string&) { return MakeBlob(3, 3); }, err, nullptr, 2) && tc.Get("k4"),
              "tokens only move forward");
    CHECK(tc.GetOrFetch("k3", [&](std::string&) { return MakeBlob(2, 4); }, err) && tc.Get("k3"));   // kAnyToken: always cached
    CloseHandle(started);
    CloseHandle(release);
}

// ---------------------------------------------------------------- provider ----

void TestProvider()
{
    FakeBroker b;
    b.Put("sam/MapVillage/MapVillage.sam", Bytes("SAM-v1"));
    b.Put("unit/cgg/unit_cgg_60956.csv", Bytes("a,b\r\nc,d\r\n"));
    b.Put("unit/img/unit_anime_60956.png", Bytes("\x89PNG-anime"));

    {
        FakeBroker off;
        off.enabled = false;
        Provider p(&off, 1 << 20, 1 << 20);
        p.SetAutoStart(false);
        std::string why;
        CHECK(!p.InitializeOnce(why) && p.State() == ProviderState::Dormant);
        CHECK(p.Classify("MapVillage.sam") == Ownership::NotOwned);
    }

    Provider p(&b, 1 << 20, 1 << 20);

    p.SetAutoStart(false);
    std::string why;
    CHECK_MSG(p.InitializeOnce(why), why);
    CHECK(p.Active());
    CHECK(p.Classify("mapvillage.SAM") == Ownership::Present);
    CHECK(p.Classify("Other.png") == Ownership::NotOwned);

    std::vector<uint8_t> out;
    std::string err;
    bool hit = true;
    CHECK(p.Read("MapVillage.sam", out, err, nullptr, &hit) == ReadStatus::Ok && Str(out) == "SAM-v1" && !hit);
    const int callsAfterFirst = b.fileCalls;
    CHECK(p.Read("MapVillage.sam", out, err, nullptr, &hit) == ReadStatus::Ok && hit);
    CHECK_EQ(b.fileCalls.load(), callsAfterFirst);

    // Same-size edit: invisible until the safe point, then visible.
    b.Put("sam/MapVillage/MapVillage.sam", Bytes("SAM-v2"));
    CHECK(p.PollOnce(why) && p.HasPending());
    CHECK(p.Read("MapVillage.sam", out, err) == ReadStatus::Ok && Str(out) == "SAM-v1");
    std::vector<std::string> changed = p.SafePoint("test");
    CHECK(std::find(changed.begin(), changed.end(), "mapvillage.sam") != changed.end());
    CHECK(p.Read("MapVillage.sam", out, err) == ReadStatus::Ok && Str(out) == "SAM-v2");

    // A file first read after the pin whose server copy changed meanwhile: the
    // scene never gets the newer version.  The read fails clearly, a retry in
    // the same scene costs no request, and the next scene change serves it.
    b.Put("unit/img/unit_anime_60956.png", Bytes("\x89PNG-anime2"));
    CHECK_MSG(p.Read("unit_anime_60956.png", out, err) == ReadStatus::Superseded && err.find("pinned") != std::string::npos,
              "a newer server copy is refused inside the pinned scene: " + err);
    const int callsAfterSuperseded = b.fileCalls;
    CHECK(p.Read("unit_anime_60956.png", out, err) == ReadStatus::Superseded);
    CHECK_MSG(b.fileCalls.load() == callsAfterSuperseded, "a version known to be gone is not requested again in the same scene");
    CHECK(p.Stats().superseded >= 2);
    CHECK(p.PollOnce(why));
    p.SafePoint("test");
    CHECK(p.Read("unit_anime_60956.png", out, err) == ReadStatus::Ok && Str(out) == "\x89PNG-anime2");

    // Deletion: a tombstone, with no fallback to the client cache.
    b.Remove("unit/cgg/unit_cgg_60956.csv");
    CHECK(p.PollOnce(why));
    p.SafePoint("test");
    CHECK(p.Classify("unit_cgg_60956.csv") == Ownership::Absent);
    CHECK(p.Read("unit_cgg_60956.csv", out, err) == ReadStatus::Absent);

    // A name that becomes ambiguous is declined.
    b.Collide("unit/img/unit_anime_60956.png");
    CHECK(p.PollOnce(why));
    p.SafePoint("test");
    CHECK(p.Classify("unit_anime_60956.png") == Ownership::NotOwned);

    // Busy answers are retried a bounded number of times.
    b.Put("ui/busy.png", Bytes("busy-ok"));
    CHECK(p.PollOnce(why));
    p.SafePoint("test");
    b.busyAnswers = 2;
    CHECK(p.Read("busy.png", out, err) == ReadStatus::Ok && Str(out) == "busy-ok");
    b.Put("ui/busy2.png", Bytes("never"));
    CHECK(p.PollOnce(why));
    p.SafePoint("test");
    b.busyAnswers = 100;
    const ULONGLONG t0 = GetTickCount64();
    CHECK(p.Read("busy2.png", out, err) == ReadStatus::Error);
    CHECK_MSG(GetTickCount64() - t0 < 2000, "a busy file fails within a bounded time");
    b.busyAnswers = 0;

    // A corrupted transfer is rejected and not cached.
    b.Put("ui/corrupt.png", Bytes("payload"));
    CHECK(p.PollOnce(why));
    p.SafePoint("test");
    b.corruptDigest = true;
    CHECK(p.Read("corrupt.png", out, err) == ReadStatus::Error && err.find("digest") != std::string::npos);
    b.corruptDigest = false;
    CHECK(p.Read("corrupt.png", out, err) == ReadStatus::Ok && Str(out) == "payload");

    // Broker gone: the read fails, and later reads fail fast without stalling.
    b.Put("ui/late.png", Bytes("late"));
    CHECK(p.PollOnce(why));
    p.SafePoint("test");
    b.unreachable = true;
    CHECK(p.Read("late.png", out, err) == ReadStatus::Error);
    const int calls = b.fileCalls;
    CHECK(p.Read("late.png", out, err) == ReadStatus::Error && err.find("fast-fail") != std::string::npos);
    CHECK_EQ(b.fileCalls.load(), calls);
    b.unreachable = false;

    // A broker restart (new epoch) invalidates everything at the next safe point.
    b.Restart();
    CHECK(p.PollOnce(why));
    changed = p.SafePoint("test");
    CHECK(std::find(changed.begin(), changed.end(), "mapvillage.sam") != changed.end());
    CHECK_EQ(p.Epoch(), b.epoch);

    // State names listed by a misbehaving broker are still never owned.
    b.Put("x/UserDefault.xml", Bytes("<x/>"));
    CHECK(p.PollOnce(why));
    p.SafePoint("test");
    CHECK(p.Classify("UserDefault.xml") == Ownership::NotOwned);
}

void TestProviderSwitchedOff()
{
    FakeBroker b;
    b.Put("sam/MapVillage/MapVillage.sam", Bytes("SAM"));
    Provider p(&b, 1 << 20, 1 << 20);
    p.SetAutoStart(false);
    std::string why, err;
    std::vector<uint8_t> out;
    CHECK(p.InitializeOnce(why) && p.Read("MapVillage.sam", out, err) == ReadStatus::Ok);
    b.enabled = false;                       // maintainer's rollback: enabled false + server restart
    CHECK(!p.PollOnce(why));
    CHECK_MSG(p.Active() && p.Classify("MapVillage.sam") == Ownership::Present,
              "the current scene keeps its generation until the next scene change");
    const std::vector<std::string> handedBack = p.SafePoint("rollback");
    CHECK(p.State() == ProviderState::Dormant);
    CHECK_MSG(std::find(handedBack.begin(), handedBack.end(), "mapvillage.sam") != handedBack.end(),
              "served names are reported so the game reloads them from its own cache");
    CHECK(p.Classify("MapVillage.sam") == Ownership::NotOwned);
    CHECK(p.CacheBytes() == 0);

    // A broker answering 503 not-ready (re-indexing after a restart) is not
    // retried as "busy": one call, then the fast-fail window.
    FakeBroker c;
    c.Put("ui/a.png", Bytes("a"));
    Provider q(&c, 1 << 20, 1 << 20);
    q.SetAutoStart(false);
    CHECK(q.InitializeOnce(why));
    c.fileNotReady = true;
    const int before = c.fileCalls;
    CHECK(q.Read("a.png", out, err) == ReadStatus::Error && err.find("not ready") != std::string::npos);
    CHECK_EQ(c.fileCalls.load(), before + 1);
}

void TestProviderConcurrency()
{
    FakeBroker b;
    std::vector<std::string> names;
    std::map<std::string, std::vector<std::string> > versions;
    for (int i = 0; i < 6; ++i)
    {
        const std::string rel = "dir/f" + std::to_string(i) + ".png";
        names.push_back("f" + std::to_string(i) + ".png");
        for (int v = 0; v < 4; ++v)
            versions[names.back()].push_back(std::string(4096, static_cast<char>('A' + v)) + std::to_string(i));
        b.Put(rel, Bytes(versions[names.back()][0]));
    }
    Provider p(&b, 64 * 1024, 64 * 1024);
    p.SetAutoStart(false);
    std::string why;
    CHECK(p.InitializeOnce(why));
    std::atomic<bool> stop(false);
    std::atomic<int> bad(0), ok(0);
    std::vector<std::thread> readers;
    for (int r = 0; r < 6; ++r)
        readers.push_back(std::thread([&, r] {
            std::mt19937 rng(r);
            while (!stop)
            {
                const std::string& n = names[rng() % names.size()];
                std::vector<uint8_t> out;
                std::string err;
                if (p.Read(n, out, err) != ReadStatus::Ok)
                    continue;
                const std::vector<std::string>& vs = versions[n];
                if (std::find(vs.begin(), vs.end(), Str(out)) == vs.end())
                    ++bad;
                else
                    ++ok;
            }
        }));
    for (int round = 1; round < 40; ++round)
    {
        for (size_t i = 0; i < names.size(); ++i)
            b.Put("dir/" + names[i], Bytes(versions[names[i]][round % 4]));
        p.PollOnce(why);
        p.SafePoint("concurrency");
        Sleep(2);
    }
    stop = true;
    for (size_t i = 0; i < readers.size(); ++i)
        readers[i].join();
    CHECK_MSG(bad.load() == 0, "every read returned one complete version, never a mix");
    CHECK(ok.load() > 100);
    CHECK_MSG(p.CacheBytes() <= 64 * 1024, "the cache bound holds under concurrent reads and updates");
}

// ------------------------------------------------------- version binding ----

//! A broker whose first `gate` file requests take their answer, then wait to be released.
class GatedBroker : public FakeBroker
{
public:
    HANDLE captured = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::atomic<int> gate{ 1 };
    ~GatedBroker() { CloseHandle(captured); CloseHandle(release); }
    cp::FetchResult GetFile(const std::string& rel) override
    {
        cp::FetchResult r = FakeBroker::GetFile(rel);
        if (gate.fetch_sub(1) > 0)
        {
            SetEvent(captured);
            WaitForSingleObject(release, 5000);
        }
        return r;
    }
};

struct ReadOutcome
{
    ReadStatus status = ReadStatus::Error;
    std::string bytes, error;
};

std::thread ReadAsync(Provider& p, const char* name, ReadOutcome& out)
{
    return std::thread([&p, name, &out] {
        std::vector<uint8_t> v;
        out.status = p.Read(name, v, out.error);
        out.bytes = Str(v);
    });
}

bool WaitFor(const std::function<bool()>& pred, int ms = 5000)
{
    for (int i = 0; i < ms && !pred(); ++i)
        Sleep(1);
    return pred();
}

/*!
* Reads that overlap a scene change keep their own pinned version to the end
* and never leave it behind for the next scene: outstanding first reads,
* waiters sharing a fetch, a path evicted earlier, a broker restart, a broker
* that ignores the version binding, and an edit reverted within one scene.
*/
void TestVersionBinding()
{
    {   // Outstanding first read + a waiter that joins it, across a scene change.
        GatedBroker b;
        b.Put("ui/a.png", Bytes("old"));
        Provider p(&b, 1 << 20, 1 << 20);
        p.SetAutoStart(false);
        std::string why, err;
        std::vector<uint8_t> out;
        CHECK(p.InitializeOnce(why));
        ReadOutcome first, waiter;
        std::thread t1 = ReadAsync(p, "a.png", first);
        CHECK(WaitForSingleObject(b.captured, 5000) == WAIT_OBJECT_0);
        const uint64_t joinedBefore = p.Stats().coalesced;
        std::thread t2 = ReadAsync(p, "a.png", waiter);
        CHECK_MSG(WaitFor([&] { return p.Stats().coalesced > joinedBefore; }), "a second reader of the same version joins the fetch");
        b.Put("ui/a.png", Bytes("newer"));
        CHECK(p.PollOnce(why));
        const std::vector<std::string> changed = p.SafePoint("binding: in flight");
        CHECK(std::find(changed.begin(), changed.end(), "a.png") != changed.end());
        // The next scene's reader neither joins the old fetch nor waits for it.
        CHECK_MSG(p.Read("a.png", out, err) == ReadStatus::Ok && Str(out) == "newer",
                  "the new scene reads its own version while the old fetch is still outstanding");
        SetEvent(b.release);
        t1.join();
        t2.join();
        CHECK_MSG(first.status == ReadStatus::Ok && first.bytes == "old" && waiter.status == ReadStatus::Ok && waiter.bytes == "old",
                  "the old scene's readers get the version their scene pinned");
        CHECK_MSG(p.Stats().dropped >= 1 && p.CacheBytes() == 5, "the outstanding fetch was delivered, not cached");
        bool hit = false;
        CHECK(p.Read("a.png", out, err, nullptr, &hit) == ReadStatus::Ok && Str(out) == "newer" && hit);
    }
    {   // A path served and evicted earlier, re-read in flight across a scene change.
        GatedBroker b;
        b.gate = 0;
        b.Put("ui/a.png", Bytes("old"));
        b.Put("ui/b.png", Bytes("bbb"));
        Provider p(&b, 3, 3);
        p.SetAutoStart(false);
        std::string why, err;
        std::vector<uint8_t> out;
        CHECK(p.InitializeOnce(why));
        CHECK(p.Read("a.png", out, err) == ReadStatus::Ok && Str(out) == "old");
        CHECK(p.Read("b.png", out, err) == ReadStatus::Ok);   // evicts a.png (3-byte cache)
        b.gate = 1;
        ReadOutcome again;
        std::thread t1 = ReadAsync(p, "a.png", again);
        CHECK(WaitForSingleObject(b.captured, 5000) == WAIT_OBJECT_0);
        b.Put("ui/a.png", Bytes("new"));
        CHECK(p.PollOnce(why));
        p.SafePoint("binding: evicted");
        SetEvent(b.release);
        t1.join();
        CHECK(again.status == ReadStatus::Ok && again.bytes == "old");
        CHECK_MSG(p.Read("a.png", out, err) == ReadStatus::Ok && Str(out) == "new",
                  "eviction plus a late completion never resurrect the old version");
    }
    {   // Broker restart (new epoch, other bytes) overlapping the adoption.
        GatedBroker b;
        b.Put("ui/a.png", Bytes("old"));
        Provider p(&b, 1 << 20, 1 << 20);
        p.SetAutoStart(false);
        std::string why, err;
        std::vector<uint8_t> out;
        CHECK(p.InitializeOnce(why));
        ReadOutcome inFlight;
        std::thread t1 = ReadAsync(p, "a.png", inFlight);
        CHECK(WaitForSingleObject(b.captured, 5000) == WAIT_OBJECT_0);
        b.Put("ui/a.png", Bytes("newer"));
        b.Restart();
        CHECK(p.PollOnce(why));
        const std::vector<std::string> changed = p.SafePoint("binding: restart");
        CHECK(std::find(changed.begin(), changed.end(), "a.png") != changed.end() && p.Epoch() == b.epoch);
        CHECK(p.Read("a.png", out, err) == ReadStatus::Ok && Str(out) == "newer");
        SetEvent(b.release);
        t1.join();
        CHECK_MSG(inFlight.status != ReadStatus::Ok || inFlight.bytes == "old", "the pre-restart read never gets the new bytes");
        bool hit = false;
        CHECK_MSG(p.Read("a.png", out, err, nullptr, &hit) == ReadStatus::Ok && Str(out) == "newer" && hit && p.CacheBytes() == 5,
                  "only the new epoch's version is cached");
    }
    {   // A broker that ignores the version binding still cannot mix versions.
        FakeBroker b;
        b.honorVersion = false;
        b.Put("ui/a.png", Bytes("old"));
        Provider p(&b, 1 << 20, 1 << 20);
        p.SetAutoStart(false);
        std::string why, err;
        std::vector<uint8_t> out;
        CHECK(p.InitializeOnce(why));
        b.Put("ui/a.png", Bytes("new"));
        CHECK_MSG(p.Read("a.png", out, err) == ReadStatus::Superseded && err.find("another version") != std::string::npos,
                  "bytes are checked against the pinned identity, not the response's own digest: " + err);
        CHECK(p.CacheBytes() == 0);
    }
    {   // An edit reverted within one scene: the pinned version is back, so it is served.
        FakeBroker b;
        b.Put("ui/a.png", Bytes("old"));
        Provider p(&b, 1 << 20, 1 << 20);
        p.SetAutoStart(false);
        std::string why, err;
        std::vector<uint8_t> out;
        CHECK(p.InitializeOnce(why));
        b.Put("ui/a.png", Bytes("tmp"));
        b.Put("ui/a.png", Bytes("old"));
        CHECK(p.Read("a.png", out, err) == ReadStatus::Ok && Str(out) == "old");
    }
}

// ----------------------------------------------------------- hook logic ----

namespace fake {
int originalGetFileData = 0, originalIsFileExist = 0, originalExists = 0, originalDownloaded = 0;
int originalFopen = 0, originalRemove = 0, newCalls = 0, deleteCalls = 0;
std::vector<std::string> removedKeys;
std::string writable;

void* __cdecl New(size_t n) { ++newCalls; return malloc(n); }
void __cdecl Delete(void* p) { ++deleteCalls; free(p); }
void* __cdecl SharedFileUtils() { return reinterpret_cast<void*>(0x1234); }
void* __fastcall GetWritablePath(void*, void*, hooks::MsvcString* r)
{
    memset(r, 0, sizeof *r);
    r->size = static_cast<uint32_t>(writable.size());
    if (writable.size() < 16)
    {
        r->capacity = 15;
        memcpy(r->bx.buf, writable.c_str(), writable.size() + 1);
    }
    else
    {
        r->capacity = static_cast<uint32_t>(writable.size());
        r->bx.ptr = static_cast<char*>(New(writable.size() + 1));
        memcpy(r->bx.ptr, writable.c_str(), writable.size() + 1);
    }
    return r;
}
unsigned char* __fastcall GetFileData(void*, void*, const char*, const char*, unsigned long* size)
{
    ++originalGetFileData;
    *size = 3;
    unsigned char* p = static_cast<unsigned char*>(New(3));
    memcpy(p, "OLD", 3);
    return p;
}
bool __fastcall IsFileExist(void*, void*, const char*) { ++originalIsFileExist; return true; }
bool __fastcall Exists(const hooks::MsvcString*, void*) { ++originalExists; return true; }
bool __fastcall Downloaded(const hooks::MsvcString*, void*) { ++originalDownloaded; return true; }
FILE* __cdecl Fopen(const char*, const char*) { ++originalFopen; return nullptr; }
int __cdecl Remove(const char*) { ++originalRemove; return 0; }
void* __cdecl SharedTextureCache() { return reinterpret_cast<void*>(0x5678); }
void __fastcall RemoveTextureForKey(void*, void*, const char* key) { removedKeys.push_back(key); }
} // namespace fake

hooks::MsvcString MakeString(const std::string& s)
{
    hooks::MsvcString m;
    memset(&m, 0, sizeof m);
    m.size = static_cast<uint32_t>(s.size());
    if (s.size() < 16)
    {
        m.capacity = 15;
        memcpy(m.bx.buf, s.c_str(), s.size() + 1);
    }
    else
    {
        m.capacity = static_cast<uint32_t>(s.size());
        m.bx.ptr = _strdup(s.c_str());
    }
    return m;
}

void SetupEnv(Provider* p, const std::string& writable)
{
    hooks::Env& e = hooks::env();
    e.provider = p;
    e.trueGetFileData = fake::GetFileData;
    e.trueIsFileExist = fake::IsFileExist;
    e.trueExistsLocalFile = fake::Exists;
    e.trueIsFileAlreadyDownloaded = fake::Downloaded;
    e.trueFopen = fake::Fopen;
    e.trueRemove = fake::Remove;
    e.sharedFileUtils = fake::SharedFileUtils;
    e.getWritablePath = fake::GetWritablePath;
    e.sharedTextureCache = fake::SharedTextureCache;
    e.removeTextureForKey = fake::RemoveTextureForKey;
    e.msvcrNew = fake::New;
    e.msvcrDelete = fake::Delete;
    e.encodedReaderReturn[0] = 0x0BADF00D;
    e.encodedReaderReturn[1] = 0x0BADF00E;
    e.prefixKnown = false;
    e.anyThreadMayResolve = true;
    fake::writable = writable;
}

void TestHookLogic()
{
    FakeBroker b;
    b.Put("sam/MapVillage/MapVillage.sam", Bytes("MAS.framed"));
    b.Put("unit/cgg/unit_cgg_60956.csv", Bytes("1,2\r\n3,4\r\n"));
    b.Put("unit/img/unit_anime_60956.png", Bytes("\x89PNG\r\n\x1a\nanime"));
    Provider p(&b, 1 << 20, 1 << 20);
    p.SetAutoStart(false);
    std::string why;
    CHECK(p.InitializeOnce(why));
    const std::string ls = "C:\\Users\\T\\AppData\\Local\\Packages\\gumi.BraveFrontier_99p3jr0gh0z6w\\LocalState";
    SetupEnv(&p, ls);   // no trailing separator, longer than 15: heap string path

    const int deletesBefore = fake::deleteCalls;
    CHECK(hooks::EnsurePrefix());
    CHECK_MSG(fake::deleteCalls == deletesBefore + 1, "the writable path string is freed with the game's operator delete");

    unsigned long size = 0;
    const std::string samPath = ls + "\\MapVillage.sam";
    int origBefore = fake::originalGetFileData;
    unsigned char* data = hooks::Hook_GetFileData(nullptr, nullptr, samPath.c_str(), "rb", &size);
    CHECK(data && size == 10 && memcmp(data, "MAS.framed", 10) == 0);
    CHECK_MSG(fake::originalGetFileData == origBefore, "an owned read never touches the client cache");
    fake::Delete(data);

    const std::string csvPath = ls + "/unit_cgg_60956.csv";   // mixed separators, as built by some callers
    data = hooks::Hook_GetFileData(nullptr, nullptr, csvPath.c_str(), "r", &size);
    CHECK(data && std::string(reinterpret_cast<char*>(data), size) == "1,2\n3,4\n");
    fake::Delete(data);

    // The two-image reader always decodes: it gets the cache's encoded form.
    const std::string pngPath = ls + "\\unit_anime_60956.png";
    data = hooks::ServeOwned("unit_anime_60956.png", pngPath.c_str(), "rb", &size, 0x0BADF00D);
    CHECK(data && size == 13);
    std::vector<uint8_t> roundTrip(data, data + size);
    FileCryptDecode(&roundTrip[0], roundTrip.size());
    CHECK(Str(roundTrip) == "\x89PNG\r\n\x1a\nanime" && data[1] == 0x51);
    fake::Delete(data);
    data = hooks::ServeOwned("unit_anime_60956.png", pngPath.c_str(), "rb", &size, 0x12345678);
    CHECK(data && data[1] == 0x50);   // any other reader gets raw bytes
    fake::Delete(data);

    origBefore = fake::originalGetFileData;
    const std::string other = ls + "\\not_owned.png";
    data = hooks::Hook_GetFileData(nullptr, nullptr, other.c_str(), "rb", &size);
    CHECK(fake::originalGetFileData == origBefore + 1 && size == 3);
    fake::Delete(data);
    data = hooks::Hook_GetFileData(nullptr, nullptr, "MapVillage.sam", "rb", &size);   // bundle-relative
    CHECK(fake::originalGetFileData == origBefore + 2);
    fake::Delete(data);
    const std::string state = ls + "\\UserDefault.xml";
    data = hooks::Hook_GetFileData(nullptr, nullptr, state.c_str(), "rb", &size);
    CHECK_MSG(fake::originalGetFileData == origBefore + 3, "client state files always go to the original reader");
    fake::Delete(data);

    hooks::MsvcString owned = MakeString("MapVillage.sam");
    hooks::MsvcString ownedLong = MakeString("unit_anime_60956.png");
    hooks::MsvcString notOwned = MakeString("other.png");
    int ex = fake::originalExists;
    CHECK(hooks::Hook_ExistsLocalFile(&owned, nullptr) && fake::originalExists == ex);
    CHECK(hooks::Hook_ExistsLocalFile(&ownedLong, nullptr) && fake::originalExists == ex);
    CHECK(hooks::Hook_ExistsLocalFile(&notOwned, nullptr) && fake::originalExists == ex + 1);
    int dl = fake::originalDownloaded;
    CHECK(hooks::Hook_IsFileAlreadyDownloaded(&owned, nullptr) && fake::originalDownloaded == dl);
    int fe = fake::originalIsFileExist;
    CHECK(hooks::Hook_IsFileExist(nullptr, nullptr, samPath.c_str()) && fake::originalIsFileExist == fe);

    // Tripwires.
    const long writes = hooks::env().persistentWrites;
    hooks::Hook_Fopen(samPath.c_str(), "wb");
    CHECK(hooks::env().persistentWrites == writes + 1 && fake::originalFopen == 1);
    hooks::Hook_Fopen(samPath.c_str(), "rb");
    CHECK(hooks::env().persistentWrites == writes + 1);
    CHECK(hooks::Hook_Remove(samPath.c_str()) == -1 && fake::originalRemove == 0);
    CHECK(hooks::Hook_Remove(other.c_str()) == 0 && fake::originalRemove == 1);

    // Safe point releases the game's decoded copy under the exact key it used.
    b.Put("sam/MapVillage/MapVillage.sam", Bytes("MAS.edited"));
    CHECK(p.PollOnce(why));
    fake::removedKeys.clear();
    hooks::SafePoint("test");
    CHECK(std::find(fake::removedKeys.begin(), fake::removedKeys.end(), samPath) != fake::removedKeys.end());
    data = hooks::Hook_GetFileData(nullptr, nullptr, samPath.c_str(), "rb", &size);
    CHECK(data && std::string(reinterpret_cast<char*>(data), size) == "MAS.edited");
    fake::Delete(data);

    // Removed from game_content: absent, and no fallback to the cached copy.
    b.Remove("sam/MapVillage/MapVillage.sam");
    CHECK(p.PollOnce(why));
    hooks::SafePoint("test");
    origBefore = fake::originalGetFileData;
    ex = fake::originalExists;
    CHECK(!hooks::Hook_ExistsLocalFile(&owned, nullptr) && fake::originalExists == ex);
    data = hooks::Hook_GetFileData(nullptr, nullptr, samPath.c_str(), "rb", &size);
    CHECK(!data && size == 0 && fake::originalGetFileData == origBefore);

    // Short writable path (SSO string): no free.
    Provider dormant(&b, 1 << 20, 1 << 20);
    dormant.SetAutoStart(false);
    SetupEnv(&dormant, "C:\\LS");
    const int deletes = fake::deleteCalls;
    CHECK(hooks::EnsurePrefix() && fake::deleteCalls == deletes);
    // An inactive provider passes everything through.
    origBefore = fake::originalGetFileData;
    data = hooks::Hook_GetFileData(nullptr, nullptr, "C:\\LS\\MapVillage.sam", "rb", &size);
    CHECK(fake::originalGetFileData == origBefore + 1);
    fake::Delete(data);
    ex = fake::originalExists;
    hooks::Hook_ExistsLocalFile(&owned, nullptr);
    CHECK(fake::originalExists == ex + 1);
    free(ownedLong.bx.ptr);
    hooks::env().provider = nullptr;
}

// ------------------------------------------------- getTexture thunk ABI ----


uint32_t g_abi_seenEcx = 0, g_abi_seenEdx = 0, g_abi_seenStackArg = 0, g_abi_seenEbx = 0, g_abi_seenEsi = 0, g_abi_seenEdi = 0;
uint32_t g_abi_afterEbx = 0, g_abi_afterEsi = 0, g_abi_afterEdi = 0, g_abi_afterEax = 0, g_abi_espDelta = 0;

extern "C" __declspec(naked) void FakeGetTexture()
{
    __asm {
        mov g_abi_seenEcx, ecx
        mov g_abi_seenEdx, edx
        mov eax, [esp + 4]
        mov g_abi_seenStackArg, eax
        mov g_abi_seenEbx, ebx
        mov g_abi_seenEsi, esi
        mov g_abi_seenEdi, edi
        mov eax, 0x1234
        ret
    }
}

void CallThunk(const hooks::MsvcString* path, uint32_t dlValue, uint32_t stackArg)
{
    uint32_t before = 0, after = 0;
    void* thunk = reinterpret_cast<void*>(&hooks::GetTextureThunk);
    __asm {
        push ebx
        push esi
        push edi
        mov ebx, 0x11111111
        mov esi, 0x22222222
        mov edi, 0x33333333
        mov before, esp
        push stackArg
        mov ecx, path
        mov edx, dlValue
        call dword ptr [thunk]
        add esp, 4
        mov after, esp
        mov g_abi_afterEbx, ebx
        mov g_abi_afterEsi, esi
        mov g_abi_afterEdi, edi
        mov g_abi_afterEax, eax
        pop edi
        pop esi
        pop ebx
    }
    g_abi_espDelta = before - after;
}

void TestPrefixThread()
{
    FakeBroker b;
    b.Put("unit/img/unit_anime_60956.png", Bytes("\x89PNG"));
    Provider p(&b, 1 << 20, 1 << 20);
    p.SetAutoStart(false);
    std::string why;
    CHECK(p.InitializeOnce(why));
    SetupEnv(&p, "C:\\Pk\\LocalState\\");
    hooks::Env& e = hooks::env();
    e.anyThreadMayResolve = false;
    e.renderThreadId = 0;
    const int origBefore = fake::originalGetFileData;
    unsigned long size = 0;
    unsigned char* data = nullptr;
    std::thread worker([&] {
        data = hooks::Hook_GetFileData(nullptr, nullptr, "C:\\Pk\\LocalState\\unit_anime_60956.png", "rb", &size);
    });
    worker.join();
    CHECK_MSG(!e.prefixKnown && fake::originalGetFileData == origBefore + 1,
              "a worker thread never resolves the LocalState prefix (WinRT); it passes through until the render thread has");
    fake::Delete(data);
    e.renderThreadId = GetCurrentThreadId();   // this thread plays the render thread
    data = hooks::Hook_GetFileData(nullptr, nullptr, "C:\\Pk\\LocalState\\unit_anime_60956.png", "rb", &size);
    CHECK(e.prefixKnown && data && size == 4);
    fake::Delete(data);
    e.provider = nullptr;
    e.anyThreadMayResolve = true;
}

void TestThunkAbi()
{
    FakeBroker b;
    b.Put("unit/img/unit_anime_60956.png", Bytes("\x89PNG"));
    Provider p(&b, 1 << 20, 1 << 20);
    p.SetAutoStart(false);
    std::string why;
    CHECK(p.InitializeOnce(why));
    SetupEnv(&p, "C:\\Pk\\LocalState\\");
    hooks::g_cpTrueGetTexture = reinterpret_cast<void*>(FakeGetTexture);

    hooks::MsvcString owned = MakeString("C:\\Pk\\LocalState\\unit_anime_60956.png");
    hooks::MsvcString other = MakeString("C:\\Pk\\LocalState\\unit_anime_10011.png");
    CallThunk(&owned, 0xAAAA0001, 1);
    CHECK_MSG((g_abi_seenEdx & 0xFF) == 0, "owned path: force-decode (DL) cleared");
    CHECK_MSG((g_abi_seenEdx & 0xFFFFFF00) == 0xAAAA0000, "the rest of EDX is untouched");
    CHECK(g_abi_seenEcx == reinterpret_cast<uint32_t>(&owned));
    CHECK_MSG(g_abi_seenStackArg == 1, "the stack bool reaches the original unchanged");
    CHECK(g_abi_seenEbx == 0x11111111 && g_abi_seenEsi == 0x22222222 && g_abi_seenEdi == 0x33333333);
    CHECK(g_abi_afterEbx == 0x11111111 && g_abi_afterEsi == 0x22222222 && g_abi_afterEdi == 0x33333333);
    CHECK(g_abi_afterEax == 0x1234 && g_abi_espDelta == 0);

    CallThunk(&other, 0xAAAA0001, 0);
    CHECK_MSG((g_abi_seenEdx & 0xFF) == 1, "unowned path: force-decode left as the game set it");
    CHECK(g_abi_seenStackArg == 0 && g_abi_espDelta == 0 && g_abi_afterEax == 0x1234);
    free(owned.bx.ptr);
    free(other.bx.ptr);
    hooks::env().provider = nullptr;
}

// ------------------------------------------------------- instrumentation ----

int g_fakeDrawCalls = 0;
void __fastcall FakeDrawScene(void*, void*) { ++g_fakeDrawCalls; }

} // namespace

struct RttiProbeScene
{
    virtual ~RttiProbeScene() {}
    int x = 0;
};

namespace {

void TestInstrumentation()
{
    RttiProbeScene probe;
    CHECK_EQ(hooks::ClassNameOf(&probe), std::string("RttiProbeScene"));
    int notAnObject = 0;
    CHECK_EQ(hooks::ClassNameOf(&notAnObject), std::string("?"));   // unreadable RTTI never crashes
    CHECK_EQ(hooks::ClassNameOf(nullptr), std::string("?"));

    hooks::Env& e = hooks::env();
    e.trueDrawScene = FakeDrawScene;
    e.frameCount = 0;
    e.lastFrameQpc = 0;
    for (int i = 0; i < 20; ++i)
    {
        hooks::Hook_DrawScene(nullptr, nullptr);
        Sleep(1);
    }
    CHECK(g_fakeDrawCalls == 20 && e.frameCount == 19);
    hooks::LogPerformanceWindow("test");
    CHECK(e.frameCount == 0);
    const std::vector<uint8_t> log = ReadFileBytes(LogPath());
    CHECK_MSG(Str(log).find("perf (test): 19 frame(s)") != std::string::npos, "the perf line reports the sampled frames");
}

// ---------------------------------------------------------- signatures ----

//! Maps an on-disk PE to "image" bytes for an RVA (pre-relocation, like the masked signatures).
struct DiskImage
{
    std::vector<uint8_t> raw;
    bool Load(const std::string& path) { raw = ReadFileBytes(path); return raw.size() > 4096; }
    const uint8_t* At(uint32_t rva, size_t& avail) const
    {
        const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(&raw[0]);
        const IMAGE_NT_HEADERS32* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(&raw[0] + dos->e_lfanew);
        const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i)
            if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + sec[i].SizeOfRawData)
            {
                const uint32_t off = sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
                avail = raw.size() - off;
                return &raw[off];
            }
        avail = 0;
        return nullptr;
    }
};

void TestSignatures()
{
    SiteSignature s = { "synthetic", 0, 0, "558BEC6AFF68AABBCCDD", "xxxxxx????" };
    uint8_t code[10] = { 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x01, 0x02, 0x03, 0x04 };
    std::string why;
    CHECK_MSG(MatchSignature(s, code, sizeof code, why), "relocated bytes are ignored");
    code[3] = 0x90;
    CHECK(!MatchSignature(s, code, sizeof code, why) && why.find("byte +3") != std::string::npos);
    CHECK(!MatchSignature(s, code, 4, why));

    const char* dirEnv = getenv("BF_APPX_DIR");
    const std::string dir = dirEnv ? dirEnv : "C:\\Users\\Evan\\BF\\BraveFrontierAppxClient";
    DiskImage exe, cocos;
    if (!exe.Load(dir + "\\BraveFrontier.Windows.exe") || !cocos.Load(dir + "\\libcocos2d_v2.2.5_Windows_8.1.dll"))
    {
        t::Skip("signature table vs the real client binaries", "BF_APPX_DIR not set / client not extracted");
        return;
    }
    const DiskImage* images[2] = { &exe, &cocos };
    for (int m = 0; m < 2; ++m)
        CHECK_MSG(MatchIdentity(kSupportedModules[m], &images[m]->raw[0], images[m]->raw.size(), why), why);
    for (size_t i = 0; i < sizeof kSiteSignatures / sizeof kSiteSignatures[0]; ++i)
    {
        size_t avail = 0;
        const uint8_t* p = images[kSiteSignatures[i].module]->At(kSiteSignatures[i].rva, avail);
        CHECK_MSG(p && MatchSignature(kSiteSignatures[i], p, avail, why), std::string(kSiteSignatures[i].name) + ": " + why);
    }
    // An unknown build declines: wrong identity, and a changed byte at a site.
    DiskImage curl;
    if (curl.Load(dir + "\\libcurl.dll"))
        CHECK(!MatchIdentity(kSupportedModules[1], &curl.raw[0], curl.raw.size(), why) && why.find("mismatch") != std::string::npos);
    DiskImage patched = exe;
    IMAGE_NT_HEADERS32* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(&patched.raw[0] + reinterpret_cast<IMAGE_DOS_HEADER*>(&patched.raw[0])->e_lfanew);
    nt->FileHeader.TimeDateStamp ^= 1;
    CHECK(!MatchIdentity(kSupportedModules[0], &patched.raw[0], patched.raw.size(), why));
    const SiteSignature* existsSite = nullptr;
    for (size_t i = 0; i < sizeof kSiteSignatures / sizeof kSiteSignatures[0]; ++i)
        if (strcmp(kSiteSignatures[i].name, "existsLocalFile") == 0)
            existsSite = &kSiteSignatures[i];
    CHECK(existsSite && existsSite->module == 0);
    size_t avail = 0;
    uint8_t* site = const_cast<uint8_t*>(patched.At(existsSite->rva, avail));
    CHECK(site && MatchSignature(*existsSite, site, avail, why));
    site[0] ^= 0xFF;
    CHECK_MSG(!MatchSignature(*existsSite, site, avail, why), "one changed byte at a hook site declines the build");
}

// ------------------------------------------------- gate flash (#24) ----

namespace gf = cp::gateflash;

//! A fake SuperAnimEx: the path, frame and enabled flag at the x86 offsets.
struct FakeAnim
{
    uint8_t bytes[0x240];
    explicit FakeAnim(const std::string& path, float frame = 0.f, bool enabled = true)
    {
        memset(bytes, 0, sizeof bytes);
        *Path() = MakeString(path);
        Frame(frame);
        Enable(enabled);
    }
    ~FakeAnim()
    {
        if (Path()->capacity >= 16)
            free(Path()->bx.ptr);
    }
    hooks::MsvcString* Path() { return reinterpret_cast<hooks::MsvcString*>(bytes + gf::kAnimPathOffset); }
    void Frame(float f) { memcpy(bytes + gf::kAnimFrameOffset, &f, sizeof f); }
    void Enable(bool on) { bytes[gf::kAnimEnabledOffset] = on ? 1 : 0; }
    const uint8_t* P() const { return bytes; }
private:
    FakeAnim(const FakeAnim&);
    FakeAnim& operator=(const FakeAnim&);
};

//! A fake SummonsAnimeScene2: only the overlay pointer matters.
struct FakeScene
{
    uint8_t bytes[0x240];
    FakeScene() { memset(bytes, 0, sizeof bytes); }
    void Overlay(const void* p) { memcpy(bytes + gf::kSceneOverlayOffset, &p, sizeof p); }
    const uint8_t* P() const { return bytes; }
};

typedef std::vector<const uint8_t*> AnimList;

bool GateStep(gf::State& st, const FakeScene& scene, const AnimList& list, gf::Report& r)
{
    const uint8_t* const* b = list.empty() ? nullptr : &list[0];
    return gf::Decide(scene.P(), b, b ? b + list.size() : nullptr, st, r);
}

//! Plays an opening pair from frame 0 to 60; returns the first frame that turns white (-1: none).
int PlayOpening(gf::State& st, const FakeScene& scene, const AnimList& before, FakeAnim& open, FakeAnim& blend,
                const AnimList& after, bool* stockAtSameFrame = nullptr)
{
    AnimList list(before);
    list.push_back(open.P());
    list.push_back(blend.P());
    list.insert(list.end(), after.begin(), after.end());
    for (int f = 0; f <= 60; ++f)
    {
        open.Frame(static_cast<float>(f));
        blend.Frame(static_cast<float>(f));
        gf::Report r;
        if (GateStep(st, scene, list, r))
        {
            if (stockAtSameFrame)
                *stockAtSameFrame = r.nativeWouldFlash;
            return f;
        }
    }
    return -1;
}

const char* const kLs = "C:\\Users\\p\\AppData\\Local\\Packages\\gumi\\LocalState\\";

void TestGateFlashDecision()
{
    const std::string ls = kLs;
    FakeAnim overflow(ls + "StaminaBarOverflowAdd.sam", 30.f);
    FakeAnim download(ls + "downloading_icon.sam", 5.f);
    FakeAnim close5(ls + "GachaGateClose5.sam", 50.f);
    FakeAnim close6(ls + "GachaGateClose6.sam", 50.f), close6add(ls + "GachaGateClose6Add.sam", 50.f);
    FakeAnim touch(ls + "Touch.sam", 10.f);
    FakeAnim change(ls + "GachaGateChange5_6.sam", 49.f);
    FakeAnim ripple(ls + "ripple.sam", 3.f);

    // The player's premature whiteout: two unrelated animations + one gate = 3.
    {
        FakeScene scene;
        gf::State st;
        gf::Report r;
        CHECK_MSG(!GateStep(st, scene, AnimList{ overflow.P(), download.P(), close5.P() }, r) && r.nativeWouldFlash,
                  "waiting rainbow gate + overflow glow + download icon: the stock rule whites out, the fix does not");
        CHECK(!GateStep(st, scene, AnimList{ overflow.P(), download.P(), change.P() }, r) && r.nativeWouldFlash);
        CHECK_MSG(!GateStep(st, scene, AnimList{ overflow.P(), download.P(), close6.P(), close6add.P(), touch.P() }, r)
                  && !r.nativeWouldFlash && r.count == 5, "a waiting black gate with its touch prompt: no white");
        int stockPremature = 0, fixWhite = 0;
        for (int f = 0; f < 120; ++f)
        {
            close5.Frame(static_cast<float>(f));
            change.Frame(static_cast<float>(f % 50));
            fixWhite += GateStep(st, scene, AnimList{ overflow.P(), close5.P(), touch.P() }, r);
            fixWhite += GateStep(st, scene, AnimList{ close5.P() }, r);
            fixWhite += GateStep(st, scene, AnimList{ overflow.P(), download.P(), change.P() }, r);
            stockPremature += r.nativeWouldFlash;
        }
        CHECK_MSG(fixWhite == 0 && stockPremature > 0,
                  "120 frames of waiting / changing gates: the stock rule fires, the fix never does");
    }

    // The final gate's opening: white at frame 45 whatever else is on screen.
    struct Case { const char* what; const char* open; const char* blend; AnimList before; AnimList after; bool stockToo; };
    const Case cases[] = {
        { "black gate (7-star / Omni), overflow + download (the missing final white)", "GachaGateOpen6.sam",
          "GachaGateOpen6Add.sam", AnimList{ overflow.P(), download.P() }, AnimList(), false },
        { "rainbow gate (5/6-star), overflow + download", "GachaGateOpen5.sam", "GachaGateOpenAdd.sam",
          AnimList{ overflow.P(), download.P() }, AnimList(), false },
        { "rainbow gate, one unrelated animation (the stock rule's own case)", "GachaGateOpen5.sam",
          "GachaGateOpenAdd.sam", AnimList{ download.P() }, AnimList(), true },
        { "black gate, energy flat (one unrelated animation)", "GachaGateOpen6.sam", "GachaGateOpen6Add.sam",
          AnimList{ overflow.P() }, AnimList(), true },
        { "gold gate, nothing else on screen", "GachaGateOpen3.sam", "GachaGateOpenAdd.sam", AnimList(), AnimList(), false },
        { "stone gate, a tap ripple after the pair", "GachaGateOpen2.sam", "GachaGateOpenAdd.sam",
          AnimList{ overflow.P() }, AnimList{ ripple.P() }, false },
        { "red gate, three unrelated animations", "GachaGateOpen4.sam", "GachaGateOpenAdd.sam",
          AnimList{ overflow.P(), download.P(), touch.P() }, AnimList(), false },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i)
    {
        FakeScene scene;
        gf::State st;
        FakeAnim open(ls + cases[i].open), blend(ls + cases[i].blend);
        bool stock = false;
        const int at = PlayOpening(st, scene, cases[i].before, open, blend, cases[i].after, &stock);
        CHECK_MSG(at == gf::kFlashFrame, std::string(cases[i].what) + ": white at frame " + std::to_string(at));
        CHECK_MSG(stock == cases[i].stockToo, std::string(cases[i].what) + ": the stock rule "
                  + (cases[i].stockToo ? "fires on the same frame (unchanged timing)" : "would not have fired"));
    }

    // Rapid taps during the opening: ripples come and go, the white still lands on frame 45.
    {
        FakeScene scene;
        gf::State st;
        FakeAnim open(ls + "GachaGateOpen6.sam"), blend(ls + "GachaGateOpen6Add.sam");
        int at = -1;
        for (int f = 0; f <= 60 && at < 0; ++f)
        {
            open.Frame(static_cast<float>(f));
            blend.Frame(static_cast<float>(f));
            AnimList list{ overflow.P(), download.P() };
            if (f % 3 == 0)
                list.push_back(ripple.P());
            list.push_back(open.P());
            list.push_back(blend.P());
            if (f % 4 == 1)
                list.push_back(ripple.P());
            gf::Report r;
            if (GateStep(st, scene, list, r))
                at = f;
        }
        CHECK_MSG(at == gf::kFlashFrame, "rapid taps: white at frame 45");
    }

    // A leftover opening animation (first seen past frame 45) never whites out a new scene.
    {
        FakeScene scene;
        gf::State st;
        gf::Report r;
        FakeAnim stale(ls + "GachaGateOpen6Add.sam", 60.f);
        int white = 0;
        for (int f = 0; f < 200; ++f)
        {
            close5.Frame(static_cast<float>(f));
            white += GateStep(st, scene, AnimList{ stale.P(), close5.P(), touch.P() }, r);
        }
        CHECK_MSG(white == 0, "a leftover opening animation never whites out a waiting gate");
        FakeAnim open(ls + "GachaGateOpen5.sam"), blend(ls + "GachaGateOpenAdd.sam");
        CHECK_MSG(PlayOpening(st, scene, AnimList{ stale.P() }, open, blend, AnimList()) == gf::kFlashFrame,
                  "the real opening still whites out at frame 45 next to a leftover");
    }

    // Disabled animations do not count; an overlay ends the decision; a new scene forgets.
    {
        FakeScene scene;
        gf::State st;
        gf::Report r;
        FakeAnim open(ls + "GachaGateOpen5.sam", 10.f), blend(ls + "GachaGateOpenAdd.sam", 10.f);
        CHECK(!GateStep(st, scene, AnimList{ open.P(), blend.P() }, r) && r.armedNew && st.armedCount == 2);
        open.Enable(false);
        blend.Enable(false);
        open.Frame(50.f);
        blend.Frame(50.f);
        CHECK_MSG(!GateStep(st, scene, AnimList{ open.P(), blend.P() }, r) && st.armedCount == 0,
                  "disabled (being removed) opening animations never whiten, and are forgotten");
        open.Enable(true);
        blend.Enable(true);
        CHECK_MSG(!GateStep(st, scene, AnimList{ open.P(), blend.P() }, r), "re-seen past frame 45: not armed");

        FakeScene other;
        gf::State st2;
        open.Frame(10.f);
        CHECK(!GateStep(st2, scene, AnimList{ open.P() }, r) && st2.armedCount == 1);
        open.Frame(50.f);
        CHECK_MSG(!GateStep(st2, other, AnimList{ open.P() }, r) && st2.scene == other.P() && st2.armedCount == 0,
                  "a different scene starts with nothing armed");

        gf::State st3;
        open.Frame(10.f);
        CHECK(!GateStep(st3, scene, AnimList{ open.P() }, r));
        int overlay = 0;
        scene.Overlay(&overlay);
        open.Frame(50.f);
        CHECK_MSG(!GateStep(st3, scene, AnimList{ open.P() }, r) && st3.armedCount == 0,
                  "an existing overlay: the game's fade step runs, nothing new is created");
        CHECK_MSG(!r.nativeWouldFlash, "the stock rule also stops once the overlay exists");
    }

    // Frame reads and paths, as the stock code reads them.
    {
        FakeAnim a(ls + "GachaGateOpen5.sam", 44.99f);
        CHECK(gf::FrameOf(a.P()) == 44);
        a.Frame(45.f);
        CHECK(gf::FrameOf(a.P()) == 45);
        float nan = 0.f;
        const uint32_t qnan = 0x7FC00000u;
        memcpy(&nan, &qnan, sizeof nan);
        a.Frame(nan);
        CHECK_MSG(gf::FrameOf(a.P()) == INT_MIN, "NaN reads as INT_MIN, like cvttss2si (below 45)");
        a.Frame(1e12f);
        CHECK(gf::FrameOf(a.P()) == INT_MIN);
        FakeAnim lower(ls + "gachagateopen6add.sam");
        CHECK(gf::IsOpeningGate(lower.P()));
        FakeAnim sso("GachaGateOpen");          // 13 bytes: the inline (SSO) form
        CHECK(sso.Path()->capacity == 15 && gf::IsOpeningGate(sso.P()));
        char name[64];
        gf::NameOf(a.P(), name, sizeof name);
        CHECK_EQ(std::string(name), std::string("GachaGateOpen5.sam"));
        FakeAnim bad(ls + "GachaGateOpen5.sam");
        const uint32_t size = bad.Path()->size;
        bad.Path()->size = bad.Path()->capacity + 1;
        CHECK_MSG(!gf::IsOpeningGate(bad.P()), "an implausible string is never read");
        bad.Path()->size = size;
        FakeAnim change2(ls + "GachaGateChange3_4.sam"), close(ls + "GachaGateClose6Add.sam");
        CHECK(!gf::IsOpeningGate(change2.P()) && !gf::IsOpeningGate(close.P()) && !gf::IsOpeningGate(touch.P()));
    }
}

// The thunk is entered by jmp from game code: it must hand every register
// and esp to the chosen continuation exactly as it found them.
uint32_t g_gf_landed = 0;
uint32_t g_gf_eax = 0, g_gf_ebx = 0, g_gf_ecx = 0, g_gf_edx = 0, g_gf_esi = 0, g_gf_edi = 0, g_gf_esp = 0;

extern "C" __declspec(naked) void GfLandYes()
{
    __asm {
        mov g_gf_landed, 1
        mov g_gf_eax, eax
        mov g_gf_ebx, ebx
        mov g_gf_ecx, ecx
        mov g_gf_edx, edx
        mov g_gf_esi, esi
        mov g_gf_edi, edi
        mov g_gf_esp, esp
        ret
    }
}

extern "C" __declspec(naked) void GfLandNo()
{
    __asm {
        mov g_gf_landed, 2
        mov g_gf_eax, eax
        mov g_gf_ebx, ebx
        mov g_gf_ecx, ecx
        mov g_gf_edx, edx
        mov g_gf_esi, esi
        mov g_gf_edi, edi
        mov g_gf_esp, esp
        ret
    }
}

uint32_t CallGateThunk(const uint8_t* scene)
{
    uint32_t before = 0;
    void* thunk = reinterpret_cast<void*>(&gf::GateFlashThunk);
    g_gf_landed = 0;
    __asm {
        push ebx
        push esi
        push edi
        mov edi, scene
        mov eax, 0x44444444
        mov ebx, 0x11111111
        mov ecx, 0x55555555
        mov edx, 0x66666666
        mov esi, 0x22222222
        mov before, esp
        call dword ptr [thunk]
        pop edi
        pop esi
        pop ebx
    }
    return before;
}

struct FakeArrayObject { uint8_t pad[gf::kArrayBeginOffset]; const uint8_t* const* begin; const uint8_t* const* end; };
struct FakeAnimList { uint8_t pad[gf::kListArrayOffset]; FakeArrayObject* array; };
FakeArrayObject g_fakeArray;
FakeAnimList g_fakeList;
AnimList g_fakeAnims;
void* __cdecl FakeSharedList()
{
    g_fakeArray.begin = g_fakeAnims.empty() ? nullptr : &g_fakeAnims[0];
    g_fakeArray.end = g_fakeArray.begin ? g_fakeArray.begin + g_fakeAnims.size() : nullptr;
    g_fakeList.array = &g_fakeArray;
    return &g_fakeList;
}
void* __cdecl UnreadableList() { return reinterpret_cast<void*>(0x10); }

// Code writes with scripted OS failures (round-8 QC P2).  Writes are numbered from 1; a fault fails one step of
// one write: 1 = making the page writable (nothing is copied), 2 = putting the protection back, 3 = the flush.
// Every other step is the real VirtualProtect / FlushInstructionCache on a real page, so a test sees the bytes and
// the page protection the production writer (gf::WriteCodeWith) leaves.
struct WriteFault { int write; int step; };
struct WriteScript {
    int writes = 0;
    int protectCalls = 0;        // within the current write: 1 = make writable, 2 = put back
    std::vector<WriteFault> faults;
} g_ws;

bool WsFails(int step)
{
    for (const WriteFault& f : g_ws.faults)
        if (f.write == g_ws.writes && f.step == step)
            return true;
    return false;
}

bool WsProtect(void* at, size_t n, uint32_t protection, uint32_t* previous)
{
    const int step = ++g_ws.protectCalls;
    if (WsFails(step))
    {
        SetLastError(step == 1 ? ERROR_ACCESS_DENIED : ERROR_INVALID_PARAMETER);
        return false;
    }
    return gf::CodeWriteOsOps().protect(at, n, protection, previous);
}

bool WsFlush(const void* at, size_t n)
{
    if (WsFails(3))
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return false;
    }
    return gf::CodeWriteOsOps().flush(at, n);
}

const gf::CodeWriteOps kWsOps = { &WsProtect, &WsFlush };

gf::WriteResult WsWrite(uint8_t* at, const uint8_t* bytes, size_t n, uint32_t restoreTo)
{
    ++g_ws.writes;
    g_ws.protectCalls = 0;
    return gf::WriteCodeWith(kWsOps, at, bytes, n, restoreTo);
}

void WsReset(std::vector<WriteFault> faults = {})
{
    g_ws = WriteScript();
    g_ws.faults = std::move(faults);
}

//! Real code pages (PAGE_EXECUTE_READ), one per site, each starting with `fill`.
struct CodePages {
    uint8_t* base = nullptr;
    int count = 0;
    explicit CodePages(int n, uint8_t fill = 0xCC) : count(n)
    {
        base = static_cast<uint8_t*>(VirtualAlloc(nullptr, 4096 * n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        memset(base, fill, 4096 * n);
        DWORD old = 0;
        VirtualProtect(base, 4096 * n, PAGE_EXECUTE_READ, &old);
    }
    CodePages(const CodePages&) = delete;
    CodePages& operator=(const CodePages&) = delete;
    ~CodePages() { VirtualFree(base, 0, MEM_RELEASE); }
    uint8_t* Page(int i) const { return base + 4096 * i; }
    void Reprotect(int i) const { DWORD old = 0; VirtualProtect(Page(i), 4096, PAGE_EXECUTE_READ, &old); }
};

void TestCodeWriteSteps()
{
    CodePages pages(1);
    uint8_t* at = pages.Page(0) + 0x10;
    const uint8_t a[5] = { 0xE9, 1, 2, 3, 4 }, b[5] = { 0xE8, 5, 6, 7, 8 };
    {   // the production writer: complete, the bytes in place, the protection back
        const gf::WriteResult r = gf::WriteCode(at, a, 5);
        CHECK(r.Complete() && r.copied && r.protectRestored && r.flushed && r.error == 0);
        CHECK(memcmp(at, a, 5) == 0 && gf::ProtectionOf(at) == PAGE_EXECUTE_READ && r.found == PAGE_EXECUTE_READ);
        CHECK(std::string(gf::FailedStep(r)).empty());
    }
    {   // step 1 fails: nothing copied, the page untouched
        WsReset({ { 1, 1 } });
        const gf::WriteResult r = WsWrite(at, b, 5, 0);
        CHECK(!r.copied && !r.Complete() && r.error == ERROR_ACCESS_DENIED);
        CHECK(memcmp(at, a, 5) == 0 && gf::ProtectionOf(at) == PAGE_EXECUTE_READ);
        CHECK_EQ(std::string(gf::FailedStep(r)), std::string("making the page writable"));
    }
    {   // step 2 fails AFTER the copy: the bytes changed, the page is left writable, the flush still ran
        WsReset({ { 1, 2 } });
        const gf::WriteResult r = WsWrite(at, b, 5, 0);
        CHECK_MSG(r.copied && !r.protectRestored && r.flushed && !r.Complete(), "copied, protection not restored");
        CHECK(r.error == ERROR_INVALID_PARAMETER && memcmp(at, b, 5) == 0);
        CHECK_MSG(gf::ProtectionOf(at) == PAGE_EXECUTE_READWRITE, "the real page is left writable");
        CHECK_EQ(std::string(gf::FailedStep(r)), std::string("restoring the page protection"));
        // A later write that only "puts back what it found" keeps the page writable; restoreTo fixes it.
        WsReset();
        const gf::WriteResult keep = WsWrite(at, a, 5, 0);
        CHECK(keep.Complete() && keep.found == PAGE_EXECUTE_READWRITE && gf::ProtectionOf(at) == PAGE_EXECUTE_READWRITE);
        const gf::WriteResult fix = WsWrite(at, a, 5, PAGE_EXECUTE_READ);
        CHECK(fix.Complete() && gf::ProtectionOf(at) == PAGE_EXECUTE_READ);
    }
    {   // step 3 fails after the copy: the bytes changed and the protection is back
        WsReset({ { 1, 3 } });
        const gf::WriteResult r = WsWrite(at, b, 5, 0);
        CHECK(r.copied && r.protectRestored && !r.flushed && !r.Complete() && r.error == ERROR_NOT_SUPPORTED);
        CHECK(memcmp(at, b, 5) == 0 && gf::ProtectionOf(at) == PAGE_EXECUTE_READ);
        CHECK_EQ(std::string(gf::FailedStep(r)), std::string("flushing the instruction cache"));
    }
    {   // steps 2 and 3 fail: the first failure's error is kept
        WsReset({ { 1, 2 }, { 1, 3 } });
        const gf::WriteResult r = WsWrite(at, a, 5, 0);
        CHECK(r.copied && !r.protectRestored && !r.flushed && r.error == ERROR_INVALID_PARAMETER);
        pages.Reprotect(0);
    }
    {   // no address: no OS call at all
        WsReset();
        const gf::WriteResult r = WsWrite(nullptr, a, 5, 0);
        CHECK(!r.copied && r.error == ERROR_INVALID_ADDRESS && g_ws.protectCalls == 0);
    }
}

void TestGateFlashThunk()
{
    const std::string ls = kLs;
    gf::GateEnv& g = gf::genv();
    g = gf::GateEnv();
    g.sharedList = FakeSharedList;
    gf::g_cpGateFlashYes = reinterpret_cast<uintptr_t>(&GfLandYes);
    gf::g_cpGateFlashNo = reinterpret_cast<uintptr_t>(&GfLandNo);
    FakeScene scene;
    FakeAnim overflow(ls + "StaminaBarOverflowAdd.sam", 30.f), download(ls + "downloading_icon.sam", 5.f);
    FakeAnim close5(ls + "GachaGateClose5.sam", 50.f);
    FakeAnim open(ls + "GachaGateOpen6.sam", 0.f), blend(ls + "GachaGateOpen6Add.sam", 0.f);

    g_fakeAnims = AnimList{ overflow.P(), download.P(), close5.P() };
    uint32_t before = CallGateThunk(scene.P());
    CHECK_MSG(g_gf_landed == 2, "the stock rule would whiten a waiting gate: the thunk continues at the fade step");
    CHECK(g_gf_eax == 0x44444444 && g_gf_ebx == 0x11111111 && g_gf_ecx == 0x55555555 && g_gf_edx == 0x66666666
          && g_gf_esi == 0x22222222 && g_gf_edi == reinterpret_cast<uint32_t>(scene.P()));
    CHECK_MSG(g_gf_esp == before - 4, "esp reaches the continuation unchanged (only the test's return address)");

    g_fakeAnims = AnimList{ overflow.P(), download.P(), open.P(), blend.P() };
    int early = 0;
    for (int f = 0; f <= 45; ++f)
    {
        open.Frame(static_cast<float>(f));
        blend.Frame(static_cast<float>(f));
        before = CallGateThunk(scene.P());
        if (f < 45)
            early += g_gf_landed != 2;
    }
    CHECK_MSG(early == 0, "frames 0..44 of the opening continue at the fade step");
    CHECK_MSG(g_gf_landed == 1, "frame 45 of the final opening: the thunk continues at the overlay creation");
    CHECK(g_gf_eax == 0x44444444 && g_gf_ebx == 0x11111111 && g_gf_ecx == 0x55555555 && g_gf_edx == 0x66666666
          && g_gf_esi == 0x22222222 && g_gf_edi == reinterpret_cast<uint32_t>(scene.P()) && g_gf_esp == before - 4);

    const std::string log = Str(ReadFileBytes(LogPath()));
    CHECK_MSG(log.find("gate flash: the stock trigger would turn the screen white now (3 animations, the third "
                       "GachaGateClose5.sam at frame 50)") != std::string::npos, "the suppressed stock trigger is logged");
    CHECK_MSG(log.find("gate flash: the final gate is opening (GachaGateOpen6.sam at frame 0, 4 animation(s) on screen)")
              != std::string::npos, "the opening is logged");
    CHECK_MSG(log.find("gate flash: white at frame 45 of GachaGateOpen6.sam (4 animation(s) on screen; the stock trigger "
                       "would not have fired)") != std::string::npos, "the white is logged");

    // A fault reading the list: no white this frame, the stock bytes go back.
    uint8_t* page = static_cast<uint8_t*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ));
    CHECK(page != nullptr);
    const uint8_t stock[5] = { 0xE8, 0x9C, 0xB2, 0xDB, 0xFF };
    const uint8_t patch[5] = { 0xE9, 0x01, 0x02, 0x03, 0x04 };
    CHECK(gf::WriteCode(page, patch, sizeof patch).Complete() && memcmp(page, patch, 5) == 0);
    MEMORY_BASIC_INFORMATION mbi;
    CHECK_MSG(VirtualQuery(page, &mbi, sizeof mbi) && mbi.Protect == PAGE_EXECUTE_READ, "the page protection is restored");
    g.site = page;
    memcpy(g.original, stock, sizeof stock);
    g.protection = gf::ProtectionOf(page);
    g.patched = true;
    g.sharedList = UnreadableList;
    FakeScene scene2;
    CallGateThunk(scene2.P());
    CHECK_MSG(g_gf_landed == 2 && g.faulted && !g.patched && memcmp(page, stock, 5) == 0,
              "a fault continues at the fade step and writes the stock trigger back");
    CHECK(Str(ReadFileBytes(LogPath())).find("gate flash: fault while reading the animation list; the stock white-screen "
                                             "trigger is restored") != std::string::npos);
    g.sharedList = FakeSharedList;
    CallGateThunk(scene.P());
    CHECK_MSG(g_gf_landed == 2, "after a fault the decision stays off");

    // The fault's restore through the scripted writer (round-8 QC P2): `patched` follows the copy, the log the step.
    struct { int step; bool patchedAfter; const char* log; } cases[] = {
        { 2, false, "the stock white-screen trigger is restored from the next frame, but restoring the page "
                    "protection failed (error 87)" },
        { 3, false, "the stock white-screen trigger is restored from the next frame, but flushing the instruction "
                    "cache failed (error 50)" },
        { 1, true, "the trigger stays off for this session (stock bytes could not be written back: making the page "
                   "writable failed, error 5)" },
    };
    for (const auto& c : cases)
    {
        CHECK(gf::WriteCode(page, patch, sizeof patch, PAGE_EXECUTE_READ).Complete());
        g = gf::GateEnv();
        g.write = &WsWrite;
        g.site = page;
        memcpy(g.original, stock, sizeof stock);
        g.protection = PAGE_EXECUTE_READ;
        g.patched = true;
        g.sharedList = UnreadableList;
        WsReset({ { 1, c.step } });
        FakeScene scene3;
        CallGateThunk(scene3.P());
        CHECK_MSG(g_gf_landed == 2 && g.faulted && g.patched == c.patchedAfter, "patched follows the copy");
        CHECK(memcmp(page, c.patchedAfter ? patch : stock, 5) == 0);
        CHECK_MSG(Str(ReadFileBytes(LogPath())).find(c.log) != std::string::npos, c.log);
        // A later restore (detach) puts the stock protection back explicitly, whatever the failed write left.
        WsReset();
        if (g.patched)
            CHECK(gf::RestoreSite(g).Complete() && !g.patched && memcmp(page, stock, 5) == 0);
        CHECK(!gf::RestoreSite(g).copied);                          // nothing patched: nothing written
        gf::WriteCode(page, stock, sizeof stock, PAGE_EXECUTE_READ);
        CHECK(gf::ProtectionOf(page) == PAGE_EXECUTE_READ);
    }
    VirtualFree(page, 0, MEM_RELEASE);
    g = gf::GateEnv();
    g_fakeAnims.clear();
}

void TestGateFlashSignatures()
{
    const char* dirEnv = getenv("BF_APPX_DIR");
    const std::string dir = dirEnv ? dirEnv : "C:\\Users\\Evan\\BF\\BraveFrontierAppxClient";
    DiskImage exe;
    if (!exe.Load(dir + "\\BraveFrontier.Windows.exe"))
    {
        t::Skip("gate flash sites vs the real client EXE", "BF_APPX_DIR not set / client not extracted");
        return;
    }
    std::string why;
    for (size_t i = 0; i < sizeof kGateFlashSignatures / sizeof kGateFlashSignatures[0]; ++i)
    {
        size_t avail = 0;
        const uint8_t* p = exe.At(kGateFlashSignatures[i].rva, avail);
        CHECK_MSG(kGateFlashSignatures[i].module == 0 && p && MatchSignature(kGateFlashSignatures[i], p, avail, why),
                  std::string(kGateFlashSignatures[i].name) + ": " + why);
    }
    size_t avail = 0;
    const uint8_t* site = exe.At(0x8760EF, avail);
    CHECK_MSG(site && memcmp(site, "\xE8\x9C\xB2\xDB\xFF", 5) == 0, "the patched instruction is call rel32");
    int32_t rel = 0;
    memcpy(&rel, site + 1, sizeof rel);
    CHECK_MSG(0x8760EFu + 5u + static_cast<uint32_t>(rel) == 0x631390u, "...to SuperAnimList::shared");
    const uint8_t* yes = exe.At(0x8761C3, avail);
    const uint8_t* no = exe.At(0x876238, avail);
    CHECK_MSG(yes && memcmp(yes, "\x51\x8B\xCC", 3) == 0, "0x8761C3: push ecx; mov ecx, esp (the overlay creation)");
    CHECK_MSG(no && memcmp(no, "\x8B\x9F\x38\x02\x00\x00", 6) == 0, "0x876238: mov ebx, [edi+238h] (the fade step)");
    DiskImage changed = exe;
    uint8_t* trigger = const_cast<uint8_t*>(changed.At(0x8761BE, avail));
    CHECK(trigger && trigger[0] == 0x83 && trigger[2] == 0x2D);
    trigger[2] = 0x2E;                                         // cmp eax, 2Eh
    const SiteSignature* sig = nullptr;
    for (size_t i = 0; i < sizeof kGateFlashSignatures / sizeof kGateFlashSignatures[0]; ++i)
        if (strcmp(kGateFlashSignatures[i].name, "gateFlashTrigger") == 0)
            sig = &kGateFlashSignatures[i];
    CHECK_MSG(sig && !MatchSignature(*sig, changed.At(sig->rva, avail), avail, why),
              "one changed byte in the trigger declines the patch");
}

// ------------------------------------------------- live broker (opt-in) ----

/*!
* Against a REAL server broker (WinINet over loopback, the same client code
* the DLL uses), started by BF-WorkingDirRust/scripts/test_content_provider_live.py
* with a fixture root.  BF_BROKER_PORT and BF_BROKER_ROOT select it.
*/
void TestLiveBroker()
{
    const char* portText = getenv("BF_BROKER_PORT");
    const char* rootText = getenv("BF_BROKER_ROOT");
    if (!portText || !rootText)
    {
        t::Skip("live broker integration", "BF_BROKER_PORT / BF_BROKER_ROOT not set");
        return;
    }
    const std::string root = rootText;
    WinInetBroker broker("127.0.0.1", static_cast<unsigned short>(atoi(portText)));
    Provider p(&broker, 8u << 20, 4u << 20);
    p.SetAutoStart(false);
    std::string why;
    bool up = false;
    for (int i = 0; i < 120 && !up; ++i)
    {
        up = p.InitializeOnce(why);
        if (!up)
            Sleep(250);
    }
    CHECK_MSG(up, "provider activated against the live broker: " + why);
    if (!up)
        return;

    struct Owned { const char* name; const char* rel; };
    const Owned owned[] = {
        { "MapVillage.sam", "sam/MapVillage/MapVillage.sam" },
        { "MapVillage_320x289.jpg", "_dlcbundle/MapVillage/MapVillage_320x289.jpg" },
        { "MapVillage_640x208.png", "sam/MapVillage/MapVillage_640x208.png" },
        { "MapVillageAdd.sam", "sam/MapVillageAdd/MapVillageAdd.sam" },
        { "unit_cgg_60956.csv", "unit/cgg/unit_cgg_60956.csv" },
        { "unit_anime_60956.png", "unit/img/unit_anime_60956.png" },
        { "unit_ills_thum_60956.png", "unit/img/unit_ills_thum_60956.png" },
    };
    for (size_t i = 0; i < sizeof owned / sizeof owned[0]; ++i)
    {
        std::vector<uint8_t> out;
        std::string err;
        IndexEntry e;
        const ReadStatus st = p.Read(owned[i].name, out, err, &e);
        const std::vector<uint8_t> disk = ReadFileBytes(root + "\\" + owned[i].rel);
        CHECK_MSG(st == ReadStatus::Ok && e.rel == owned[i].rel && out == disk && !disk.empty(),
                  std::string(owned[i].name) + " served byte-exact from the broker " + err);
    }
    CHECK(p.Classify("UserDefault.xml") == Ownership::NotOwned);
    CHECK(p.Classify("unit_anime_10011.png") == Ownership::NotOwned);
    CHECK(p.Classify("MapVillage_iph5.sam") == Ownership::NotOwned);

    // CSV through the hook path: text mode exactly like the CRT.
    {
        hooks::Env& env = hooks::env();
        env.provider = &p;
        env.msvcrNew = fake::New;
        env.msvcrDelete = fake::Delete;
        env.sharedFileUtils = fake::SharedFileUtils;
        env.getWritablePath = fake::GetWritablePath;
        env.trueGetFileData = fake::GetFileData;
        env.prefixKnown = false;
        env.anyThreadMayResolve = true;
        fake::writable = "C:\\Live\\LocalState\\";
        unsigned long size = 0;
        unsigned char* data = hooks::Hook_GetFileData(nullptr, nullptr, "C:\\Live\\LocalState\\unit_cgg_60956.csv", "r", &size);
        const std::vector<uint8_t> disk = ReadFileBytes(root + "\\unit\\cgg\\unit_cgg_60956.csv");
        CHECK_MSG(data && std::string(reinterpret_cast<char*>(data), size) == CrtTextRead(Str(disk)),
                  "live CSV through getFileData(\"r\") equals the CRT's text-mode read");
        fake::Delete(data);
        env.provider = nullptr;
    }

    // Readiness of an edit, observed on the server: the digest it publishes for
    // a path, and its generation.  An edit can be adopted once the server
    // publishes the new bytes' digest AND a poll made after that is pending.
    // HasPending() alone is not readiness: any newer generation satisfies it
    // (an unowned file, a re-examination), and a safe point adopts only what
    // was polled -- round-2 QC's intermittent failure at the CSV edit below.
    const auto serverIndex = [&](IndexSnapshot& snap) {
        int status = 0;
        std::string body, error;
        return broker.GetText("/offline_mod/content/v1/index?since=0&epoch=", status, body, error) && status == 200
            && ParseIndex(body, snap, error);
    };
    const auto publishedDigest = [&](const std::string& rel) {
        IndexSnapshot snap;
        if (serverIndex(snap))
            for (std::map<std::string, IndexEntry>::const_iterator it = snap.files.begin(); it != snap.files.end(); ++it)
                if (it->second.rel == rel)
                    return it->second.digest;
        return std::string();
    };
    const auto serverGeneration = [&]() -> uint64_t {
        IndexSnapshot snap;
        return serverIndex(snap) ? snap.generation : 0;
    };
    const auto adoptable = [&](const std::string& rel, const std::vector<uint8_t>& bytes) {
        const std::string want = Sha256Tag(bytes.empty() ? nullptr : &bytes[0], bytes.size());
        bool published = false;
        for (int i = 0; i < 100 && !published; ++i)
        {
            published = publishedDigest(rel) == want;
            if (!published)
                Sleep(100);
        }
        return published && p.PollOnce(why) && p.HasPending();
    };

    // Same-size edit of the SAM header (height 1161 <-> 985 px, in twips at +15).
    const std::string samPath = root + "\\sam\\MapVillage\\MapVillage.sam";
    std::vector<uint8_t> sam = ReadFileBytes(samPath);
    const std::vector<uint8_t> original = sam;
    const uint16_t h = static_cast<uint16_t>(sam[15] | (sam[16] << 8));
    const uint16_t edited = h == 1161 * 20 ? 985 * 20 : 1161 * 20;
    sam[15] = static_cast<uint8_t>(edited & 0xFF);
    sam[16] = static_cast<uint8_t>(edited >> 8);
    {
        const std::string tmp = samPath + ".tmp";
        FILE* f = nullptr;
        fopen_s(&f, tmp.c_str(), "wb");
        fwrite(&sam[0], 1, sam.size(), f);
        fclose(f);
        MoveFileExA(tmp.c_str(), samPath.c_str(), MOVEFILE_REPLACE_EXISTING);
    }
    CHECK_MSG(adoptable("sam/MapVillage/MapVillage.sam", sam),
              "the broker published the same-size edit's digest and a later poll has it pending");
    std::vector<uint8_t> out;
    std::string err;
    CHECK(p.Read("MapVillage.sam", out, err) == ReadStatus::Ok && out == original);   // pinned scene: old bytes
    const std::vector<std::string> changed = p.SafePoint("live test");
    CHECK(std::find(changed.begin(), changed.end(), "mapvillage.sam") != changed.end());
    CHECK_MSG(p.Read("MapVillage.sam", out, err) == ReadStatus::Ok && out == sam && out.size() == original.size(),
              "after the safe point the same-size edit is served");

    // Version binding through the real broker: an owned file this scene has
    // not read yet is edited (same size).  The read is refused (409 ->
    // Superseded), never answered with the newer bytes; a safe point after the
    // edit is ready serves it.
    //
    // This is also round-2 QC's intermittent failure, made deterministic: a
    // generation that does NOT contain the edit (an unowned file) is polled
    // first, so HasPending() is already true when the edit lands -- all the
    // old wait checked -- and a safe point then adopts a generation in which
    // the CSV keeps its old digest, so its read is refused, not the edit.  That
    // is the provider doing what it promises (adopt what was polled, never mix
    // versions); the test's wait was wrong.  The edit is adopted only once the
    // server publishes its digest and a poll after that is pending.
    const std::string cgsRel = "unit/cgs/unit_idle_cgs_60956.csv";
    const std::string cgsPath = root + "\\unit\\cgs\\unit_idle_cgs_60956.csv";
    const std::vector<uint8_t> cgsOriginal = ReadFileBytes(cgsPath);
    CHECK(!cgsOriginal.empty());
    if (!cgsOriginal.empty())
    {
        const auto replace = [&](const std::vector<uint8_t>& bytes) {
            const std::string t = cgsPath + ".tmp";
            FILE* w = nullptr;
            fopen_s(&w, t.c_str(), "wb");
            fwrite(&bytes[0], 1, bytes.size(), w);
            fclose(w);
            MoveFileExA(t.c_str(), cgsPath.c_str(), MOVEFILE_REPLACE_EXISTING);
        };
        // 1. An unrelated generation is published and polled.
        const std::string unrelated = root + "\\unit\\cgs\\unrelated_generation.txt";
        const uint64_t before = serverGeneration();
        {
            FILE* u = nullptr;
            fopen_s(&u, unrelated.c_str(), "wb");
            fputs("not owned: .txt is outside the policy's extensions", u);
            fclose(u);
        }
        bool bumped = false;
        for (int i = 0; i < 100 && !bumped; ++i)
        {
            bumped = serverGeneration() > before;
            if (!bumped)
                Sleep(100);
        }
        CHECK_MSG(bumped && p.PollOnce(why) && p.HasPending(),
                  "an unowned file gives the server a new generation, and the provider has it pending");
        // 2. The edit lands after that poll.
        std::vector<uint8_t> cgs = cgsOriginal;
        cgs[cgs.size() / 2] ^= 0x01;
        replace(cgs);
        CHECK_MSG(p.Read("unit_idle_cgs_60956.csv", out, err) == ReadStatus::Superseded,
                  "the live broker refuses the pinned version once it is gone: " + err);
        CHECK_MSG(p.HasPending(), "HasPending() is already true; it names no file, so it is no readiness for this edit");
        std::vector<std::string> changed = p.SafePoint("live test: generation polled before the edit");
        CHECK_MSG(std::find(changed.begin(), changed.end(), "unit_idle_cgs_60956.csv") == changed.end()
                  && p.Read("unit_idle_cgs_60956.csv", out, err) == ReadStatus::Superseded,
                  "a safe point adopts only what was polled: the CSV keeps its old digest and stays refused");
        // 3. Ready: the server publishes the edit's digest, and a poll after that is pending.
        CHECK_MSG(adoptable(cgsRel, cgs), "the broker published the CSV edit's digest and a later poll has it pending");
        changed = p.SafePoint("live test");
        CHECK(std::find(changed.begin(), changed.end(), "unit_idle_cgs_60956.csv") != changed.end());
        CHECK_MSG(p.Read("unit_idle_cgs_60956.csv", out, err) == ReadStatus::Ok && out == cgs,
                  "after the safe point the edited CSV is served");
        replace(cgsOriginal);
        CHECK(adoptable(cgsRel, cgsOriginal));
        p.SafePoint("live test");
        CHECK(p.Read("unit_idle_cgs_60956.csv", out, err) == ReadStatus::Ok && out == cgsOriginal);
        DeleteFileA(unrelated.c_str());
    }

    // Bundle: losing one Zeal file withdraws all eight; restoring brings them back.
    const std::string thum = root + "\\unit\\img\\unit_ills_thum_60956.png";
    const std::string parked = root + "\\unit_ills_thum_60956.parked";
    CHECK(MoveFileExA(thum.c_str(), parked.c_str(), MOVEFILE_REPLACE_EXISTING) != 0);
    bool gone = false;
    for (int i = 0; i < 100 && !gone; ++i)
    {
        p.PollOnce(why);
        p.SafePoint("live test");
        gone = p.Classify("unit_cgg_60956.csv") == Ownership::Absent;
        if (!gone)
            Sleep(100);
    }
    CHECK_MSG(gone && p.Classify("unit_anime_60956.png") == Ownership::Absent
              && p.Read("unit_cgg_60956.csv", out, err) == ReadStatus::Absent,
              "a missing texture withdraws the whole unit bundle (no frame layout without its texture)");
    CHECK(MoveFileExA(parked.c_str(), thum.c_str(), MOVEFILE_REPLACE_EXISTING) != 0);
    bool back = false;
    for (int i = 0; i < 100 && !back; ++i)
    {
        p.PollOnce(why);
        p.SafePoint("live test");
        back = p.Classify("unit_cgg_60956.csv") == Ownership::Present;
        if (!back)
            Sleep(100);
    }
    CHECK_MSG(back && p.Read("unit_anime_60956.png", out, err) == ReadStatus::Ok, "restoring it brings the bundle back");

    // Leave the fixture as found.
    const std::string tmp = samPath + ".tmp";
    FILE* f = nullptr;
    fopen_s(&f, tmp.c_str(), "wb");
    fwrite(&original[0], 1, original.size(), f);
    fclose(f);
    MoveFileExA(tmp.c_str(), samPath.c_str(), MOVEFILE_REPLACE_EXISTING);
    const ProviderStats st = p.Stats();
    printf("live broker: %llu fetches, %llu KB, %.1f ms total fetch time\n", st.fetches, st.bytesFetched / 1024,
           st.fetchMicros / 1000.0);
}

} // namespace

// QC regressions: a pinned index must constrain bytes, including cold reads
// and reads that overlap a scene change. These assertions intentionally expose
// gaps in the initial Session 7 candidate; do not weaken them to bless mixing.
void TestGenerationIsolationQC()
{
    {
        FakeBroker b;
        b.Put("ui/a.png", Bytes("old"));
        Provider p(&b, 1024, 1024);
        p.SetAutoStart(false);
        std::string why, err;
        std::vector<uint8_t> out;
        CHECK(p.InitializeOnce(why));
        b.Put("ui/a.png", Bytes("new"));
        const ReadStatus st = p.Read("a.png", out, err);
        CHECK_MSG(st != ReadStatus::Ok || Str(out) == "old",
                  "QC: cold read must retain the pinned bytes or reject a newer generation");
    }
    {
        FakeBroker b;
        b.Put("ui/a.png", Bytes("old"));
        Provider p(&b, 1024, 1024);
        p.SetAutoStart(false);
        std::string why, err;
        std::vector<uint8_t> out;
        CHECK(p.InitializeOnce(why));
        b.Put("ui/a.png", Bytes("new"));
        b.Restart();
        const ReadStatus st = p.Read("a.png", out, err);
        CHECK_MSG(st != ReadStatus::Ok || Str(out) == "old",
                  "QC: a new broker epoch must not supply bytes to the old scene pin");
    }
    {
        FakeBroker b;
        b.Put("ui/a.png", Bytes("old"));
        b.Put("ui/b.png", Bytes("bbb"));
        Provider p(&b, 3, 3);
        p.SetAutoStart(false);
        std::string why, err;
        std::vector<uint8_t> out;
        CHECK(p.InitializeOnce(why));
        CHECK(p.Read("a.png", out, err) == ReadStatus::Ok);
        CHECK(p.Read("b.png", out, err) == ReadStatus::Ok);
        b.Put("ui/a.png", Bytes("new"));
        const ReadStatus st = p.Read("a.png", out, err);
        CHECK_MSG(st != ReadStatus::Ok || Str(out) == "old",
                  "QC: LRU eviction must not silently upgrade an asset within a pinned scene");
    }
    {
        class BlockingBroker : public FakeBroker
        {
        public:
            HANDLE captured = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            std::atomic<bool> first{true};
            ~BlockingBroker() { CloseHandle(captured); CloseHandle(release); }
            FetchResult GetFile(const std::string& rel) override
            {
                FetchResult r = FakeBroker::GetFile(rel);
                if (first.exchange(false))
                {
                    SetEvent(captured);
                    WaitForSingleObject(release, 5000);
                }
                return r;
            }
        } b;
        b.Put("ui/a.png", Bytes("old"));
        Provider p(&b, 1024, 1024);
        p.SetAutoStart(false);
        std::string why, err;
        std::vector<uint8_t> out;
        CHECK(p.InitializeOnce(why));
        std::thread reader([&] { std::vector<uint8_t> bytes; std::string error; p.Read("a.png", bytes, error); });
        CHECK(WaitForSingleObject(b.captured, 5000) == WAIT_OBJECT_0);
        b.Put("ui/a.png", Bytes("new"));
        CHECK(p.PollOnce(why));
        p.SafePoint("QC in-flight completion");
        SetEvent(b.release);
        reader.join();
        CHECK_MSG(p.Read("a.png", out, err) == ReadStatus::Ok && Str(out) == "new",
                  "QC: old in-flight completion must not populate the new scene's byte cache");
    }
}

// Round-2 QC: HasPending() says SOME newer generation was polled, not that a
// given edit was.  A safe point adopts only what was polled, so an edit that
// lands after the poll stays unadopted -- its old version refused, never
// mixed -- until a later poll carries it.
void TestPendingReadinessQC()
{
    FakeBroker b;
    b.Put("unit/cgs/x.csv", Bytes("old1"));
    Provider p(&b, 1024, 1024);
    p.SetAutoStart(false);
    std::string why, err;
    std::vector<uint8_t> out;
    CHECK(p.InitializeOnce(why));
    b.Bump();                                       // an unowned file changed
    const uint64_t unrelated = b.generation;
    CHECK(p.PollOnce(why) && p.HasPending());
    b.Put("unit/cgs/x.csv", Bytes("new1"));         // the edit lands after that poll
    std::vector<std::string> changed = p.SafePoint("QC: generation polled before the edit");
    CHECK_MSG(changed.empty() && p.PinnedGeneration() == unrelated,
              "QC: the safe point adopted the polled generation, which changes no owned name");
    CHECK_MSG(p.Read("x.csv", out, err) == ReadStatus::Superseded,
              "QC: the pinned old version is refused, never answered with the newer bytes");
    CHECK(p.PollOnce(why) && p.HasPending());
    changed = p.SafePoint("QC: generation with the edit");
    CHECK(std::find(changed.begin(), changed.end(), "x.csv") != changed.end());
    CHECK_MSG(p.Read("x.csv", out, err) == ReadStatus::Ok && Str(out) == "new1",
              "QC: the edit is served once a poll after it has been adopted");
}

namespace {
namespace fake {
int originalAddLoadFile = 0, originalAddLoadFilePriority = 0;
std::string lastQueued;
//! The game's FileLoader queue entries own their by-value string: they free it.
void __fastcall AddLoadFile(void*, void*, int, hooks::MsvcString name)
{
    ++originalAddLoadFile;
    lastQueued.assign(hooks::StrData(&name), name.size);
    if (name.capacity >= 16)
        Delete(name.bx.ptr);
}
void __fastcall AddLoadFilePriority(void*, void*, int, int, hooks::MsvcString name)
{
    ++originalAddLoadFilePriority;
    lastQueued.assign(hooks::StrData(&name), name.size);
    if (name.capacity >= 16)
        Delete(name.bx.ptr);
}
} // namespace fake
} // namespace

// Phase C1: the FileLoader queue entries.  While the provider is active, an
// owned name it has present is never queued -- it serves the bytes itself.
// Everything else reaches the game's own downloader: before the provider is
// active, a name it does not own, an owned name it reports absent, the
// provider switched off or dormant.  So suppression can never strand a load
// the provider cannot replace.  The by-value string is freed exactly once on
// either path (by the hook when suppressed, by the original otherwise).
void TestEnqueueFilter()
{
    FakeBroker b;
    b.Put("unit/img/unit_ills_thum_60956.png", Bytes("PNG"));
    b.Put("ui/a.png", Bytes("A"));
    b.Put("ui/gone.png", Bytes("G"));
    Provider p(&b, 1024, 1024);
    p.SetAutoStart(false);
    SetupEnv(&p, "C:\\Live\\LocalState\\");
    hooks::Env& e = hooks::env();
    e.trueAddLoadFile = fake::AddLoadFile;
    e.trueAddLoadFilePriority = fake::AddLoadFilePriority;
    std::string why;
    const auto queue = [&](const std::string& n, bool priority) {
        hooks::MsvcString s = MakeString(n);
        if (priority)
            hooks::Hook_AddLoadFilePriority(nullptr, nullptr, 1, 0, s);
        else
            hooks::Hook_AddLoadFile(nullptr, nullptr, 1, s);
    };
    const std::string owned = "/unit/img/unit_ills_thum_60956.png";   // heap string (> 15 chars)

    int calls = fake::originalAddLoadFile;
    queue(owned, false);
    CHECK_MSG(fake::originalAddLoadFile == calls + 1 && fake::lastQueued == owned,
              "C1: before the provider is active (startup) an owned name is still queued");

    CHECK(p.InitializeOnce(why));
    const long suppressed = e.suppressedEnqueues;
    calls = fake::originalAddLoadFile;
    int prio = fake::originalAddLoadFilePriority;
    int deletes = fake::deleteCalls;
    queue(owned, false);
    CHECK_MSG(fake::originalAddLoadFile == calls && fake::deleteCalls == deletes + 1,
              "C1: an owned, present name is not queued, and its heap string is freed once with the game's delete");
    queue(owned, true);
    CHECK_MSG(fake::originalAddLoadFilePriority == prio && fake::deleteCalls == deletes + 2,
              "C1: nor queued with priority");
    queue("a.png", false);
    CHECK_MSG(fake::originalAddLoadFile == calls && fake::deleteCalls == deletes + 2,
              "C1: a short (in-place) string is suppressed without a free");
    CHECK_MSG(e.suppressedEnqueues == suppressed + 3, "C1: each suppression is counted");

    queue("/unit/img/unit_anime_10011.png", false);
    CHECK_MSG(fake::originalAddLoadFile == calls + 1 && fake::deleteCalls == deletes + 3,
              "C1: a name the provider does not own is queued as before (the original frees the string)");

    b.Remove("ui/gone.png");
    CHECK(p.PollOnce(why));
    p.SafePoint("C1 test");
    CHECK(p.Classify("gone.png") == Ownership::Absent);
    queue("gone.png", true);
    CHECK_MSG(fake::originalAddLoadFilePriority == prio + 1,
              "C1: an owned name the provider reports absent is queued as before (legacy kept)");

    e.provider = nullptr;
    queue(owned, false);
    CHECK_MSG(fake::originalAddLoadFile == calls + 2, "C1: with the provider off everything is queued");
    e.provider = &p;

    b.enabled = false;
    CHECK(!p.PollOnce(why));
    p.SafePoint("C1 test: switched off");
    CHECK(p.State() == ProviderState::Dormant);
    queue(owned, false);
    CHECK_MSG(fake::originalAddLoadFile == calls + 3, "C1: a dormant provider queues everything again");
    CHECK_MSG(e.suppressedEnqueues == suppressed + 3, "C1: no suppression outside the active provider");
    e.provider = nullptr;
}

namespace {

size_t CountOccurrences(const std::string& hay, const std::string& needle)
{
    size_t n = 0;
    for (size_t at = hay.find(needle); at != std::string::npos; at = hay.find(needle, at + needle.size()))
        ++n;
    return n;
}

} // namespace

// Session 16: the login check list asks about every owned name.  Decisions are
// counted, and only the first kDecisionSampleNames names per slot are written
// as lines; names passed to the game's downloader are all listed (up to 4000).
void TestDecisionLogging()
{
    FakeBroker b;
    const int kOwned = 3000;
    for (int i = 0; i < kOwned; ++i)
        b.Put("ui/owned_" + std::to_string(i) + ".png", Bytes("P"));
    Provider p(&b, 1 << 20, 1 << 20);
    p.SetAutoStart(false);
    std::string why;
    CHECK(p.InitializeOnce(why));
    SetupEnv(&p, "C:\\Dec\\LocalState\\");
    hooks::Env& e = hooks::env();
    e.trueAddLoadFile = fake::AddLoadFile;
    e.trueAddLoadFilePriority = fake::AddLoadFilePriority;
    hooks::LogDecisionTotals("test baseline");
    long before[hooks::kDecisionSlots];
    for (int i = 0; i < hooks::kDecisionSlots; ++i)
        before[i] = e.decisions[i];
    const long assetsBefore = e.mainQueuedAssets, stateBefore = e.mainQueuedState;
    const size_t logBefore = ReadFileBytes(LogPath()).size();

    LARGE_INTEGER t0, t1, f;
    QueryPerformanceFrequency(&f);
    int wrong = 0;
    QueryPerformanceCounter(&t0);
    for (int round = 0; round < 10; ++round)
        for (int i = 0; i < kOwned; ++i)
        {
            hooks::MsvcString s = MakeString("owned_" + std::to_string(i) + ".png");
            wrong += !hooks::Hook_ExistsLocalFile(&s, nullptr);
            wrong += !hooks::Hook_IsFileAlreadyDownloaded(&s, nullptr);
            if (s.capacity >= 16)
                free(s.bx.ptr);
        }
    QueryPerformanceCounter(&t1);
    CHECK_MSG(wrong == 0, "every owned name is answered present by both checks");
    const double ms = 1000.0 * static_cast<double>(t1.QuadPart - t0.QuadPart) / static_cast<double>(f.QuadPart);
    CHECK_EQ(e.decisions[hooks::kDecisionExistsPresent] - before[hooks::kDecisionExistsPresent], 10L * kOwned);
    CHECK_EQ(e.decisions[hooks::kDecisionDownloadedYes] - before[hooks::kDecisionDownloadedYes], 10L * kOwned);
    CHECK_MSG(ms < 2000.0, "60,000 owned-name decisions are counted, not written line by line (" + std::to_string(ms) + " ms)");

    std::string log = Str(ReadFileBytes(LogPath())).substr(logBefore);
    CHECK_MSG(CountOccurrences(log, "-> present (provider)") <= hooks::kDecisionSampleNames,
              "existsLocalFile: at most the sample of names is written");
    CHECK_MSG(CountOccurrences(log, "-> yes (provider)") <= hooks::kDecisionSampleNames, "downloaded?: likewise");

    // Real downloads: every name is listed, assets and client state counted apart.
    const int queuedMain = fake::originalAddLoadFile, queuedPrio = fake::originalAddLoadFilePriority;
    for (int i = 0; i < 30; ++i)
    {
        hooks::MsvcString s = MakeString("/legacy/legacy_" + std::to_string(i) + ".png");
        hooks::Hook_AddLoadFile(nullptr, nullptr, 1, s);
    }
    hooks::Hook_AddLoadFile(nullptr, nullptr, 0, MakeString("/sgtext/sgtext_UNIT_12.zip"));
    for (int i = 0; i < 5; ++i)
        hooks::Hook_AddLoadFilePriority(nullptr, nullptr, 1, 0, MakeString("layout_scene_" + std::to_string(i) + ".csv"));
    hooks::Hook_AddLoadFilePriority(nullptr, nullptr, 1, 0, MakeString("/ui/owned_7.png"));   // owned: suppressed
    CHECK_EQ(fake::originalAddLoadFile, queuedMain + 31);
    CHECK_EQ(fake::originalAddLoadFilePriority, queuedPrio + 5);
    CHECK_EQ(e.mainQueuedAssets - assetsBefore, 30L);
    CHECK_EQ(e.mainQueuedState - stateBefore, 1L);
    CHECK_EQ(e.decisions[hooks::kDecisionQueuedMain] - before[hooks::kDecisionQueuedMain], 31L);
    CHECK_EQ(e.decisions[hooks::kDecisionQueuedPriority] - before[hooks::kDecisionQueuedPriority], 5L);
    CHECK_EQ(e.decisions[hooks::kDecisionSuppressedPriority] - before[hooks::kDecisionSuppressedPriority], 1L);
    log = Str(ReadFileBytes(LogPath())).substr(logBefore);
    CHECK_MSG(CountOccurrences(log, "-> QUEUED for the game's downloader (main list)") == 31,
              "every name passed to the main list is listed");
    CHECK(log.find("addLoadFile legacy_29.png -> QUEUED") != std::string::npos);
    CHECK(log.find("addLoadFile sgtext_UNIT_12.zip -> QUEUED") != std::string::npos);
    CHECK_MSG(CountOccurrences(log, "-> QUEUED for the game's downloader (priority list)") == 5, "and to the priority list");

    hooks::LogDecisionTotals("test");
    log = Str(ReadFileBytes(LogPath())).substr(logBefore);
    CHECK_MSG(log.find("decisions (test): existsLocalFile present 30000 (total ") != std::string::npos,
              "the totals line reports this window's count");
    CHECK(log.find("QUEUED main 31 (total ") != std::string::npos && log.find("QUEUED priority 5 (total ") != std::string::npos);
    hooks::LogDecisionTotals("test again");
    log = Str(ReadFileBytes(LogPath())).substr(logBefore);
    CHECK_MSG(log.find("decisions (test again): existsLocalFile present 0 (total ") != std::string::npos,
              "a window starts at zero after each summary");
    printf("decision logging: 60,000 owned-name decisions in %.1f ms\n", ms);
    e.provider = nullptr;
}

// ------------------------------------------------- startup coverage (Session 16) ----

namespace {

//! The client files every report below names (Session 18): a master table in a LocalState and the
//! package's resourceMap, written once under %TEMP%; InputsScope points the decisions at them.
struct InputFixture
{
    std::string localState, package;       //!< folders, each with a trailing separator
    std::string table, tableBytes, tableDigest, mapDigest;
};

void WriteBytes(const std::string& path, const std::string& bytes)
{
    std::ofstream out(path.c_str(), std::ios::binary | std::ios::trunc);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

std::string DigestOf(const std::string& bytes)
{
    return Sha256Tag(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
}

const InputFixture& Inputs()
{
    static InputFixture f;
    if (f.localState.empty())
    {
        char tmp[MAX_PATH] = {};
        GetTempPathA(MAX_PATH, tmp);
        const std::string root = std::string(tmp) + "cp_s18_inputs_" + std::to_string(GetCurrentProcessId()) + "\\";
        f.localState = root + "LocalState\\";
        f.package = root + "package\\";
        for (const std::string& dir : { root, f.localState, f.package, f.package + "Assets\\",
                                        f.package + "Assets\\Resources\\" })
            CreateDirectoryA(dir.c_str(), nullptr);
        f.table = "Ver7_TestKey1.dat";
        f.tableBytes = "master table, version 7";
        WriteBytes(f.localState + f.table, f.tableBytes);
        WriteBytes(f.package + "Assets\\Resources\\resourceMap", "1:a.png,\r\n");
        f.tableDigest = DigestOf(f.tableBytes);
        f.mapDigest = DigestOf("1:a.png,\r\n");
    }
    return f;
}

//! The "inputs" field and its two I rows, as the Session 18 broker writes them.
std::string InputLines()
{
    const InputFixture& f = Inputs();
    return "inputs 2\nI\tlocalstate\t" + f.table + "\t" + f.tableDigest
        + "\nI\tpackage\tAssets/Resources/resourceMap\t" + f.mapDigest + "\n";
}

//! Points the game's writable path (hooks) and the package folder (startup) at the input fixture,
//! or at the folders given, for one test; restores both after.
struct InputsScope
{
    std::string raw, folded, package;
    bool known = false;
    explicit InputsScope(const std::string& localState = std::string(), const std::string& pkg = std::string())
    {
        const std::string ls = localState.empty() ? Inputs().localState : localState;
        const std::string pd = pkg.empty() ? Inputs().package : pkg;
        hooks::Env& h = hooks::env();
        std::lock_guard<std::mutex> lock(h.prefixLock);
        raw = h.prefixRaw;
        folded = h.prefixFolded;
        known = h.prefixKnown;
        h.prefixRaw = ls;
        h.prefixFolded = FoldPath(ls);
        h.prefixKnown = true;
        package = startup::env().packageDir;
        startup::env().packageDir = pd;
    }
    ~InputsScope()
    {
        hooks::Env& h = hooks::env();
        std::lock_guard<std::mutex> lock(h.prefixLock);
        h.prefixRaw = raw;
        h.prefixFolded = folded;
        h.prefixKnown = known;
        startup::env().packageDir = package;
    }
};

//! A report as the corrected broker writes it.  complete: both sets fully owned, no row, no
//! reason -- internally consistent, so the strict parser can accept it.  Incomplete: three login
//! names unowned, listed, with the reason.  Both name the input fixture's files.
std::string CoverageBody(const std::string& epoch, uint64_t gen, bool complete, bool buildMatch = true,
                         bool enabled = true, bool ready = true, const std::string& reason = std::string())
{
    std::string s = "bfcp 2\ncoverage 1\nenabled " + std::string(enabled ? "1" : "0") + "\nready "
        + (ready ? "1" : "0") + "\nepoch " + epoch + "\ngeneration " + std::to_string(gen)
        + "\npolicy sha256:" + std::string(64, 'a') + "\nmanifest sha256:" + std::string(64, 'b')
        + "\nmanifest_build B1\nclient_build " + (buildMatch ? "B1" : "B2") + "\nbuild_match " + (buildMatch ? "1" : "0")
        + "\nunknown 0\nexcluded 107\n" + InputLines();
    if (complete)
        s += "set background required 72280 ok 72280 absent 0 unowned 0 missing 0 ambiguous 0 unavailable 0\n"
             "set login required 2418 ok 2418 absent 0 unowned 0 missing 0 ambiguous 0 unavailable 0\n"
             "complete 1\n";
    else
        s += "set background required 72280 ok 72280 absent 0 unowned 0 missing 0 ambiguous 0 unavailable 0\n"
             "set login required 2418 ok 2415 absent 0 unowned 3 missing 0 ambiguous 0 unavailable 0\n"
             "complete 0\nreason " + (reason.empty() ? std::string("set login: 3 unowned") : reason) + "\n"
             "P\tlogin\tunowned\ta.png\nP\tlogin\tunowned\tb.png\nP\tlogin\tunowned\tc.png\n";
    if (complete && !reason.empty())
        s += "reason " + reason + "\n";
    return s + "end\n";
}

//! A report with one line replaced (old -> new; new empty = removed) or appended before "end".
std::string ReportEdit(const std::string& body, const std::string& oldLine, const std::string& newLine)
{
    if (oldLine.empty())
        return body.substr(0, body.size() - 4) + newLine + "\nend\n";
    const size_t at = body.find(oldLine + "\n");
    if (at == std::string::npos)
        return "edit target not found: " + oldLine;
    return body.substr(0, at) + (newLine.empty() ? std::string() : newLine + "\n") + body.substr(at + oldLine.size() + 1);
}

int g_fakeCensusCalls = 0;
void* g_fakeCensusMap = nullptr;
uint8_t g_fakeMapObject[0x40] = {};
void __cdecl FakeCensus()
{
    ++g_fakeCensusCalls;
    g_fakeCensusMap = g_fakeMapObject;
}

std::string g_fakeStored;
std::string g_fakeLastKey;
int g_fakeLoadCalls = 0;
//! SaveUtils::loadUserDefaults as the game has it: the by-value key belongs to the callee.
const char* __cdecl FakeLoadUserDefaults(hooks::MsvcString key)
{
    ++g_fakeLoadCalls;
    g_fakeLastKey.assign(hooks::StrData(&key), key.size);
    if (key.capacity >= 16)
        fake::Delete(key.bx.ptr);
    return g_fakeStored.c_str();
}

//! Calls the prompt hook exactly as LoginScene::updateEvent 0x8E5199 calls loadUserDefaults:
//! the 24-byte string built on the stack, call, add esp 18h -- with sentinel callee-saved registers.
uint32_t g_abiEbx = 0, g_abiEsi = 0, g_abiEdi = 0, g_abiEspDelta = 0;
const char* CallPromptLikeTheGame(const hooks::MsvcString& key)
{
    const char* result = nullptr;
    uint32_t before = 0, after = 0;
    void* fn = reinterpret_cast<void*>(&startup::Hook_PromptFlagRead);
    const hooks::MsvcString* src = &key;
    __asm {
        push ebx
        push esi
        push edi
        mov ebx, 0x11111111
        mov edi, 0x33333333
        mov before, esp
        sub esp, 0x18
        mov esi, src
        mov eax, [esi]
        mov [esp], eax
        mov eax, [esi + 4]
        mov [esp + 4], eax
        mov eax, [esi + 8]
        mov [esp + 8], eax
        mov eax, [esi + 12]
        mov [esp + 12], eax
        mov eax, [esi + 16]
        mov [esp + 16], eax
        mov eax, [esi + 20]
        mov [esp + 20], eax
        mov esi, 0x22222222
        call dword ptr [fn]
        add esp, 0x18
        mov result, eax
        mov after, esp
        mov g_abiEbx, ebx
        mov g_abiEsi, esi
        mov g_abiEdi, edi
        pop edi
        pop esi
        pop ebx
    }
    g_abiEspDelta = before - after;
    return result;
}

} // namespace

void TestStartupCoverage()
{
    CoverageInfo c;
    std::string err;
    CHECK(ParseCoverage(CoverageBody("e1", 7, true), c, err) && c.parsed && c.complete && c.generation == 7
          && c.epoch == "e1" && c.absent == 0 && c.policy.size() == 71);
    CHECK(ParseCoverage(CoverageBody("e1", 7, false, true, true, true, "set login: 3 unowned"), c, err) && !c.complete
          && c.reason == "set login: 3 unowned");
    CHECK_MSG(ParseCoverage(CoverageBody("e1", 7, true, false), c, err) && !c.complete,
              "complete 1 without build_match 1 is not complete (another client build)");
    CHECK_MSG(ParseCoverage(CoverageBody("e1", 7, true, true, false), c, err) && !c.complete, "nor without enabled 1");
    CHECK_MSG(ParseCoverage(CoverageBody("e1", 7, true, true, true, false), c, err) && !c.complete, "nor without ready 1");
    std::string truncated = CoverageBody("e1", 7, true);
    truncated.resize(truncated.size() - 4);
    CHECK_MSG(!ParseCoverage(truncated, c, err) && !c.complete, "a truncated report is no report");
    CHECK(!ParseCoverage("bfcp 1\ncoverage 1\ncomplete 1\nend\n", c, err));
    CHECK(!ParseCoverage("bfcp 2\nenabled 1\nready 1\ncomplete 1\nend\n", c, err));            // not a coverage report
    CHECK(!ParseCoverage("bfcp 2\ncoverage 1\nepoch e\ncomplete 1\nend\n", c, err));          // no generation
    CHECK(!ParseCoverage("<html>busy</html>", c, err));
    CHECK_EQ(BuildIdentity(kSupportedModules[0]), std::string("6253F827-01756000-00ED273D"));

    // The build the reader asked for is part of the proof (Provider::FetchCoverage passes it).
    CHECK_MSG(ParseCoverage(CoverageBody("e1", 7, true), c, err, "B1") && c.complete, "complete for the build asked for");
    CHECK_MSG(ParseCoverage(CoverageBody("e1", 7, true), c, err, "B9") && !c.complete
              && c.reason.find("another client build") != std::string::npos, "the same report asked for another build");
    CHECK_MSG(ParseCoverage(CoverageBody("e1", 7, true), c, err) && c.claimed && c.sets.size() == 2
              && c.sets["login"].required == 2418 && c.sets["background"].ok == 72280, "the set lines are read");
    // QC (2026-10-20): a bare claim, and the first Session 16 broker's accepted-absent report.
    CHECK_MSG(!ParseCoverage("bfcp 2\ncoverage 1\ncomplete 1\ngeneration 1\nend\n", c, err) && !c.complete,
              "a bare \"complete 1\" with no sets and no header is no report");
    const std::string withAbsent = ReportEdit(
        ReportEdit(CoverageBody("e1", 7, true),
                   "set login required 2418 ok 2418 absent 0 unowned 0 missing 0 ambiguous 0 unavailable 0",
                   "set login required 2418 ok 2356 absent 62 unowned 0 missing 0 ambiguous 0 unavailable 0"),
        "", "A\tlogin\tarena_vs.png");
    CHECK_MSG(!ParseCoverage(withAbsent, c, err) && !c.complete, "accepted-absent A rows are not this protocol");
    const std::string absentClaim = ReportEdit(CoverageBody("e1", 7, true),
        "set login required 2418 ok 2418 absent 0 unowned 0 missing 0 ambiguous 0 unavailable 0",
        "set login required 2418 ok 2356 absent 62 unowned 0 missing 0 ambiguous 0 unavailable 0");
    CHECK_MSG(ParseCoverage(absentClaim, c, err) && !c.complete && c.absent == 62,
              "absent names in a report that claims complete: not complete");

    // Session 18: the report names the client files its manifest was derived from.
    const InputFixture& f = Inputs();
    const std::string full = CoverageBody("e1", 7, true);
    const std::string tableRow = "I\tlocalstate\t" + f.table + "\t" + f.tableDigest;
    const std::string mapRow = "I\tpackage\tAssets/Resources/resourceMap\t" + f.mapDigest;
    CHECK_MSG(ParseCoverage(full, c, err) && c.complete && c.inputCount == 2 && c.inputs.size() == 2
              && c.inputs[0].root == "localstate" && c.inputs[0].path == f.table && c.inputs[1].root == "package"
              && c.inputs[1].path == "Assets/Resources/resourceMap", "the inputs and their I rows are read");
    const std::string noInputs = ReportEdit(ReportEdit(ReportEdit(full, "inputs 2", ""), tableRow, ""), mapRow, "");
    CHECK_MSG(!ParseCoverage(noInputs, c, err) && err.find("no inputs") != std::string::npos,
              "a report without the inputs field (a Session 17 broker) is no report: " + err);
    const std::string zero = ReportEdit(ReportEdit(ReportEdit(full, "inputs 2", "inputs 0"), tableRow, ""), mapRow, "");
    CHECK_MSG(ParseCoverage(zero, c, err) && !c.complete && c.reason.find("without naming the client files") != std::string::npos,
              "complete 1 naming no client file is not complete: " + c.reason);
    CHECK_MSG(ParseCoverage(ReportEdit(full, mapRow, ""), c, err) && !c.complete
              && c.reason.find("inputs count and its rows disagree") != std::string::npos,
              "an I row missing from the count: not complete (" + c.reason + ")");
    const char* const badRows[] = {
        "I\tsystem\tx.dat\tsha256:", "I\tpackage\tAssets/../x.dat\tsha256:", "I\tlocalstate\ta/x.dat\tsha256:",
        "I\tpackage\t/Assets/x\tsha256:", "I\tpackage\tAssets\\x\tsha256:", "I\tlocalstate\tC:x.dat\tsha256:",
        "I\tlocalstate\t\tsha256:", "I\tlocalstate\tx.dat\tsha256:abcd", "I\tlocalstate\tx.dat" };
    for (const char* row : badRows)
    {
        std::string line(row);
        if (line.size() > 7 && line.compare(line.size() - 7, 7, "sha256:") == 0)
            line += std::string(64, 'c');
        CHECK_MSG(!ParseCoverage(ReportEdit(full, mapRow, line), c, err), std::string("a malformed I row is no report: ") + row);
    }
    std::string twice = tableRow;
    for (size_t i = 0; i < twice.size(); ++i)
        twice[i] = static_cast<char>(toupper(static_cast<unsigned char>(twice[i])));
    twice = "I\tlocalstate\t" + twice.substr(13, f.table.size()) + "\t" + f.tableDigest;
    CHECK_MSG(!ParseCoverage(ReportEdit(full, mapRow, twice), c, err), "the same LocalState file twice (any case): no report");
}

void TestClientInputs()
{
    const InputFixture& f = Inputs();
    std::vector<ClientInput> in(2);
    in[0].root = "localstate";
    in[0].path = f.table;
    in[0].digest = f.tableDigest;
    in[1].root = "package";
    in[1].path = "Assets/Resources/resourceMap";
    in[1].digest = f.mapDigest;
    std::string why;
    CHECK_MSG(VerifyClientInputs(in, f.localState, f.package, why), "the client holds exactly the inputs: " + why);
    std::string noSep = f.localState.substr(0, f.localState.size() - 1);
    CHECK_MSG(VerifyClientInputs(in, noSep, f.package, why), "the LocalState path without its trailing separator: " + why);
    CHECK_MSG(!VerifyClientInputs(std::vector<ClientInput>(), f.localState, f.package, why), "no input: never verified");
    CHECK_MSG(!VerifyClientInputs(in, std::string(), f.package, why) && why.find("not known") != std::string::npos,
              "LocalState not known yet: fails closed (" + why + ")");
    CHECK_MSG(!VerifyClientInputs(in, f.localState, f.localState, why) && why.find("cannot be read") != std::string::npos,
              "another package folder: the package file is not there (" + why + ")");

    WriteBytes(f.localState + f.table, f.tableBytes + "!");
    CHECK_MSG(!VerifyClientInputs(in, f.localState, f.package, why) && why.find("is not the one") != std::string::npos,
              "the table's bytes changed: not the manifest's input (" + why + ")");
    WriteBytes(f.localState + f.table, f.tableBytes);
    CHECK(VerifyClientInputs(in, f.localState, f.package, why));

    const char* const others[] = { "Ver6_TestKey1.dat", "Ver7_TestKey1_2.dat", "ver8_testkey1.dat" };
    for (const char* other : others)
    {
        WriteBytes(f.localState + other, "another copy");
        CHECK_MSG(!VerifyClientInputs(in, f.localState, f.package, why) && why.find("also holds") != std::string::npos,
                  std::string("LocalState also holds ") + other + ": which copy the game reads is unknown (" + why + ")");
        DeleteFileA((f.localState + other).c_str());
    }
    WriteBytes(f.localState + "Ver7_OtherKey.dat", "a table of another key");
    WriteBytes(f.localState + "Ver7_TestKey1.dat.tmp", "not a table file");
    CHECK_MSG(VerifyClientInputs(in, f.localState, f.package, why),
              "files of another table, or not table files, are not another version: " + why);
    DeleteFileA((f.localState + "Ver7_OtherKey.dat").c_str());
    DeleteFileA((f.localState + "Ver7_TestKey1.dat.tmp").c_str());

    std::vector<ClientInput> missing = in;
    missing[0].path = "Ver9_Missing1.dat";
    CHECK_MSG(!VerifyClientInputs(missing, f.localState, f.package, why) && why.find("cannot be read") != std::string::npos,
              "a named table this client lacks: not verified (" + why + ")");
    std::vector<ClientInput> plain = in;
    plain[0].path = "notes.txt";
    WriteBytes(f.localState + "notes.txt", f.tableBytes);
    CHECK_MSG(VerifyClientInputs(plain, f.localState, f.package, why), "a LocalState file that is no table: only its bytes: " + why);
    DeleteFileA((f.localState + "notes.txt").c_str());
}

namespace {

struct CorpusCase
{
    std::string name, expect, build, body;
};

//! offline-proxy/tests/fixtures/coverage_reports.txt -- shared with the BF-WorkingDirRust harness.
std::vector<CorpusCase> ReadCoverageCorpus(const std::string& path)
{
    std::vector<CorpusCase> cases;
    std::istringstream in(Str(ReadFileBytes(path)));
    std::string line;
    CorpusCase c;
    bool inBody = false;
    while (std::getline(in, line))
    {
        if (!line.empty() && line[line.size() - 1] == '\r')
            line.erase(line.size() - 1);
        if (inBody)
        {
            if (line == ">>>")
            {
                cases.push_back(c);
                inBody = false;
            }
            else
                c.body += line + "\n";
        }
        else if (line.compare(0, 3, "== ") == 0)
        {
            c = CorpusCase();
            c.name = line.substr(3);
        }
        else if (line.compare(0, 7, "expect ") == 0)
            c.expect = line.substr(7);
        else if (line.compare(0, 6, "build ") == 0)
            c.build = line.substr(6);
        else if (line == "<<<")
        {
            inBody = true;
            c.body.clear();
        }
    }
    return cases;
}

} // namespace

void TestCoverageCorpus()
{
    const std::vector<CorpusCase> cases = ReadCoverageCorpus(std::string(BF_TEST_FIXTURES) + "\\coverage_reports.txt");
    CHECK_MSG(cases.size() >= 25, "the shared coverage-report corpus is read (" + std::to_string(cases.size()) + " cases)");
    for (size_t i = 0; i < cases.size(); ++i)
    {
        CoverageInfo c;
        std::string err;
        const bool parsed = ParseCoverage(cases[i].body, c, err, cases[i].build);
        const std::string got = !parsed ? "unreadable" : c.complete ? "complete" : "incomplete";
        CHECK_MSG(got == cases[i].expect, "corpus \"" + cases[i].name + "\": expected " + cases[i].expect + ", got "
                  + got + " (" + (parsed ? c.reason : err) + ")");
        CHECK_MSG(parsed || !c.complete, "corpus \"" + cases[i].name + "\": an unreadable report is never complete");
    }
}

void TestStartupDecisions()
{
    InputsScope inputs;
    FakeBroker b;
    b.Put("ui/a.png", Bytes("A"));
    Provider p(&b, 1 << 20, 1 << 20);
    p.SetAutoStart(false);
    startup::Env& s = startup::env();
    s.provider = nullptr;
    CHECK_MSG(!startup::DecideCensus().skip, "no provider (build declined): the census is built");
    CHECK_MSG(!startup::DecidePrompt().skip, "no provider: the prompt is the player's");
    s.provider = &p;
    s.build = "B1";
    s.haveCoverage = false;
    b.coverage = CoverageBody(b.epoch, b.generation, true);
    startup::Decision d = startup::DecideCensus();
    CHECK_MSG(!d.skip && d.why.find("has not adopted an index yet") != std::string::npos,
              "provider not yet active, report complete: BUILT -- stock until active (QC 2026-10-20 finding 4)");
    CHECK_MSG(!startup::DecidePrompt().skip, "the prompt needs an ACTIVE provider");

    std::string why;
    CHECK(p.InitializeOnce(why));
    d = startup::DecideCensus();
    CHECK_MSG(d.skip && d.coverage.generation == p.PinnedGeneration(), "active, report for the served generation: left out");
    CHECK_MSG(b.lastCoverageQuery.find("build=B1") != std::string::npos, "the report is asked for this client build");

    b.Put("ui/c.png", Bytes("C"));              // the broker moves on...
    b.coverage = CoverageBody(b.epoch, b.generation, true);
    CHECK(p.PollOnce(why) && p.HasPending());
    d = startup::DecideCensus();
    CHECK_MSG(!d.skip && d.why.find("newer generation") != std::string::npos,
              "a generation the provider has not adopted yet: built");
    p.SafePoint("startup test");
    d = startup::DecideCensus();
    CHECK_MSG(d.skip, "adopted at a scene change: left out again");

    b.coverage = CoverageBody(b.epoch, b.generation + 5, true);
    s.haveCoverage = false;
    d = startup::DecideCensus();
    CHECK_MSG(!d.skip && d.why.find("the report describes") != std::string::npos,
              "a report for another generation never applies to this one");
    b.coverage = CoverageBody("other-epoch", b.generation, true);
    s.haveCoverage = false;
    CHECK_MSG(!startup::DecideCensus().skip, "nor one from another broker run (epoch)");
    b.coverage = CoverageBody(b.epoch, b.generation, false, true, true, true, "set login: 1 unowned");
    s.haveCoverage = false;
    d = startup::DecideCensus();
    CHECK_MSG(!d.skip && d.why.find("set login: 1 unowned") != std::string::npos, "incomplete: built, reason logged");
    b.coverage = CoverageBody(b.epoch, b.generation, true, false);
    s.haveCoverage = false;
    CHECK_MSG(!startup::DecideCensus().skip, "a report for another client build: built");
    b.coverage.clear();
    s.haveCoverage = false;
    d = startup::DecideCensus();
    CHECK_MSG(!d.skip && d.why.find("404") != std::string::npos, "an older broker without the report: built");
    b.coverage = "<html>not a report</html>";
    s.haveCoverage = false;
    CHECK_MSG(!startup::DecideCensus().skip, "an unreadable report: built");
    b.coverage = CoverageBody(b.epoch, b.generation, true);
    b.unreachable = true;
    s.haveCoverage = false;
    CHECK_MSG(!startup::DecideCensus().skip, "broker unreachable: built");
    CHECK_MSG(!startup::DecidePrompt().skip, "broker unreachable: the prompt is the player's");
    b.unreachable = false;
    s.haveCoverage = false;
    CHECK(startup::DecideCensus().skip);

    // Session 18: a complete report proves nothing about another client's tables.
    const InputFixture& f = Inputs();
    WriteBytes(f.localState + f.table, f.tableBytes + " (another build of the table)");
    d = startup::DecideCensus();
    CHECK_MSG(!d.skip && d.why.find("not derived from this client's own files") != std::string::npos
              && d.why.find(f.table) != std::string::npos, "this client's table differs from the manifest's: built -- " + d.why);
    CHECK_MSG(!startup::DecidePrompt().skip, "and the prompt is the player's");
    WriteBytes(f.localState + f.table, f.tableBytes);
    CHECK_MSG(startup::DecideCensus().skip, "the client's own table again: left out");
    WriteBytes(f.localState + "Ver8_TestKey1.dat", "a newer copy the game may read instead");
    d = startup::DecideCensus();
    CHECK_MSG(!d.skip && d.why.find("also holds Ver8_TestKey1.dat") != std::string::npos,
              "another version of the table in LocalState: built -- " + d.why);
    DeleteFileA((f.localState + "Ver8_TestKey1.dat").c_str());
    {
        InputsScope elsewhere(f.package, f.package);   // a LocalState without the table
        d = startup::DecideCensus();
        CHECK_MSG(!d.skip && d.why.find("cannot be read") != std::string::npos, "the table missing: built -- " + d.why);
    }
    {
        hooks::Env& hk = hooks::env();
        bool known;
        {
            std::lock_guard<std::mutex> lock(hk.prefixLock);
            known = hk.prefixKnown;
            hk.prefixKnown = false;                  // the game has not resolved its writable path yet
        }
        const auto fu = hk.sharedFileUtils;
        hk.sharedFileUtils = nullptr;
        d = startup::DecideCensus();
        CHECK_MSG(!d.skip && d.why.find("folder is not known yet") != std::string::npos,
                  "LocalState not known yet: built -- " + d.why);
        hk.sharedFileUtils = fu;
        std::lock_guard<std::mutex> lock(hk.prefixLock);
        hk.prefixKnown = known;
    }
    CHECK_MSG(startup::DecideCensus().skip, "restored: left out");

    hooks::Env& h = hooks::env();
    const long assets = h.mainQueuedAssets, state = h.mainQueuedState;
    h.mainQueuedAssets = 0;
    h.mainQueuedState = 4;
    d = startup::DecidePrompt();
    CHECK_MSG(d.skip && d.why.find("4 client-state") != std::string::npos,
              "complete, nothing but client state queued: the prompt may be left out");
    h.mainQueuedAssets = 2;
    d = startup::DecidePrompt();
    CHECK_MSG(!d.skip && d.why.find("2 asset name(s)") != std::string::npos,
              "any asset queued for background download: the player is asked");
    h.mainQueuedAssets = 0;
    b.coverage = CoverageBody(b.epoch, b.generation, false, true, true, true, "set background: 3 unowned");
    CHECK_MSG(!startup::DecidePrompt().skip, "incomplete: the player is asked");
    b.coverage = CoverageBody(b.epoch, b.generation + 1, true);
    CHECK_MSG(!startup::DecidePrompt().skip, "a report for another generation: the player is asked");

    b.coverage = CoverageBody(b.epoch, b.generation, true);
    b.enabled = false;                            // switched off mid-session
    CHECK(!p.PollOnce(why));
    p.SafePoint("startup test: off");
    CHECK(p.State() == ProviderState::Dormant);
    CHECK_MSG(!startup::DecideCensus().skip && !startup::DecidePrompt().skip, "dormant: both stay the game's");
    h.mainQueuedAssets = assets;
    h.mainQueuedState = state;
    s.provider = nullptr;
    s.haveCoverage = false;
}

//! QC 2026-10-20 finding 4: the census is the game's until the provider is ACTIVE on the generation
//! a complete report describes -- a delayed start, a start that never succeeds, a disabled broker and
//! a report older than the adopted generation all keep it.
void TestStartupProviderStates()
{
    InputsScope inputs;
    startup::Env& s = startup::env();
    std::string why;
    const auto setCoverage = [](FakeBroker& d, bool complete) {
        std::lock_guard<std::mutex> g(d.lock);
        d.coverage = CoverageBody(d.epoch, d.generation, complete);
    };

    // A delayed start: the broker is still indexing (status "ready 0") yet already offers a complete report.
    {
        FakeBroker d;
        d.Put("ui/a.png", Bytes("A"));
        {
            std::lock_guard<std::mutex> g(d.lock);
            d.ready = false;
        }
        setCoverage(d, true);
        Provider q(&d, 1 << 20, 1 << 20);             // auto-start: its thread keeps waiting for the broker
        s.provider = &q;
        s.build = "B1";
        s.haveCoverage = false;
        startup::Decision x = startup::DecideCensus();
        CHECK_MSG(q.State() == ProviderState::Starting && !x.skip
                  && x.why.find("has not adopted an index yet") != std::string::npos,
                  "delayed start, complete report offered: the census is built (" + x.why + ")");
        CHECK_MSG(!startup::DecidePrompt().skip, "delayed start: the prompt is the player's");
        {
            std::lock_guard<std::mutex> g(d.lock);
            d.ready = true;                              // indexing finished
        }
        for (int i = 0; i < 400 && !q.Active(); ++i)
            Sleep(25);
        CHECK_MSG(q.Active(), "the provider activates once the broker is ready");
        setCoverage(d, true);
        x = startup::DecideCensus();
        CHECK_MSG(x.skip && x.coverage.generation == q.PinnedGeneration(),
                  "active on the report's generation: left out (the delayed start recovers) -- " + x.why);
        s.provider = nullptr;
        s.haveCoverage = false;
        q.Stop();
    }

    // A start that never succeeds: every decision, however often, stays the game's.
    {
        FakeBroker d;
        d.Put("ui/a.png", Bytes("A"));
        {
            std::lock_guard<std::mutex> g(d.lock);
            d.ready = false;
        }
        setCoverage(d, true);
        Provider q(&d, 1 << 20, 1 << 20);
        s.provider = &q;
        s.build = "B1";
        s.haveCoverage = false;
        bool anySkip = false;
        for (int i = 0; i < 4; ++i)
        {
            anySkip = anySkip || startup::DecideCensus().skip || startup::DecidePrompt().skip;
            Sleep(60);
        }
        CHECK_MSG(!anySkip && q.State() == ProviderState::Starting,
                  "a start that never succeeds: the census is built and the prompt asked, every time");
        s.provider = nullptr;
        s.haveCoverage = false;
        q.Stop();
    }

    // Disabled at start: dormant from the first answer; a complete report changes nothing.
    {
        FakeBroker d;
        d.Put("ui/a.png", Bytes("A"));
        {
            std::lock_guard<std::mutex> g(d.lock);
            d.enabled = false;
        }
        setCoverage(d, true);
        Provider q(&d, 1 << 20, 1 << 20);
        q.SetAutoStart(false);
        CHECK(!q.InitializeOnce(why) && q.State() == ProviderState::Dormant);
        s.provider = &q;
        s.build = "B1";
        s.haveCoverage = false;
        CHECK_MSG(!startup::DecideCensus().skip && !startup::DecidePrompt().skip,
                  "disabled at start: dormant, both stay the game's");
        s.provider = nullptr;
    }

    // A report older than the generation the provider has adopted.
    {
        FakeBroker d;
        d.Put("ui/a.png", Bytes("A"));
        Provider q(&d, 1 << 20, 1 << 20);
        q.SetAutoStart(false);
        CHECK(q.InitializeOnce(why));
        s.provider = &q;
        s.build = "B1";
        s.haveCoverage = false;
        setCoverage(d, true);
        CHECK_MSG(startup::DecideCensus().skip, "active, report for the adopted generation: left out (control)");
        const std::string old = d.coverage;
        d.Put("ui/b.png", Bytes("B"));                  // the broker moves on
        CHECK(q.PollOnce(why) && q.HasPending());
        q.SafePoint("stale report test");                // ...and the provider adopts it
        CHECK(!q.HasPending() && q.PinnedGeneration() == d.generation);
        {
            std::lock_guard<std::mutex> g(d.lock);
            d.coverage = old;                            // the report still describes the older generation
        }
        startup::Decision x = startup::DecideCensus();
        CHECK_MSG(!x.skip && x.why.find("the report describes") != std::string::npos,
                  "a report older than the adopted generation: built -- " + x.why);
        CHECK_MSG(!startup::DecidePrompt().skip, "and the prompt is the player's");
        setCoverage(d, true);
        CHECK_MSG(startup::DecideCensus().skip, "the report catches up: left out again");

        // Every report the shared corpus calls incomplete or unreadable keeps the census, live.
        const std::vector<CorpusCase> cases = ReadCoverageCorpus(std::string(BF_TEST_FIXTURES) + "\\coverage_reports.txt");
        size_t kept = 0, judged = 0;
        for (size_t i = 0; i < cases.size(); ++i)
        {
            if (cases[i].expect == "complete")
                continue;
            ++judged;
            {
                std::lock_guard<std::mutex> g(d.lock);
                d.coverage = cases[i].body;
            }
            s.haveCoverage = false;
            kept += startup::DecideCensus().skip || startup::DecidePrompt().skip ? 0 : 1;
        }
        CHECK_MSG(judged >= 20 && kept == judged, "every incomplete or unreadable corpus report keeps the census and the prompt ("
                  + std::to_string(kept) + "/" + std::to_string(judged) + ")");
        s.provider = nullptr;
        s.haveCoverage = false;
    }
}

void TestStartupHooks()
{
    FakeBroker b;
    b.Put("ui/a.png", Bytes("A"));
    Provider p(&b, 1 << 20, 1 << 20);
    p.SetAutoStart(false);
    std::string why;
    CHECK(p.InitializeOnce(why));
    SetupEnv(&p, "C:\\Startup\\LocalState\\");
    InputsScope inputs;            // the game's writable path is the fixture's LocalState
    startup::Env& s = startup::env();
    s.provider = &p;
    s.build = "B1";
    s.haveCoverage = false;
    s.trueCensus = FakeCensus;
    s.censusMap = &g_fakeCensusMap;
    s.trueLoadUserDefaults = FakeLoadUserDefaults;
    *reinterpret_cast<long*>(g_fakeMapObject + 0x18) = 71329;
    hooks::Env& h = hooks::env();
    const long assets = h.mainQueuedAssets;
    h.mainQueuedAssets = 0;
    const size_t logBefore = ReadFileBytes(LogPath()).size();

    b.coverage = CoverageBody(b.epoch, b.generation, true);
    g_fakeCensusMap = nullptr;
    int calls = g_fakeCensusCalls;
    const long skipped = s.censusSkipped, built = s.censusBuilt;
    startup::Hook_Census();
    CHECK_MSG(g_fakeCensusCalls == calls && g_fakeCensusMap == nullptr && s.censusSkipped == skipped + 1,
              "covered: the census is left out and the map stays null (existsLocalFile checks files itself)");
    b.coverage = CoverageBody(b.epoch, b.generation, false, true, true, true, "set login: 2 unowned");
    s.haveCoverage = false;
    startup::Hook_Census();
    CHECK_MSG(g_fakeCensusCalls == calls + 1 && g_fakeCensusMap == g_fakeMapObject && s.censusBuilt == built + 1,
              "not covered: the game's census runs once");
    CHECK_EQ(startup::CensusEntries(), 71329L);
    g_fakeCensusMap = nullptr;
    std::string log = Str(ReadFileBytes(LogPath())).substr(logBefore);
    CHECK(log.find("LocalState census #") != std::string::npos && log.find("LEFT OUT") != std::string::npos);
    CHECK(log.find("built [caller") != std::string::npos && log.find("71329 name(s)") != std::string::npos
          && log.find("set login: 2 unowned") != std::string::npos);

    // The prompt's flag read: a stored answer is always the game's.
    const int deletes = fake::deleteCalls;
    int loads = g_fakeLoadCalls;
    g_fakeStored = "true";
    b.coverage = CoverageBody(b.epoch, b.generation, true);
    const char* v = startup::Hook_PromptFlagRead(MakeString(startup::kPromptKey));
    CHECK_MSG(v && std::string(v) == "true" && g_fakeLoadCalls == loads + 1 && g_fakeLastKey == startup::kPromptKey,
              "a stored answer stands");
    CHECK_MSG(fake::deleteCalls == deletes + 1, "the by-value key is freed once, by the callee");
    g_fakeStored.clear();
    v = startup::Hook_PromptFlagRead(MakeString(startup::kPromptKey));
    CHECK_MSG(v == startup::kAnswerNo && std::string(v) == "false" && fake::deleteCalls == deletes + 2,
              "unset, covered, nothing queued: read as \"false\" for this session (the key still freed once)");
    h.mainQueuedAssets = 1;
    v = startup::Hook_PromptFlagRead(MakeString(startup::kPromptKey));
    CHECK_MSG(v && *v == 0, "unset and an asset queued for background download: \"\" -- the game asks");
    h.mainQueuedAssets = 0;
    b.coverage = CoverageBody(b.epoch, b.generation, false, true, true, true, "set background: 1 missing");
    v = startup::Hook_PromptFlagRead(MakeString(startup::kPromptKey));
    CHECK_MSG(v && *v == 0, "unset and not covered: the game asks");
    b.coverage = CoverageBody(b.epoch, b.generation, true);
    v = startup::Hook_PromptFlagRead(MakeString("BUN_VER"));
    CHECK_MSG(v && *v == 0 && g_fakeLastKey == "BUN_VER", "any other key reads the game's own value");

    // The ABI LoginScene::updateEvent uses at 0x8E51A8.
    loads = g_fakeLoadCalls;
    v = CallPromptLikeTheGame(MakeString(startup::kPromptKey));
    CHECK_MSG(v == startup::kAnswerNo && g_fakeLoadCalls == loads + 1, "called like the game: same answer");
    CHECK_MSG(g_abiEbx == 0x11111111 && g_abiEsi == 0x22222222 && g_abiEdi == 0x33333333 && g_abiEspDelta == 0,
              "callee-saved registers and the stack are the caller's after the call (cdecl, the caller pops 18h)");
    log = Str(ReadFileBytes(LogPath())).substr(logBefore);
    CHECK(log.find("background-download prompt LEFT OUT") != std::string::npos
          && log.find("background-download prompt left to the player") != std::string::npos
          && log.find("stored answer \"true\" stands") != std::string::npos);
    h.mainQueuedAssets = assets;
    s.provider = nullptr;
    s.haveCoverage = false;
    hooks::env().provider = nullptr;
}

/*!
* The REAL broker's coverage report through the provider and the startup decisions (Session 16),
* started by BF-WorkingDirRust/scripts/test_content_startup_live.py: BF_COVERAGE_PORT, the client
* build to ask for (BF_COVERAGE_BUILD) and the expected verdict (BF_COVERAGE_EXPECT = complete |
* incomplete), and the folders the decisions check the report's client inputs in
* (BF_COVERAGE_LOCALSTATE, BF_COVERAGE_PACKAGE; Session 18).  Nothing is written.
*/
void TestLiveStartupCoverage()
{
    const char* portEnv = getenv("BF_COVERAGE_PORT");
    const char* buildEnv = getenv("BF_COVERAGE_BUILD");
    const char* expectEnv = getenv("BF_COVERAGE_EXPECT");
    if (!portEnv || !buildEnv || !expectEnv)
    {
        t::Skip("startup coverage against a live broker", "BF_COVERAGE_PORT / BF_COVERAGE_BUILD / BF_COVERAGE_EXPECT not set");
        return;
    }
    const char* lsEnv = getenv("BF_COVERAGE_LOCALSTATE");
    const char* pkgEnv = getenv("BF_COVERAGE_PACKAGE");
    InputsScope inputs(lsEnv ? lsEnv : "C:\\no-such-folder\\LocalState\\", pkgEnv ? pkgEnv : "C:\\no-such-folder\\");
    // "other-client": the report is complete, but for client files this one does not hold.
    const std::string expect(expectEnv);
    const bool expectComplete = expect == "complete" || expect == "other-client";
    const bool expectSkip = expect == "complete";
    WinInetBroker broker("127.0.0.1", static_cast<unsigned short>(atoi(portEnv)));
    Provider p(&broker, 48u << 20, 16u << 20);
    p.SetAutoStart(false);
    {
        // Before the provider has adopted any index, whatever the real report says (QC finding 4).
        startup::Env& s0 = startup::env();
        s0.provider = &p;
        s0.build = buildEnv;
        s0.haveCoverage = false;
        const startup::Decision early = startup::DecideCensus();
        CHECK_MSG(!p.Active() && !early.skip && early.why.find("has not adopted an index yet") != std::string::npos,
                  "before the provider adopts an index: the census is built (" + early.why + ")");
        CHECK_MSG(!startup::DecidePrompt().skip, "before the provider adopts an index: the prompt is the player's");
        s0.provider = nullptr;
    }
    std::string why;
    bool active = false;
    for (int i = 0; i < 600 && !(active = p.InitializeOnce(why)); ++i)
        Sleep(500);
    CHECK_MSG(active, "the provider activates against the live broker: " + why);
    CoverageInfo c;
    CHECK_MSG(p.FetchCoverage(buildEnv, c, why), "the live report is readable: " + why);
    CHECK_MSG(c.parsed && c.complete == expectComplete,
              std::string("live report complete=") + (c.complete ? "1" : "0") + ", expected " + expectEnv + " (" + c.reason + ")");
    CHECK_MSG(c.epoch == p.Epoch() && c.generation == p.PinnedGeneration(),
              "the report names the epoch and generation the provider adopted");
    startup::Env& s = startup::env();
    s.provider = &p;
    s.build = buildEnv;
    s.haveCoverage = false;
    hooks::Env& h = hooks::env();
    const long assets = h.mainQueuedAssets;
    h.mainQueuedAssets = 0;
    const startup::Decision census = startup::DecideCensus();
    const startup::Decision prompt = startup::DecidePrompt();
    CHECK_MSG(census.skip == expectSkip, "census decision: " + census.why);
    CHECK_MSG(prompt.skip == expectSkip, "prompt decision: " + prompt.why);
    if (expect == "other-client")
        CHECK_MSG(census.why.find("not derived from this client's own files") != std::string::npos
                  && prompt.why.find("not derived from this client's own files") != std::string::npos,
                  "a complete report for other client files: both fall back for that reason -- " + census.why);
    h.mainQueuedAssets = 1;
    CHECK_MSG(!startup::DecidePrompt().skip, "with an asset queued for background download the player is asked");
    h.mainQueuedAssets = assets;
    printf("live startup coverage: %s, generation %llu, %llu absent-everywhere name(s); census %s, prompt %s\n",
           c.complete ? "complete" : "incomplete", static_cast<unsigned long long>(c.generation),
           static_cast<unsigned long long>(c.absent), census.skip ? "left out" : "built", prompt.skip ? "left out" : "asked");
    s.provider = nullptr;
    s.haveCoverage = false;
}

void TestStartupSignatures()
{
    const char* dirEnv = getenv("BF_APPX_DIR");
    const std::string dir = dirEnv ? dirEnv : "C:\\Users\\Evan\\BF\\BraveFrontierAppxClient";
    DiskImage exe;
    if (!exe.Load(dir + "\\BraveFrontier.Windows.exe"))
    {
        t::Skip("startup sites vs the real client EXE", "BF_APPX_DIR not set / client not extracted");
        return;
    }
    std::string why;
    for (size_t i = 0; i < sizeof kStartupSignatures / sizeof kStartupSignatures[0]; ++i)
    {
        size_t avail = 0;
        const uint8_t* p = exe.At(kStartupSignatures[i].rva, avail);
        CHECK_MSG(kStartupSignatures[i].module == 0 && p && MatchSignature(kStartupSignatures[i], p, avail, why),
                  std::string(kStartupSignatures[i].name) + ": " + why);
    }
    size_t avail = 0;
    const uint8_t* call = exe.At(0x8E51A8, avail);
    int32_t rel = 0;
    CHECK(call && call[0] == 0xE8);
    memcpy(&rel, call + 1, sizeof rel);
    CHECK_MSG(0x8E51A8u + 5u + static_cast<uint32_t>(rel) == 0x240300u, "the redirected call targets SaveUtils::loadUserDefaults");
    DiskImage changed = exe;
    uint8_t* test = const_cast<uint8_t*>(changed.At(0x8E51B0, avail));
    CHECK(test && test[0] == 0x85 && test[1] == 0xC0);       // test eax, eax after the call
    test[1] = 0xDB;                                          // test ebx, ebx
    const SiteSignature* sig = nullptr;
    for (size_t i = 0; i < sizeof kStartupSignatures / sizeof kStartupSignatures[0]; ++i)
        if (strcmp(kStartupSignatures[i].name, "promptFlagRead") == 0)
            sig = &kStartupSignatures[i];
    CHECK_MSG(sig && !MatchSignature(*sig, changed.At(sig->rva, avail), avail, why),
              "one changed byte after the prompt's read declines the startup edits");
}

namespace {

//! A Detours-style x86 detour written by hand into synthetic code: the target gets E9 to the hook
//! and CC up to the end of the displaced bytes; the trampoline gets those bytes and E9 back.
void PlaceDetour(uint8_t* target, size_t displaced, uint8_t* trampoline, const uint8_t* hook)
{
    memcpy(trampoline, target, displaced);
    trampoline[displaced] = 0xE9;
    const int32_t back = static_cast<int32_t>(reinterpret_cast<uintptr_t>(target + displaced)
                                              - reinterpret_cast<uintptr_t>(trampoline + displaced + 5));
    memcpy(trampoline + displaced + 1, &back, 4);
    target[0] = 0xE9;
    const int32_t to = static_cast<int32_t>(reinterpret_cast<uintptr_t>(hook) - reinterpret_cast<uintptr_t>(target + 5));
    memcpy(target + 1, &to, 4);
    for (size_t i = 5; i < displaced; ++i)
        target[i] = 0xCC;
}

} // namespace

//! cp_core.h SnapshotSites / VerifySitesSince on synthetic code (no client needed): every rule, the
//! accepted case and one negative per way a site can differ from its snapshot.
void TestSiteSnapshots()
{
    uint8_t* mem = static_cast<uint8_t*>(VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    CHECK(mem != nullptr);
    if (!mem)
        return;
    // censusLookup's real first 18 bytes and existsLocalFile's 6-byte prologue (Detours displaces 6).
    const uint8_t lookup[18] = { 0x55, 0x8B, 0xEC, 0x51, 0x56, 0x8B, 0x35, 0x20, 0x7E, 0x99, 0x01, 0x57, 0x8B, 0xF9,
                                 0x85, 0xF6, 0x74, 0x4B };
    const uint8_t exists[12] = { 0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8, 0x6A, 0xFF, 0x68, 0x48, 0x04, 0x2F };
    const SiteSignature sigs[2] = {
        { "censusLookup", 0, 0x100, "558BEC51568B35207E9901578BF985F6744B", "xxxxxxx????xxxxxxx" },
        { "existsLocal", 0, 0x200, "558BEC83E4F86AFF6848042F", "xxxxxxxxx???" },
    };
    uint8_t* site = mem + 0x100;
    uint8_t* site2 = mem + 0x200;
    uint8_t* tramp = mem + 0x800;
    uint8_t* tramp2 = mem + 0x900;
    uint8_t* hook = mem + 0x1000;
    uint8_t* other = mem + 0x1100;
    hook[0] = other[0] = 0xC3;
    const auto reset = [&]() {
        memcpy(site, lookup, sizeof lookup);
        memcpy(site2, exists, sizeof exists);
        memset(tramp, 0xCC, 0x100);
        memset(tramp2, 0xCC, 0x100);
    };
    reset();
    std::string why;
    std::vector<SiteSnapshot> snaps;
    CHECK_MSG(SnapshotSites(reinterpret_cast<uintptr_t>(mem), sigs, 2, snaps, why) && snaps.size() == 2
              && snaps[0].bytes.size() == 18, "the untouched sites match and are kept: " + why);
    const SharedSite shared[2] = { { "censusLookup", "isFileAlreadyDownloaded" }, { "existsLocal", "existsLocalFile" } };
    CHECK_MSG(VerifySitesSince(snaps, nullptr, 0, nullptr, 0, why), "unchanged sites pass with no detour: " + why);

    CodeDetour d[2];
    d[0].owner = d[1].owner = "content provider";
    d[0].site = "isFileAlreadyDownloaded";
    d[0].target = reinterpret_cast<uintptr_t>(site);
    d[0].detour = reinterpret_cast<uintptr_t>(hook);
    d[0].trampoline = tramp;
    d[1].site = "existsLocalFile";
    d[1].target = reinterpret_cast<uintptr_t>(site2);
    d[1].detour = reinterpret_cast<uintptr_t>(hook);
    d[1].trampoline = tramp2;
    PlaceDetour(site, 5, tramp, hook);
    PlaceDetour(site2, 6, tramp2, hook);
    CHECK_MSG(!MatchSignature(sigs[0], site, 18, why) && why == "censusLookup: byte +0 is E9, expected 55",
              "the old rule declines the provider's own detour: " + why);
    CHECK_MSG(VerifySitesSince(snaps, d, 2, shared, 2, why), "the expected detours, 5 and 6 bytes displaced: " + why);

    const auto declines = [&](const char* what, const char* needle, const CodeDetour* ds, size_t nd,
                              const SharedSite* sh, size_t ns) {
        std::string w;
        const bool ok = VerifySitesSince(snaps, ds, nd, sh, ns, w);
        CHECK_MSG(!ok && w.find(needle) != std::string::npos, std::string(what) + " declines (" + w + ")");
    };
    declines("a detour on a site none is expected on", "was 55 on the untouched image", d, 2, shared + 1, 1);
    declines("the expected detour not recorded", "isFileAlreadyDownloaded detour expected on it is not recorded",
             d + 1, 1, shared, 2);
    {
        CodeDetour wrong = d[0];
        wrong.site = "getTexture";
        CodeDetour both[2] = { wrong, d[1] };
        declines("a detour recorded under another site", "is not recorded", both, 2, shared, 2);
    }
    {
        int32_t keep = 0;
        memcpy(&keep, site + 1, 4);
        const int32_t to = static_cast<int32_t>(reinterpret_cast<uintptr_t>(other) - reinterpret_cast<uintptr_t>(site + 5));
        memcpy(site + 1, &to, 4);
        declines("a jump to anything but the recorded detour", "is a jump to", d, 2, shared, 2);
        memcpy(site + 1, &keep, 4);
    }
    {
        CodeDetour moved = d[0];
        moved.target += 20;
        CodeDetour both[2] = { moved, d[1] };
        declines("a recorded detour outside the verified bytes", "is not inside the verified bytes", both, 2, shared, 2);
    }
    tramp[2] ^= 0x01;
    declines("a trampoline that does not hold the displaced bytes", "trampoline does not hold", d, 2, shared, 2);
    tramp[2] ^= 0x01;
    tramp[6] ^= 0x01;
    declines("a trampoline that does not jump back to the next instruction", "trampoline does not hold", d, 2, shared, 2);
    tramp[6] ^= 0x01;
    site2[5] = 0x90;
    declines("anything but CC after the jump in the displaced bytes", "not the CC", d, 2, shared, 2);
    site2[5] = 0xCC;
    site[7] ^= 0xFF;
    declines("a changed relocated byte after the detour (the map global's address)", "byte +7", d, 2, shared, 2);
    site[7] ^= 0xFF;
    site[15] = 0xFF;
    declines("a changed instruction after the detour (the null test)", "byte +15", d, 2, shared, 2);
    site[15] = 0xF6;
    CHECK_MSG(VerifySitesSince(snaps, d, 2, shared, 2, why), "every negative restored: accepted again: " + why);
    memcpy(site, lookup, 5);
    declines("a recorded detour that is not in place", "is 55, not the content provider's isFileAlreadyDownloaded detour",
             d, 2, shared, 2);
    VirtualFree(mem, 0, MEM_RELEASE);
}

namespace {

//! The real client EXE laid out by RVA in this process's memory, its code sections executable like
//! the loader maps them (never run): what main.cpp's attach sequence patches.
struct MappedImage
{
    uint8_t* base = nullptr;
    size_t size = 0;
    MappedImage() = default;
    MappedImage(const MappedImage&) = delete;
    MappedImage& operator=(const MappedImage&) = delete;
    ~MappedImage()
    {
        if (base)
            VirtualFree(base, 0, MEM_RELEASE);
    }
    bool Load(const std::string& path)
    {
        const std::vector<uint8_t> raw = ReadFileBytes(path);
        if (raw.size() < 4096)
            return false;
        const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(&raw[0]);
        const IMAGE_NT_HEADERS32* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(&raw[0] + dos->e_lfanew);
        size = nt->OptionalHeader.SizeOfImage;
        base = static_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!base)
            return false;
        memcpy(base, &raw[0], nt->OptionalHeader.SizeOfHeaders);
        const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            const size_t n = std::min<size_t>(sec[i].SizeOfRawData, size - sec[i].VirtualAddress);
            if (sec[i].PointerToRawData + n <= raw.size())
                memcpy(base + sec[i].VirtualAddress, &raw[sec[i].PointerToRawData], n);
        }
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            DWORD old = 0;
            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
                VirtualProtect(base + sec[i].VirtualAddress, sec[i].Misc.VirtualSize, PAGE_EXECUTE_READ, &old);
        }
        return true;
    }
};

//! ContentProvider_Attach's detours of the game EXE, placed with the real Detours on an image (its
//! cocos2d detours patch the other module): the same sites, hook functions and single transaction,
//! recorded as cp_hooks.cpp records them.  tests/fixtures/check_attach_overlap.py checks this list
//! against cp_hooks.cpp.
struct ProviderExeDetours
{
    struct Row { const char* site; PVOID hook; void* pointer; };
    Row rows[5] = {
        { "existsLocalFile", reinterpret_cast<PVOID>(hooks::Hook_ExistsLocalFile), nullptr },
        { "isFileAlreadyDownloaded", reinterpret_cast<PVOID>(hooks::Hook_IsFileAlreadyDownloaded), nullptr },
        { "getTexture", reinterpret_cast<PVOID>(hooks::GetTextureThunk), nullptr },
        { "addLoadFile", reinterpret_cast<PVOID>(hooks::Hook_AddLoadFile), nullptr },
        { "addLoadFilePriority", reinterpret_cast<PVOID>(hooks::Hook_AddLoadFilePriority), nullptr },
    };
    CodeDetour records[5];
    size_t count = 0;
    bool attached = false;

    static uint32_t Rva(const char* site)
    {
        for (size_t i = 0; i < sizeof kSiteSignatures / sizeof kSiteSignatures[0]; ++i)
            if (strcmp(kSiteSignatures[i].name, site) == 0 && kSiteSignatures[i].module == 0)
                return kSiteSignatures[i].rva;
        return 0;
    }
    bool Attach(uintptr_t base)
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        for (Row& r : rows)
        {
            r.pointer = reinterpret_cast<void*>(base + Rva(r.site));
            DetourAttach(&r.pointer, r.hook);
        }
        if (DetourTransactionCommit() != NO_ERROR)
            return false;
        count = 0;
        for (const Row& r : rows)
        {
            CodeDetour& d = records[count++];
            d.owner = "content provider";
            d.site = r.site;
            d.target = base + Rva(r.site);
            d.detour = reinterpret_cast<uintptr_t>(DetourCodeFromPointer(r.hook, nullptr));
            d.trampoline = static_cast<const uint8_t*>(r.pointer);
        }
        attached = true;
        return true;
    }
    void Detach()
    {
        if (!attached)
            return;
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        for (Row& r : rows)
            DetourDetach(&r.pointer, r.hook);
        DetourTransactionCommit();
        attached = false;
        count = 0;
    }
};

//! The rule Startup_Attach applied until Session 17: every startup signature against live memory,
//! after the provider had attached (the C16 client's "DECLINED: censusLookup: ... byte +0 is E9").
bool PreSession17StartupCheck(uintptr_t base, std::string& why)
{
    for (size_t i = 0; i < sizeof kStartupSignatures / sizeof kStartupSignatures[0]; ++i)
    {
        const SiteSignature& sig = kStartupSignatures[i];
        if (!MatchSignature(sig, reinterpret_cast<const uint8_t*>(base + sig.rva), strlen(sig.mask), why))
            return false;
    }
    return true;
}

bool SameBytes(const uint8_t* a, const std::vector<uint8_t>& b, size_t& first)
{
    for (size_t i = 0; i < b.size(); ++i)
        if (a[i] != b[i])
        {
            first = i;
            return false;
        }
    return true;
}

} // namespace

/*!
* Session 17 regression: main.cpp's attach sequence on the real executable's bytes with the real
* Detours -- Startup_Prepare's check of the untouched image, ContentProvider_Attach's detours of
* the game EXE, then Startup_Attach -- and the C16 client's failure (collected log 20261021-055758:
* "startup coverage path DECLINED: censusLookup: ... byte +0 is E9, expected 55") reproduced on the
* same bytes by the rule that preceded it.  Then the detach order restores every byte, and each
* negative control declines with nothing of the startup edits left in place.
*/
void TestStartupAttachOrder()
{
    const char* dirEnv = getenv("BF_APPX_DIR");
    const std::string dir = dirEnv ? dirEnv : "C:\\Users\\Evan\\BF\\BraveFrontierAppxClient";
    MappedImage img;
    if (!img.Load(dir + "\\BraveFrontier.Windows.exe"))
    {
        t::Skip("startup attach order on the real client EXE", "BF_APPX_DIR not set / client not extracted");
        return;
    }
    const uintptr_t base = reinterpret_cast<uintptr_t>(img.base);
    const std::vector<uint8_t> file(img.base, img.base + img.size);
    startup::Env& s = startup::env();
    const uintptr_t savedBase = s.exeBase;
    const std::string savedBuild = s.build;
    void* const* savedMap = s.censusMap;
    const startup::Census_t savedCensus = s.trueCensus;
    const startup::LoadUserDefaults_t savedLoad = s.trueLoadUserDefaults;
    s.provider = nullptr;
    FakeBroker b;
    Provider p(&b, 1 << 20, 1 << 20);
    p.SetAutoStart(false);
    uint8_t* census = img.base + 0xE415D0;
    uint8_t* promptCall = img.base + 0x8E51A8;
    const auto startupEditsAbsent = [&]() {
        return s.provider == nullptr && memcmp(census, &file[0xE415D0], 5) == 0
            && memcmp(promptCall, &file[0x8E51A8], 5) == 0;
    };
    std::string why;

    // 1. Startup_Prepare: the untouched image.
    std::vector<SiteSnapshot> untouched;
    CHECK_MSG(startup::PrepareImage(base, untouched, why) && untouched.size() == 9,
              "Startup_Prepare: identity and the 9 startup sites match the untouched image: " + why);
    // 2. ContentProvider_Attach (its game-EXE detours, real Detours).
    ProviderExeDetours provider;
    CHECK_MSG(provider.Attach(base), "the provider's five game-EXE detours commit on the image");
    const uint8_t* lookup = img.base + 0xE417E0;
    CHECK_MSG(lookup[0] == 0xE9 && provider.count == 5, "the provider's detour now starts the downloaded-name lookup");
    // The old rule on these bytes: exactly what the C16 client logged.
    std::string old;
    CHECK_MSG(!PreSession17StartupCheck(base, old) && old == "censusLookup: byte +0 is E9, expected 55",
              "the pre-Session-17 rule declines the provider's own detour, as the client did: " + old);
    const uint8_t* tr = provider.records[1].trampoline;
    char seen[200];
    sprintf_s(seen, "lookup %02X %02X %02X %02X %02X, trampoline %02X %02X %02X %02X %02X %02X", lookup[0], lookup[1],
              lookup[2], lookup[3], lookup[4], tr[0], tr[1], tr[2], tr[3], tr[4], tr[5]);
    std::vector<SiteSnapshot> late;
    std::string lateWhy;
    CHECK_MSG(!startup::PrepareImage(base, late, lateWhy) && lateWhy == "censusLookup: byte +0 is E9, expected 55",
              "checking the untouched image only after the provider attached declines the same way: " + lateWhy);
    // 3. Startup_Attach: verified again, then installed.
    CHECK_MSG(startup::AttachImage(base, &p, untouched, provider.records, provider.count, why),
              "Startup_Attach after the provider: installed (" + why + ")");
    int32_t rel = 0;
    memcpy(&rel, census + 1, 4);
    CHECK_MSG(census[0] == 0xE9 && reinterpret_cast<uintptr_t>(census + 5 + rel)
                                       == reinterpret_cast<uintptr_t>(DetourCodeFromPointer(reinterpret_cast<PVOID>(startup::Hook_Census), nullptr)),
              "the census builder now jumps to Hook_Census");
    memcpy(&rel, promptCall + 1, 4);
    CHECK_MSG(promptCall[0] == 0xE8 && reinterpret_cast<uintptr_t>(promptCall + 5 + rel)
                                           == reinterpret_cast<uintptr_t>(&startup::Hook_PromptFlagRead),
              "the prompt's flag read now calls Hook_PromptFlagRead");
    CHECK_MSG(s.provider == &p && s.exeBase == base, "the decisions are bound to the provider last");
    CHECK_MSG(!startup::AttachImage(base, &p, untouched, provider.records, provider.count, why)
                  && why.find("already installed") != std::string::npos,
              "a second attach is refused (" + why + ")");
    // 4. main.cpp's detach order: Startup_Detach, then ContentProvider_Detach -- every byte is the file's again.
    startup::DetachImage();
    CHECK_MSG(startupEditsAbsent(), "Startup_Detach: decisions unbound, census and prompt call restored");
    provider.Detach();
    size_t first = 0;
    CHECK_MSG(SameBytes(img.base, file, first), "after both detaches the image is the file again (first difference at +"
              + std::to_string(first) + ")");

    // 5. Negative controls: each on the provider-patched image, each declining with no startup edit left.
    CHECK(provider.Attach(base));
    const auto declines = [&](const char* what, const char* needle, const CodeDetour* ds, size_t nd) {
        std::string w;
        const bool ok = startup::AttachImage(base, &p, untouched, ds, nd, w);
        if (ok)
            startup::DetachImage();
        CHECK_MSG(!ok && w.find(needle) != std::string::npos && startupEditsAbsent(),
                  std::string(what) + " declines and changes nothing (" + w + ")");
    };
    declines("no provider detours recorded", "isFileAlreadyDownloaded detour expected on it is not recorded", nullptr, 0);
    {
        CodeDetour others[5];
        size_t n = 0;
        for (size_t i = 0; i < provider.count; ++i)
            if (strcmp(provider.records[i].site, "isFileAlreadyDownloaded") != 0)
                others[n++] = provider.records[i];
        declines("the lookup's detour missing from the provider's records", "is not recorded", others, n);
    }
    {
        // The lookup's E9 retargeted to another provider hook: a jump, but not the expected detour.
        DWORD orig = 0;
        uint8_t* site = img.base + 0xE417E0;
        VirtualProtect(site, 18, PAGE_EXECUTE_READWRITE, &orig);
        int32_t keep = 0;
        memcpy(&keep, site + 1, 4);
        const uintptr_t elsewhere = provider.records[0].detour;    // Hook_ExistsLocalFile's code
        const int32_t to = static_cast<int32_t>(elsewhere - reinterpret_cast<uintptr_t>(site + 5));
        memcpy(site + 1, &to, 4);
        declines("a jump at the lookup to anything but its recorded detour", "is a jump to", provider.records,
                 provider.count);
        memcpy(site + 1, &keep, 4);
        // A changed relocated byte after the detour (the map global's address) and a changed null test.
        site[7] ^= 0xFF;
        declines("a changed relocated byte of the lookup after the detour", "byte +7", provider.records, provider.count);
        site[7] ^= 0xFF;
        site[15] = 0xFF;
        declines("a changed null test in the lookup", "byte +15", provider.records, provider.count);
        site[15] = 0xF6;
        VirtualProtect(site, 18, orig, &orig);
    }
    {
        // An unrelated patch at another startup site: the prompt branch's `test eax, eax`.
        uint8_t* test = img.base + 0x8E51B0;
        DWORD oldProt = 0;
        VirtualProtect(test, 2, PAGE_EXECUTE_READWRITE, &oldProt);
        CHECK(test[0] == 0x85 && test[1] == 0xC0);
        test[1] = 0xDB;
        declines("an unrelated patch at another startup site (promptFlagRead)", "promptFlagRead: byte", provider.records,
                 provider.count);
        test[1] = 0xC0;
        VirtualProtect(test, 2, oldProt, &oldProt);
    }
    {
        // A detour where none is expected: another "provider" detour on the census builder itself.
        void* target = census;
        PVOID hook = reinterpret_cast<PVOID>(hooks::Hook_ExistsLocalFile);
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&target, hook);
        CHECK(DetourTransactionCommit() == NO_ERROR);
        CodeDetour extra[6];
        for (size_t i = 0; i < provider.count; ++i)
            extra[i] = provider.records[i];
        extra[5] = provider.records[0];
        extra[5].site = "census";
        extra[5].target = reinterpret_cast<uintptr_t>(census);
        extra[5].trampoline = static_cast<const uint8_t*>(target);
        std::string w;
        const bool ok = startup::AttachImage(base, &p, untouched, extra, 6, w);
        if (ok)
            startup::DetachImage();
        CHECK_MSG(!ok && w.find("census: byte +0 is E9, was 55") != std::string::npos && s.provider == nullptr,
                  "a detour on a startup site where none is expected declines (" + w + ")");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&target, hook);
        CHECK(DetourTransactionCommit() == NO_ERROR);
        CHECK_MSG(memcmp(census, &file[0xE415D0], 5) == 0, "that detour removed again");
    }
    {
        // The provider's trampoline for the lookup no longer holding the displaced bytes.
        uint8_t* tramp = const_cast<uint8_t*>(provider.records[1].trampoline);
        CHECK(strcmp(provider.records[1].site, "isFileAlreadyDownloaded") == 0);
        DWORD oldProt = 0;
        VirtualProtect(tramp, 16, PAGE_EXECUTE_READWRITE, &oldProt);
        tramp[1] ^= 0x01;
        declines("the lookup's trampoline not holding the displaced bytes", "trampoline does not hold", provider.records,
                 provider.count);
        // An attach that wrongly went ahead committed a Detours transaction, which makes every
        // trampoline region read-only again: unprotect before restoring.
        DWORD unused = 0;
        VirtualProtect(tramp, 16, PAGE_EXECUTE_READWRITE, &unused);
        tramp[1] ^= 0x01;
        VirtualProtect(tramp, 16, oldProt, &unused);
    }
    {
        std::vector<SiteSnapshot> none;
        CHECK_MSG(!startup::AttachImage(base, &p, none, provider.records, provider.count, why)
                      && why.find("not checked on the untouched image") != std::string::npos && startupEditsAbsent(),
                  "an empty snapshot declines (" + why + ")");
        CHECK_MSG(!startup::AttachImage(base, nullptr, untouched, provider.records, provider.count, why)
                      && why.find("content provider is not installed") != std::string::npos && startupEditsAbsent(),
                  "no provider declines (" + why + ")");
    }
    {
        // An unsupported binary: another TimeDateStamp in the untouched image's header.
        IMAGE_NT_HEADERS32* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(
            img.base + reinterpret_cast<IMAGE_DOS_HEADER*>(img.base)->e_lfanew);
        const DWORD stamp = nt->FileHeader.TimeDateStamp;
        nt->FileHeader.TimeDateStamp ^= 1;
        std::vector<SiteSnapshot> other;
        CHECK_MSG(!startup::PrepareImage(base, other, why) && why.find("build mismatch") != std::string::npos,
                  "Startup_Prepare declines another build (" + why + ")");
        nt->FileHeader.TimeDateStamp = stamp;
    }
    CHECK_MSG(startup::AttachImage(base, &p, untouched, provider.records, provider.count, why),
              "every negative restored: installed again (" + why + ")");
    startup::DetachImage();
    provider.Detach();
    CHECK_MSG(SameBytes(img.base, file, first), "the image is the file again after the negative controls (first difference at +"
              + std::to_string(first) + ")");
    printf("startup attach order on the real EXE: after the provider's detours (%s) the pre-Session-17 rule declined "
           "\"%s\"; Startup_Prepare -> provider -> Startup_Attach installed; detached in main.cpp's order the image "
           "was the file's bytes again\n", seen, old.c_str());

    s.provider = nullptr;
    s.exeBase = savedBase;
    s.build = savedBuild;
    s.censusMap = savedMap;
    s.trueCensus = savedCensus;
    s.trueLoadUserDefaults = savedLoad;
}

namespace {

//! One read the game makes of an owned file: the flat name, its policy path, the
//! getFileData mode and whether the LocalState path joins with '/' (a SuperAnim
//! page: "<dir of the .sam>/<page>") or '\\' (getLocalPath).
struct GameRead
{
    std::string name, rel, mode;
    bool forwardSlash = false;
};

//! What the client's own CRT returns for fopen(path, mode) + fread: the oracle a
//! served read must equal (text mode included).
std::vector<uint8_t> CrtRead(const std::string& path, const char* mode)
{
    std::vector<uint8_t> out;
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), mode) != 0 || !f)
        return out;
    uint8_t buf[65536];
    for (;;)
    {
        const size_t n = fread(buf, 1, sizeof buf, f);
        if (!n)
            break;
        out.insert(out.end(), buf, buf + n);
    }
    fclose(f);
    return out;
}

} // namespace

/*!
* A generated family policy (BF-WorkingDirRust/scripts/gen_unit_family_policy.py,
* gen_effect_family_policy.py) served by a REAL broker over the real, read-only
* game_content tree, started by BF-WorkingDirRust/scripts/test_content_family_live.py.
* BF_FAMILY_PORT, BF_FAMILY_ROOT (that content root) and BF_FAMILY_EXPECT select
* it; the expectation file holds "owned <count>", "present <name> <rel>" and
* "notowned <name>" lines -- the names a traced client session downloaded and
* the names a generator left to the legacy path -- and, for a phase whose files
* the game reads in more than one way (C3: SuperAnim and particles), "read
* <name> <rel> <mode> <b|f>" (one getFileData call exactly as the game makes it)
* and "fileexist <name>" (the dependency processor's isFileExist check).
* Nothing is written: unlike the fixture case above, the tree is the game's.
*/
// ------------------------------------------------ audio reader (Session 15) ----

namespace {

//! Exactly what the audio reader (x86 0xEC0030) does with a file, through the
//! hooked imports: fopen_s(&f, path, "rb"); fread(buf, 1, 210, f) while it
//! returns > 0; fclose(f).  Returns fopen_s's errno.
int ReadLikeTheAudioReader(const std::string& path, std::vector<uint8_t>& out)
{
    out.clear();
    FILE* f = nullptr;
    const int err = hooks::Hook_FopenS(&f, path.c_str(), "rb");
    if (err || !f)
        return err ? err : -1;
    uint8_t buf[0xD2];
    for (;;)
    {
        const size_t n = hooks::Hook_Fread(buf, 1, sizeof buf, f);
        if (static_cast<int>(n) <= 0)
            break;
        out.insert(out.end(), buf, buf + n);
    }
    hooks::Hook_Fclose(f);
    return 0;
}

//! A fresh, empty folder playing the client's LocalState (disposable: removed first).
std::string DisposableLocalState(const char* name)
{
    const std::string dir = TempDir() + "\\" + name;
    std::string cmd = "rmdir /s /q \"" + dir + "\" 2>nul";
    system(cmd.c_str());
    CreateDirectoryA(dir.c_str(), nullptr);
    return dir;
}

std::vector<std::string> FilesIn(const std::string& dir)
{
    std::vector<std::string> out;
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA((dir + "\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
        return out;
    do
    {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            out.push_back(fd.cFileName);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    std::sort(out.begin(), out.end());
    return out;
}

void WriteFileBytes(const std::string& path, const std::vector<uint8_t>& bytes)
{
    std::ofstream o(path.c_str(), std::ios::binary);
    o.write(reinterpret_cast<const char*>(bytes.empty() ? nullptr : &bytes[0]), static_cast<std::streamsize>(bytes.size()));
}

int g_realFopenS = 0;
int __cdecl CountingFopenS(FILE** f, const char* path, const char* mode)
{
    ++g_realFopenS;
    return fopen_s(f, path, mode);
}

//! The audio hooks' environment: the REAL CRT behind them, so a passthrough opens real files.
void SetupAudio(Provider* p, const std::string& localState)
{
    SetupEnv(p, localState + "\\");
    hooks::Env& e = hooks::env();
    e.trueFopenS = CountingFopenS;
    e.trueFread = fread;
    e.trueFclose = fclose;
    e.trueAddLoadFile = fake::AddLoadFile;
    e.trueAddLoadFilePriority = fake::AddLoadFilePriority;
    e.audioHooked = true;
}

} // namespace

// The audio reader's file contract served from provider RAM (Session 15 P1).
// The client's LocalState is a DISPOSABLE empty folder: the script-named
// sounds are absent from it, as on an uncached client.
void TestAudioHooks()
{
    const std::vector<uint8_t> water = RandomBytes(27742, 210);       // bf210_se_water2.mp3's size
    const std::vector<uint8_t> union_ = RandomBytes(26561, 1126);
    FakeBroker b;
    b.Put("sound/bf210_se_water2.mp3", water);
    b.Put("sound/bf1126_zin_act_union.mp3", union_);
    b.Put("sound/bgm/bf001_title.mp3", RandomBytes(5 * 210 + 7, 1));
    Provider p(&b, 1 << 20, 1 << 20);
    p.SetAutoStart(false);
    std::string why;
    CHECK(p.InitializeOnce(why));
    const std::string ls = DisposableLocalState("audio_localstate");
    SetupAudio(&p, ls);
    hooks::Env& e = hooks::env();
    CHECK_MSG(FilesIn(ls).empty(), "the disposable LocalState starts empty (no cached sounds)");

    // Cold: served from the broker, nothing written, nothing left open.
    std::vector<uint8_t> got;
    const long served = e.audioServed;
    const uint64_t fetches = p.Stats().fetches;
    const int realBefore = g_realFopenS;
    CHECK(ReadLikeTheAudioReader(ls + "\\bf210_se_water2.mp3", got) == 0);
    CHECK_MSG(got == water, "cold: the reader gets the broker's bytes exactly (27,742 bytes in 210-byte reads)");
    CHECK_MSG(g_realFopenS == realBefore, "cold: the CRT never opened the path");
    CHECK_MSG(FilesIn(ls).empty(), "cold: nothing was written to LocalState");
    CHECK(hooks::OpenMemFiles() == 0 && e.audioServed == served + 1 && p.Stats().fetches == fetches + 1);
    CHECK(ReadLikeTheAudioReader(ls + "\\bf001_title.mp3", got) == 0 && got.size() == 5 * 210 + 7);

    // Warm repeat (the sound manager unloads its oldest effect and decodes it again later).
    const uint64_t hits = p.Stats().cacheHits;
    CHECK(ReadLikeTheAudioReader(ls + "\\BF210_SE_WATER2.MP3", got) == 0 && got == water);
    CHECK_MSG(p.Stats().cacheHits == hits + 1 && p.Stats().fetches == fetches + 2,
              "warm repeat: served from RAM, no new fetch (case-insensitive name)");

    // The download contract: an owned, present sound is "downloaded" and never queued.
    hooks::MsvcString water_s = MakeString("bf210_se_water2.mp3");
    const int ex = fake::originalExists;
    CHECK(hooks::Hook_ExistsLocalFile(&water_s, nullptr) && fake::originalExists == ex);
    const int queued = fake::originalAddLoadFilePriority;
    hooks::MsvcString q = MakeString("bf210_se_water2.mp3");
    hooks::Hook_AddLoadFilePriority(nullptr, nullptr, 0, 0, q);
    CHECK_MSG(fake::originalAddLoadFilePriority == queued,
              "the script dependency processor's queue entry for an owned sound is dropped (provider serves it)");
    hooks::MsvcString legacy = MakeString("bf999_not_owned.mp3");
    hooks::Hook_AddLoadFilePriority(nullptr, nullptr, 0, 0, legacy);
    CHECK_MSG(fake::originalAddLoadFilePriority == queued + 1 && fake::lastQueued == "bf999_not_owned.mp3",
              "a sound the policy does not own is still downloaded");

    // Real files pass through, interleaved with RAM files.
    const std::vector<uint8_t> local = RandomBytes(1000, 7);
    WriteFileBytes(ls + "\\bf999_not_owned.mp3", local);
    FILE* real = nullptr;
    FILE* ram = nullptr;
    CHECK(hooks::Hook_FopenS(&real, (ls + "\\bf999_not_owned.mp3").c_str(), "rb") == 0 && real);
    CHECK(hooks::Hook_FopenS(&ram, (ls + "\\bf1126_zin_act_union.mp3").c_str(), "rb") == 0 && ram && ram != real);
    std::vector<uint8_t> a, c;
    uint8_t buf[0xD2];
    for (;;)
    {
        const size_t n1 = hooks::Hook_Fread(buf, 1, sizeof buf, real);
        a.insert(a.end(), buf, buf + n1);
        const size_t n2 = hooks::Hook_Fread(buf, 1, sizeof buf, ram);
        c.insert(c.end(), buf, buf + n2);
        if (!n1 && !n2)
            break;
    }
    CHECK_MSG(a == local && c == union_, "a real FILE* and a RAM file read side by side, each its own bytes");
    CHECK(hooks::OpenMemFiles() == 1 && hooks::Hook_Fclose(ram) == 0 && hooks::OpenMemFiles() == 0);
    CHECK_MSG(hooks::Hook_Fclose(real) == 0, "a real FILE* is closed by the CRT");

    // fread edge cases on a RAM file (the CRT's item semantics).
    CHECK(hooks::Hook_FopenS(&ram, (ls + "\\bf001_title.mp3").c_str(), "rb") == 0);
    CHECK(hooks::Hook_Fread(buf, 0, 10, ram) == 0 && hooks::Hook_Fread(buf, 1, 0, ram) == 0
          && hooks::Hook_Fread(nullptr, 1, 10, ram) == 0);
    size_t total = 0;
    for (int i = 0; i < 5; ++i)
        total += hooks::Hook_Fread(buf, 1, 210, ram);
    CHECK(total == 1050 && hooks::Hook_Fread(buf, 4, 10, ram) == 1);   // 7 bytes left: one complete 4-byte item
    CHECK_MSG(hooks::Hook_Fread(buf, 1, 210, ram) == 0, "after the last byte fread returns 0 (the reader's loop ends)");
    hooks::Hook_Fclose(ram);

    // A write mode on an owned name is a tripwire (the CRT still does it, as for fopen).
    const long writes = e.persistentWrites;
    FILE* w = nullptr;
    CHECK(hooks::Hook_FopenS(&w, (ls + "\\bf1126_zin_act_union.mp3").c_str(), "wb") == 0 && w);
    CHECK(e.persistentWrites == writes + 1);
    fclose(w);
    DeleteFileA((ls + "\\bf1126_zin_act_union.mp3").c_str());

    // Missing: removed from game_content -> ENOENT; a stale cached copy is NEVER read.
    WriteFileBytes(ls + "\\bf210_se_water2.mp3", Bytes("STALE CACHED COPY"));
    b.Remove("sound/bf210_se_water2.mp3");
    CHECK(p.PollOnce(why));
    hooks::SafePoint("audio test");
    const long missing = e.audioMissing;
    const int realNow = g_realFopenS;
    FILE* gone = reinterpret_cast<FILE*>(1);
    CHECK_MSG(hooks::Hook_FopenS(&gone, (ls + "\\bf210_se_water2.mp3").c_str(), "rb") == ENOENT && !gone,
              "missing: fopen_s fails with ENOENT and a null FILE*");
    CHECK_MSG(g_realFopenS == realNow && e.audioMissing == missing + 1, "missing: the stale cached copy is not opened");
    const int ex2 = fake::originalExists;
    CHECK(!hooks::Hook_ExistsLocalFile(&water_s, nullptr) && fake::originalExists == ex2);

    // Unhooked audio: sound names stay the game's own whatever the index says.
    e.audioHooked = false;
    hooks::MsvcString union_s = MakeString("bf1126_zin_act_union.mp3");
    const int ex3 = fake::originalExists;
    hooks::Hook_ExistsLocalFile(&union_s, nullptr);
    CHECK_MSG(fake::originalExists == ex3 + 1, "audio reader not hooked: existsLocalFile of an owned sound is the game's");
    const int queued2 = fake::originalAddLoadFilePriority;
    hooks::MsvcString q2 = MakeString("bf1126_zin_act_union.mp3");
    hooks::Hook_AddLoadFilePriority(nullptr, nullptr, 0, 0, q2);
    CHECK_MSG(fake::originalAddLoadFilePriority == queued2 + 1, "audio reader not hooked: the sound is still downloaded");
    unsigned long size = 0;
    const int gfd = fake::originalGetFileData;
    unsigned char* data = hooks::Hook_GetFileData(nullptr, nullptr, (ls + "\\bf1126_zin_act_union.mp3").c_str(), "rb", &size);
    CHECK(fake::originalGetFileData == gfd + 1);
    fake::Delete(data);
    CHECK(hooks::IsAudioName("x.MP3") && hooks::IsAudioName("y.wav") && !hooks::IsAudioName("mp3")
          && !hooks::IsAudioName("a.mp3.png"));
    e.audioHooked = true;

    // Provider unavailable (dormant): everything is the game's own -- the cached copy plays.
    Provider dormant(&b, 1 << 20, 1 << 20);
    dormant.SetAutoStart(false);
    SetupAudio(&dormant, ls);
    const int realDormant = g_realFopenS;
    CHECK(ReadLikeTheAudioReader(ls + "\\bf210_se_water2.mp3", got) == 0 && Str(got) == "STALE CACHED COPY");
    CHECK_MSG(g_realFopenS == realDormant + 1, "dormant provider: the CRT opens the cached copy, as without the proxy");
    CHECK_MSG(ReadLikeTheAudioReader(ls + "\\bf1126_zin_act_union.mp3", got) == ENOENT,
              "dormant provider: an uncached sound is missing, as without the proxy");
    CHECK(hooks::OpenMemFiles() == 0);
    free(union_s.bx.ptr);
    free(water_s.bx.ptr);   // q, q2 and legacy went by value: the callee freed them
    hooks::env().provider = nullptr;
}

/*!
* Against a REAL server broker (WinINet over loopback), started by
* BF-WorkingDirRust/scripts/test_content_audio_live.py with a policy that owns
* game_content's sounds, served from a disposable root.  BF_AUDIO_PORT,
* BF_AUDIO_ROOT (that root), BF_AUDIO_EXPECT and BF_AUDIO_LS (an empty
* disposable LocalState, holding only planted stale copies) select it.
*/
void TestLiveAudio()
{
    const char* portText = getenv("BF_AUDIO_PORT");
    const char* rootText = getenv("BF_AUDIO_ROOT");
    const char* expectText = getenv("BF_AUDIO_EXPECT");
    const char* lsText = getenv("BF_AUDIO_LS");
    if (!portText || !rootText || !expectText || !lsText)
    {
        t::Skip("audio reader integration", "BF_AUDIO_PORT / BF_AUDIO_ROOT / BF_AUDIO_EXPECT / BF_AUDIO_LS not set");
        return;
    }
    const std::string root = rootText, ls = lsText;
    std::string mode;
    size_t ownedCount = 0;
    std::vector<std::pair<std::string, std::string>> present;
    std::vector<std::string> absent, stale;
    {
        std::ifstream in(expectText);
        std::string kind, a, b2;
        while (in >> kind)
        {
            if (kind == "mode")
                in >> mode;
            else if (kind == "owned")
                in >> ownedCount;
            else if (kind == "present" && in >> a >> b2)
                present.push_back(std::make_pair(a, b2));
            else if (kind == "absent" && in >> a)
                absent.push_back(a);
            else if (kind == "stale" && in >> a)
                stale.push_back(a);
        }
    }
    CHECK_MSG((mode == "active" || mode == "dormant") && !present.empty(), std::string("expectations read from ") + expectText);
    WinInetBroker broker("127.0.0.1", static_cast<unsigned short>(atoi(portText)));
    Provider p(&broker, 48u << 20, 16u << 20);
    p.SetAutoStart(false);
    std::string why;
    bool settled = false;
    for (int i = 0; i < 240 && !settled; ++i)
    {
        settled = p.InitializeOnce(why) || (mode == "dormant" && p.State() == ProviderState::Dormant);
        if (!settled)
            Sleep(250);
    }
    CHECK_MSG(settled && (mode == "active" ? p.Active() : p.State() == ProviderState::Dormant),
              "provider " + mode + " against the audio broker: " + why);
    if (!settled)
        return;
    SetupAudio(&p, ls);
    const std::vector<std::string> before = FilesIn(ls);
    std::vector<uint8_t> got;
    if (mode == "active")
    {
        size_t exact = 0, bytes = 0;
        const size_t warm = present.size() < 5 ? present.size() : 5;
        const auto cold = [&](size_t i) {
            const std::vector<uint8_t> want = ReadFileBytes(root + "\\" + present[i].second);
            const int err = ReadLikeTheAudioReader(ls + "\\" + present[i].first, got);
            if (err == 0 && got == want && !want.empty())
                ++exact, bytes += got.size();
            else
                CHECK_MSG(false, "live audio: " + present[i].first + " not served byte-exact (errno " + std::to_string(err) + ")");
        };
        LARGE_INTEGER t0, t1, f;
        QueryPerformanceCounter(&t0);
        // The first sounds (the gate scripts' own), then re-opened at once, as the
        // sound manager does after unloading an effect: from RAM, no new fetch.
        for (size_t i = 0; i < warm; ++i)
            cold(i);
        const uint64_t fetches = p.Stats().fetches, hits = p.Stats().cacheHits;
        for (size_t i = 0; i < warm; ++i)
            CHECK(ReadLikeTheAudioReader(ls + "\\" + present[i].first, got) == 0);
        CHECK_MSG(p.Stats().fetches == fetches && p.Stats().cacheHits == hits + warm,
                  "live audio: warm repeats come from RAM (no new fetch)");
        printf("live audio: %u warm repeat(s) from RAM\n", static_cast<unsigned>(warm));
        for (size_t i = warm; i < present.size(); ++i)
            cold(i);
        QueryPerformanceCounter(&t1);
        QueryPerformanceFrequency(&f);
        printf("live audio: %u sound(s) served byte-exact to the audio reader contract (%u KB, %.0f ms; cache %u KB of 48 MB)\n",
               static_cast<unsigned>(exact), static_cast<unsigned>(bytes / 1024),
               1000.0 * static_cast<double>(t1.QuadPart - t0.QuadPart) / static_cast<double>(f.QuadPart),
               static_cast<unsigned>(p.CacheBytes() / 1024));
        for (size_t i = 0; i < absent.size(); ++i)
        {
            FILE* fp = reinterpret_cast<FILE*>(1);
            const int realBefore = g_realFopenS;
            const int err = hooks::Hook_FopenS(&fp, (ls + "\\" + absent[i]).c_str(), "rb");
            CHECK_MSG(err == ENOENT && !fp && g_realFopenS == realBefore,
                      "live audio: withdrawn " + absent[i] + " fails with ENOENT; its stale cached copy is not opened");
            hooks::MsvcString s = MakeString(absent[i]);
            const int ex = fake::originalExists;
            CHECK(!hooks::Hook_ExistsLocalFile(&s, nullptr) && fake::originalExists == ex);
            if (s.capacity >= 16)
                free(s.bx.ptr);
        }
        printf("live audio: %u withdrawn sound(s) reported missing, stale copies untouched\n",
               static_cast<unsigned>(absent.size()));
    }
    else
    {
        size_t legacy = 0;
        for (size_t i = 0; i < stale.size(); ++i)
        {
            const int realBefore = g_realFopenS;
            if (ReadLikeTheAudioReader(ls + "\\" + stale[i], got) == 0 && g_realFopenS == realBefore + 1
                && Str(got) == "STALE CACHED COPY " + stale[i])
                ++legacy;
        }
        CHECK_MSG(legacy == stale.size(), "live audio (dormant): every sound is the game's own cached copy");
        CHECK_MSG(ReadLikeTheAudioReader(ls + "\\" + present[0].first, got) == ENOENT,
                  "live audio (dormant): an uncached sound is missing, as without the proxy");
        printf("live audio: dormant broker -> %u cached cop(ies) read by the CRT, uncached sounds missing\n",
               static_cast<unsigned>(legacy));
    }
    CHECK_MSG(FilesIn(ls) == before, "live audio: nothing was written to the disposable LocalState");
    CHECK(hooks::OpenMemFiles() == 0);
    hooks::env().provider = nullptr;
}

void TestLiveFamilyPolicy()
{
    const char* portText = getenv("BF_FAMILY_PORT");
    const char* rootText = getenv("BF_FAMILY_ROOT");
    const char* expectText = getenv("BF_FAMILY_EXPECT");
    if (!portText || !rootText || !expectText)
    {
        t::Skip("family policy integration", "BF_FAMILY_PORT / BF_FAMILY_ROOT / BF_FAMILY_EXPECT not set");
        return;
    }
    const std::string root = rootText;
    size_t ownedCount = 0;
    std::vector<std::pair<std::string, std::string>> present;
    std::vector<std::string> notOwned;
    std::vector<GameRead> reads;
    std::vector<std::string> fileExist;
    {
        std::ifstream in(expectText);
        std::string kind, a, b, c, d;
        while (in >> kind)
        {
            if (kind == "owned")
                in >> ownedCount;
            else if (kind == "present" && in >> a >> b)
                present.push_back(std::make_pair(a, b));
            else if (kind == "notowned" && in >> a)
                notOwned.push_back(a);
            else if (kind == "read" && in >> a >> b >> c >> d)
            {
                GameRead r;
                r.name = a;
                r.rel = b;
                r.mode = c;
                r.forwardSlash = d == "f";
                reads.push_back(r);
            }
            else if (kind == "fileexist" && in >> a)
                fileExist.push_back(a);
        }
    }
    CHECK_MSG(ownedCount && !present.empty() && !notOwned.empty(), std::string("expectations read from ") + expectText);

    // What holding the policy's index costs this 32-bit process (the game's own
    // address space when the DLL runs): private bytes around the first load.
    const auto privateMb = []() {
        PROCESS_MEMORY_COUNTERS_EX mem;
        memset(&mem, 0, sizeof mem);
        mem.cb = sizeof mem;
        GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&mem), sizeof mem);
        return static_cast<double>(mem.PrivateUsage) / (1024.0 * 1024.0);
    };
    const double privateBefore = privateMb();
    WinInetBroker broker("127.0.0.1", static_cast<unsigned short>(atoi(portText)));
    Provider p(&broker, 64u << 20, 16u << 20);
    p.SetAutoStart(false);
    std::string why;
    bool up = false;
    LARGE_INTEGER t0, t1, freq;
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < 240 && !up; ++i)
    {
        up = p.InitializeOnce(why);
        if (!up)
            Sleep(250);
    }
    QueryPerformanceCounter(&t1);
    QueryPerformanceFrequency(&freq);
    CHECK_MSG(up, "provider activated against the family-policy broker: " + why);
    if (!up)
        return;
    printf("family policy: provider active after %.1f s; private bytes %.1f MB -> %.1f MB with the %u-name index\n",
           static_cast<double>(t1.QuadPart - t0.QuadPart) / static_cast<double>(freq.QuadPart), privateBefore,
           privateMb(), static_cast<unsigned>(ownedCount));
    {
        int status = 0;
        std::string body, error;
        IndexSnapshot snap;
        const bool ok = broker.GetText("/offline_mod/content/v1/index?since=0&epoch=", status, body, error)
            && status == 200 && ParseIndex(body, snap, error);
        CHECK_MSG(ok && snap.files.size() == ownedCount,
                  "the broker's full index lists the policy's " + std::to_string(ownedCount) + " names (got "
                  + std::to_string(snap.files.size()) + ") " + error);
    }

    size_t exact = 0;
    for (size_t i = 0; i < present.size(); ++i)
    {
        IndexEntry entry;
        const Ownership own = p.Classify(present[i].first, &entry);
        std::vector<uint8_t> out;
        std::string err;
        IndexEntry used;
        const ReadStatus st = p.Read(present[i].first, out, err, &used);
        std::string disk = root + "\\" + present[i].second;
        std::replace(disk.begin(), disk.end(), '/', '\\');
        const std::vector<uint8_t> bytes = ReadFileBytes(disk);
        const bool good = own == Ownership::Present && st == ReadStatus::Ok && used.rel == present[i].second
            && !bytes.empty() && out == bytes;
        exact += good ? 1 : 0;
        CHECK_MSG(good, present[i].first + " is owned and served byte-exact from " + present[i].second + " " + err);
    }
    printf("family policy: %u traced name(s) served byte-exact\n", static_cast<unsigned>(exact));
    for (size_t i = 0; i < notOwned.size(); ++i)
        CHECK_MSG(p.Classify(notOwned[i]) == Ownership::NotOwned, notOwned[i] + " stays with the legacy path");

    // The primary gate: requestFileWithEncode asks existsLocalFile before it
    // queues anything.  Owned names are answered by the provider alone;
    // everything else is the game's own check.
    SetupEnv(&p, "C:\\Live\\LocalState\\");
    const int exists = fake::originalExists;
    size_t answered = 0;
    for (size_t i = 0; i < present.size(); ++i)
    {
        hooks::MsvcString s = MakeString(present[i].first);
        answered += hooks::Hook_ExistsLocalFile(&s, nullptr) ? 1 : 0;
        if (s.capacity >= 16)
            free(s.bx.ptr);
    }
    CHECK_MSG(answered == present.size() && fake::originalExists == exists,
              "existsLocalFile answers present for every traced owned name without consulting LocalState");
    for (size_t i = 0; i < notOwned.size(); ++i)
    {
        hooks::MsvcString s = MakeString(notOwned[i]);
        hooks::Hook_ExistsLocalFile(&s, nullptr);
        if (s.capacity >= 16)
            free(s.bx.ptr);
    }
    CHECK_MSG(fake::originalExists == exists + static_cast<int>(notOwned.size()),
              "every traced legacy name is asked of the game's own existence check");

    // The enqueue filter with this live provider: the traced downloads of owned
    // names are never queued; the legacy ones reach the game's downloader.
    hooks::Env& e = hooks::env();
    e.trueAddLoadFile = fake::AddLoadFile;
    e.trueAddLoadFilePriority = fake::AddLoadFilePriority;
    const long suppressed = e.suppressedEnqueues;
    const int prio = fake::originalAddLoadFilePriority;
    for (size_t i = 0; i < present.size(); ++i)
    {
        const std::string folder = present[i].second.substr(0, present[i].second.rfind('/') + 1);
        hooks::Hook_AddLoadFilePriority(nullptr, nullptr, 1, 0, MakeString("/" + folder + present[i].first));
    }
    CHECK_MSG(fake::originalAddLoadFilePriority == prio
              && e.suppressedEnqueues == suppressed + static_cast<long>(present.size()),
              "every traced owned name is kept out of the download queue");
    for (size_t i = 0; i < notOwned.size(); ++i)
        hooks::Hook_AddLoadFilePriority(nullptr, nullptr, 1, 0, MakeString(notOwned[i]));
    CHECK_MSG(fake::originalAddLoadFilePriority == prio + static_cast<int>(notOwned.size()),
              "every traced legacy name is still queued for the game's own download");

    // Each read the game makes of the phase's files, through the hooked
    // getFileData with the path and mode the game passes, equals what the
    // client's CRT returns for that file (text mode included); none falls back
    // to the client cache, none reaches the downloader, nothing is written.
    if (!reads.empty())
    {
        const std::string ls = "C:\\Live\\LocalState";
        SetupEnv(&p, ls);
        e.trueAddLoadFile = fake::AddLoadFile;
        e.trueAddLoadFilePriority = fake::AddLoadFilePriority;
        const int origReads = fake::originalGetFileData;
        const int origQueue = fake::originalAddLoadFile + fake::originalAddLoadFilePriority;
        const long writes = e.persistentWrites;
        const long suppressedBefore = e.suppressedEnqueues;
        size_t same = 0, text = 0, slash = 0, queued = 0;
        for (size_t i = 0; i < reads.size(); ++i)
        {
            const GameRead& r = reads[i];
            const std::string path = ls + (r.forwardSlash ? "/" : "\\") + r.name;
            unsigned long size = 0;
            unsigned char* data = hooks::Hook_GetFileData(nullptr, nullptr, path.c_str(), r.mode.c_str(), &size);
            std::string disk = root + "\\" + r.rel;
            std::replace(disk.begin(), disk.end(), '/', '\\');
            const std::vector<uint8_t> want = CrtRead(disk, r.mode.c_str());
            const bool good = data && !want.empty() && size == want.size() && memcmp(data, &want[0], size) == 0;
            if (data)
                fake::Delete(data);
            same += good ? 1 : 0;
            text += good && r.mode.find('b') == std::string::npos ? 1 : 0;
            slash += good && r.forwardSlash ? 1 : 0;
            if (!good)
                CHECK_MSG(false, "game read of " + path + " (\"" + r.mode + "\") equals the CRT's read of " + r.rel);
            const std::string folder = r.rel.substr(0, r.rel.rfind('/') + 1);
            hooks::Hook_AddLoadFilePriority(nullptr, nullptr, 1, 0, MakeString("/" + folder + r.name));
            hooks::Hook_AddLoadFile(nullptr, nullptr, 1, MakeString(r.name));
            queued += 2;
        }
        CHECK_MSG(same == reads.size(), std::to_string(same) + " of " + std::to_string(reads.size())
                  + " game reads served exactly as the CRT reads the file");
        CHECK_MSG(fake::originalGetFileData == origReads, "no read of an owned name reached the client cache's reader");
        CHECK_MSG(fake::originalAddLoadFile + fake::originalAddLoadFilePriority == origQueue
                  && e.suppressedEnqueues == suppressedBefore + static_cast<long>(queued),
                  "every one of them is kept out of both download queues");
        CHECK_MSG(e.persistentWrites == writes, "no persistent write to an owned asset");
        printf("family policy: %u game read(s) byte-exact (%u text-mode, %u SuperAnim pages by '<dir>/<page>')\n",
               static_cast<unsigned>(same), static_cast<unsigned>(text), static_cast<unsigned>(slash));

        const int fe = fake::originalIsFileExist;
        size_t exist = 0;
        for (size_t i = 0; i < fileExist.size(); ++i)
            exist += hooks::Hook_IsFileExist(nullptr, nullptr, (ls + "\\" + fileExist[i]).c_str()) ? 1 : 0;
        CHECK_MSG(exist == fileExist.size() && fake::originalIsFileExist == fe,
                  std::to_string(exist) + " of " + std::to_string(fileExist.size())
                  + " definitions are present to the dependency processor's isFileExist without LocalState");
    }
    e.provider = nullptr;
    const ProviderStats st = p.Stats();
    printf("family policy: %llu fetches, %llu KB, %.1f ms total fetch time\n", st.fetches, st.bytesFetched / 1024,
           st.fetchMicros / 1000.0);
}

// ------------------------------------------ visible swap (opt-in, live) ----

namespace {

bool IsFile(const std::string& path)
{
    const DWORD a = GetFileAttributesA(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

//! Hands one step to the driver (<dir>\<step>.ready) and waits for its answer:
//! <dir>\<step>.done, renamed into place by the driver, holding the harness
//! command's exit code.  False on a timeout or <dir>\abort.
bool DriverStep(const std::string& dir, const std::string& step, std::string& answer)
{
    const std::string ready = dir + "\\" + step + ".ready";
    const std::string done = dir + "\\" + step + ".done";
    FILE* f = nullptr;
    if (fopen_s(&f, ready.c_str(), "wb") != 0 || !f)
        return false;
    fclose(f);
    for (int i = 0; i < 9000; ++i)   // 15 minutes; each command waits at most 4 for the broker
    {
        if (IsFile(done))
        {
            answer = Str(ReadFileBytes(done));
            return true;
        }
        if (IsFile(dir + "\\abort"))
            return false;
        Sleep(100);
    }
    return false;
}

std::string JoinKeys(const std::vector<std::string>& v)
{
    std::string out;
    for (size_t i = 0; i < v.size(); ++i)
        out += (i ? ", " : "") + v[i];
    return out.empty() ? "none" : out;
}

} // namespace

/*!
* The client checklist's Archive replacement and recovery, end to end except
* for the client.  BF-WorkingDirRust/scripts/test_content_visible_swap.py
* starts a real broker serving the harness's DISPOSABLE root for a family
* policy, and runs the harness's own commands between the steps below
* (swap NAME --like LIKE, restore, park NAME, restore); this process stands
* in for the game: one provider and the real hook code over fake game
* functions, the texture cache among them.
*
* The target is the tile the Archive actually draws.
* UnitDictionaryScene::setUnitDictionary (arm64 0x17B3910) names it
* getUnitListThum(id, dictionary image type, false): the plain
* unit_ills_thum_<id>.png.  The _100 variant needs the DBB flag, which only
* owned-unit lists pass (UserUnitInfo / BattleUnit::isDbbEligible); the
* Archive merely asks for it to exist (requestUnitFiles).  The tile loads
* through CommonUtils::getTexture -> getFileData, and CCTextureCache keys the
* decoded copy by that same LocalState path, so a swap is visible only if a
* safe point releases exactly that key and the next read returns the new
* bytes.  Session 11 swapped the _100 name: never read, nothing to release.
*
* What the client then shows for a withdrawn name is NOT asserted here: the
* provider reports it absent and refuses its read, and the game's own paths
* take over (pending client observation).
*/
// The menu-stutter XML save hook (xml_save_dedupe.cpp): a save is skipped only when it would rewrite the file
// with exactly the text the last successful save wrote, and the file is still the size that save left.
void TestXmlSaveDedupe()
{
    std::map<std::string, unsigned long long> disk;   // fake files: path -> size on disk
    int writes = 0;
    xmlsave::Deduper deduper([&](const std::string& path, unsigned long long* size) {
        const auto it = disk.find(path);
        if (it == disk.end())
            return false;
        *size = it->second;
        return true;
    });
    // `result` is what the real save returns; text mode adds bytes on disk, so the stored size differs from text.
    auto save = [&](const std::string& path, const std::string& text, int result = 0) {
        bool skipped = false;
        const int r = deduper.Save(path, text, [&]() {
            ++writes;
            if (result == 0)
                disk[path] = text.size() + 3;
            return result;
        }, &skipped);
        return std::make_pair(r, skipped);
    };

    auto r = save("a.xml", "<k>false</k>");
    CHECK_MSG(!r.second && writes == 1, "the first save of a session always writes");
    r = save("a.xml", "<k>false</k>");
    CHECK_MSG(r.second && r.first == 0 && writes == 1, "an identical save is skipped and reports success");
    r = save("a.xml", "<k>true</k>");
    CHECK_MSG(!r.second && writes == 2, "changed text writes");
    r = save("b.xml", "<k>true</k>");
    CHECK_MSG(!r.second && writes == 3, "each path has its own record");
    disk.erase("a.xml");
    r = save("a.xml", "<k>true</k>");
    CHECK_MSG(!r.second && writes == 4, "a deleted file is written again even when the text is identical");
    disk["a.xml"] = 1;
    r = save("a.xml", "<k>true</k>");
    CHECK_MSG(!r.second && writes == 5, "a file resized by someone else is written again");
    r = save("c.xml", "<y/>", 4);
    CHECK_MSG(r.first == 4 && !r.second, "a failed save returns the real error");
    r = save("c.xml", "<y/>");
    CHECK_MSG(!r.second && writes == 7, "a failed save is not remembered: the next identical save writes");
    r = save("c.xml", "<y/>");
    CHECK_MSG(r.second, "after a successful write, the identical save is skipped");
    CHECK_EQ(deduper.Skipped(), 2ull);
    CHECK_EQ(deduper.Written(), 7ull);
    CHECK(!xmlsave::ShouldSkip(nullptr, "x", true, 1));
    xmlsave::Record rec{ "x", 4 };
    CHECK(xmlsave::ShouldSkip(&rec, "x", true, 4));
    CHECK(!xmlsave::ShouldSkip(&rec, "x", false, 4));
    CHECK(!xmlsave::ShouldSkip(&rec, "y", true, 4));
}

void TestLiveVisibleSwap()
{
    const char* portText = getenv("BF_SWAP_PORT");
    const char* contentText = getenv("BF_SWAP_CONTENT");
    const char* expectText = getenv("BF_SWAP_EXPECT");
    const char* signalText = getenv("BF_SWAP_SIGNALS");
    if (!portText || !contentText || !expectText || !signalText)
    {
        t::Skip("visible swap integration", "BF_SWAP_PORT / BF_SWAP_CONTENT / BF_SWAP_EXPECT / BF_SWAP_SIGNALS not set");
        return;
    }
    const std::string signals = signalText;
    std::string name, nameRel, like, likeRel;
    std::vector<std::string> bundle;
    // "sep f": the game reads the target as "<LocalState>/<name>" -- a SuperAnim
    // page, whose path LoadSuperAnimMainDef builds from the .sam's directory.
    bool forwardSlash = false;
    {
        std::ifstream in(expectText);
        std::string kind, a, b;
        while (in >> kind)
        {
            if (kind == "name" && in >> a >> b)
            {
                name = a;
                nameRel = b;
            }
            else if (kind == "like" && in >> a >> b)
            {
                like = a;
                likeRel = b;
            }
            else if (kind == "bundle" && in >> a)
                bundle.push_back(Fold(a));
            else if (kind == "sep" && in >> a)
                forwardSlash = a == "f";
        }
    }
    const auto disk = [&](const std::string& rel) {
        std::string path = std::string(contentText) + "\\" + rel;
        std::replace(path.begin(), path.end(), '/', '\\');
        return ReadFileBytes(path);
    };
    const std::vector<uint8_t> original = disk(nameRel), likeBytes = disk(likeRel);
    CHECK_MSG(!name.empty() && !like.empty() && bundle.size() > 1
              && std::find(bundle.begin(), bundle.end(), Fold(name)) != bundle.end(),
              std::string("target, replacement and the target's bundle read from ") + expectText);
    CHECK_MSG(!original.empty() && !likeBytes.empty() && original != likeBytes,
              "the original files of " + name + " and " + like + " are readable and differ");
    if (name.empty() || original.empty() || likeBytes.empty() || original == likeBytes)
        return;

    WinInetBroker broker("127.0.0.1", static_cast<unsigned short>(atoi(portText)));
    Provider p(&broker, 64u << 20, 16u << 20);
    p.SetAutoStart(false);
    std::string why;
    bool up = false;
    for (int i = 0; i < 240 && !up; ++i)
    {
        up = p.InitializeOnce(why);
        if (!up)
            Sleep(250);
    }
    CHECK_MSG(up, "provider activated against the disposable root's broker: " + why);
    if (!up)
        return;

    // The game: LocalState as getWritablePath reports it; getTexture's key is
    // the full LocalState path of the flat name.
    const std::string ls = "C:\\Live\\LocalState";
    SetupEnv(&p, ls);
    hooks::Env& e = hooks::env();
    e.trueAddLoadFile = fake::AddLoadFile;
    e.trueAddLoadFilePriority = fake::AddLoadFilePriority;
    const char* const sep = forwardSlash ? "/" : "\\";
    const std::string namePath = ls + sep + name, likePath = ls + sep + like;
    const std::string folder = "/" + nameRel.substr(0, nameRel.rfind('/') + 1);
    const auto draw = [&](const std::string& path, std::vector<uint8_t>& out) {
        unsigned long size = 0;
        unsigned char* data = hooks::Hook_GetFileData(nullptr, nullptr, path.c_str(), "rb", &size);
        out.clear();
        if (!data)
            return false;
        out.assign(data, data + size);
        fake::Delete(data);
        return true;
    };
    const auto serverIndex = [&](IndexSnapshot& snap) {
        int status = 0;
        std::string body, error;
        return broker.GetText("/offline_mod/content/v1/index?since=0&epoch=", status, body, error) && status == 200
            && ParseIndex(body, snap, error);
    };
    // The driver's command returns once the broker publishes the change; one
    // poll after that has it pending (readiness as TestLiveBroker defines it).
    const auto pendingOnce = [&](const std::function<bool(const IndexSnapshot&)>& published) {
        for (int i = 0; i < 300; ++i)
        {
            IndexSnapshot snap;
            if (serverIndex(snap) && published(snap))
                return p.PollOnce(why) && p.HasPending();
            Sleep(100);
        }
        return false;
    };
    const auto digestIs = [&](const std::vector<uint8_t>& bytes) {
        const std::string want = Sha256Tag(&bytes[0], bytes.size());
        const std::string key = Fold(name);
        return [want, key](const IndexSnapshot& s) {
            const std::map<std::string, IndexEntry>::const_iterator it = s.files.find(key);
            return it != s.files.end() && it->second.digest == want;
        };
    };
    const auto step = [&](const char* stepName) {
        std::string answer;
        const bool ran = DriverStep(signals, stepName, answer);
        CHECK_MSG(ran && answer == "0", std::string("the driver ran the harness command for '") + stepName
                  + "' and the broker published it (exit " + (ran ? answer : "none: timeout or abort") + ")");
        return ran && answer == "0";
    };
    const auto adoptAtSceneChange = [&]() {
        fake::removedKeys.clear();
        hooks::SafePoint("replaceScene");
        return fake::removedKeys.size() == 1 && fake::removedKeys[0] == namePath;
    };
    std::vector<uint8_t> got;

    // The Archive draws both tiles: each read is served by the provider and
    // remembered under the key the texture cache uses.
    CHECK_MSG(draw(namePath, got) && got == original, name + " is drawn with its own bytes from the broker");
    CHECK_MSG(draw(likePath, got) && got == likeBytes, like + " is drawn with its own bytes from the broker");

    // swap NAME --like LIKE
    if (!step("swap"))
        return;
    CHECK_MSG(pendingOnce(digestIs(likeBytes)), "the broker publishes " + name + " with " + like
              + "'s identity, and a poll after that has it pending");
    CHECK_MSG(draw(namePath, got) && got == original,
              "inside the scene that drew it, " + name + " keeps the version that scene pinned");
    CHECK_MSG(adoptAtSceneChange(), "the scene change releases exactly the decoded copy the tile was drawn from: "
              + JoinKeys(fake::removedKeys));
    CHECK_MSG(draw(namePath, got) && got == likeBytes, "the next draw of " + name + " returns the replacement bytes");
    CHECK_MSG(draw(likePath, got) && got == likeBytes, like + " itself is unchanged");

    // restore
    if (!step("restore"))
        return;
    CHECK_MSG(pendingOnce(digestIs(original)), "the broker publishes " + name + "'s original identity again");
    CHECK_MSG(adoptAtSceneChange(), "the scene change releases the replacement's decoded copy: "
              + JoinKeys(fake::removedKeys));
    CHECK_MSG(draw(namePath, got) && got == original, "the next draw of " + name + " returns its original bytes");

    // park NAME: its whole bundle is withdrawn.
    if (!step("park"))
        return;
    CHECK_MSG(pendingOnce([&](const IndexSnapshot& s) {
                  for (size_t i = 0; i < bundle.size(); ++i)
                      if (s.files.count(bundle[i]) || !s.unavailable.count(bundle[i]))
                          return false;
                  return true;
              }),
              "the broker withdraws all " + std::to_string(bundle.size()) + " names of " + name + "'s bundle");
    CHECK_MSG(adoptAtSceneChange(), "the scene change releases the decoded copy of the withdrawn tile: "
              + JoinKeys(fake::removedKeys));
    size_t absent = 0;
    for (size_t i = 0; i < bundle.size(); ++i)
        absent += p.Classify(bundle[i]) == Ownership::Absent ? 1 : 0;
    CHECK_MSG(absent == bundle.size(), std::to_string(absent) + " of " + std::to_string(bundle.size())
              + " bundle names are absent after the scene change");
    CHECK_MSG(p.Classify(like) == Ownership::Present, "another unit's bundle (" + like + ") is untouched");
    {
        hooks::MsvcString s = MakeString(name);
        const int ex = fake::originalExists;
        CHECK_MSG(!hooks::Hook_ExistsLocalFile(&s, nullptr) && fake::originalExists == ex,
                  "existsLocalFile answers absent from the provider alone, never from a LocalState copy");
        if (s.capacity >= 16)
            free(s.bx.ptr);
    }
    {
        const int orig = fake::originalGetFileData;
        CHECK_MSG(!draw(namePath, got) && fake::originalGetFileData == orig,
                  "the tile's read is refused, with no fallback to the client cache's copy");
    }
    {
        const int prio = fake::originalAddLoadFilePriority;
        const long suppressed = e.suppressedEnqueues;
        hooks::Hook_AddLoadFilePriority(nullptr, nullptr, 1, 0, MakeString(folder + name));
        CHECK_MSG(fake::originalAddLoadFilePriority == prio + 1 && e.suppressedEnqueues == suppressed,
                  "a queued download of the withdrawn name reaches the game's own downloader");
    }

    // restore
    if (!step("restore2"))
        return;
    CHECK_MSG(pendingOnce([&](const IndexSnapshot& s) {
                  if (s.files.size() == 0 || !digestIs(original)(s))
                      return false;
                  for (size_t i = 0; i < bundle.size(); ++i)
                      if (!s.files.count(bundle[i]) || s.unavailable.count(bundle[i]))
                          return false;
                  return true;
              }),
              "the broker publishes the whole bundle again");
    CHECK_MSG(adoptAtSceneChange(), "the scene change after the restore releases the tile's key again: "
              + JoinKeys(fake::removedKeys));
    size_t present = 0;
    for (size_t i = 0; i < bundle.size(); ++i)
        present += p.Classify(bundle[i]) == Ownership::Present ? 1 : 0;
    CHECK_MSG(present == bundle.size(), std::to_string(present) + " of " + std::to_string(bundle.size())
              + " bundle names are present again");
    CHECK_MSG(draw(namePath, got) && got == original, "the next draw of " + name + " returns its original bytes");
    {
        const int prio = fake::originalAddLoadFilePriority;
        const long suppressed = e.suppressedEnqueues;
        hooks::Hook_AddLoadFilePriority(nullptr, nullptr, 1, 0, MakeString(folder + name));
        CHECK_MSG(fake::originalAddLoadFilePriority == prio && e.suppressedEnqueues == suppressed + 1,
                  "once restored, the provider serves it again and keeps it out of the download queue");
    }
    e.provider = nullptr;
    printf("visible swap: %s swapped (like %s), restored, parked (%u bundle names withdrawn), restored;"
           " each adopted at a scene change releasing exactly the drawn key%s\n",
           name.c_str(), like.c_str(), static_cast<unsigned>(bundle.size()),
           forwardSlash ? " ('<dir>/<page>' path)" : "");
}

// ---------------------------------------------------------------- name fit: per-site install/restore (rounds 7-8)
//
// cp_name_fit_logic.cpp writes every patch site through a CodeWriter.  The tests use the production writer
// (gf::WriteCodeWith) on real code pages with the scripted OS steps above (WsWrite): any step of any write fails,
// and the tests check, for every position and step, that the bookkeeping follows the bytes (a write that fails
// after its copy still changed them), that nothing is reported installed or restored that did not complete, that
// a partial install is rolled back with the failed site included, that every write leaves the site's stock page
// protection, and that a later restore retries whatever is left installed or incomplete.

namespace nf = cp::namefit;

namespace {

struct NfFixture {
    CodePages pages{ 3 };
    nf::PatchSite sites[3];
    explicit NfFixture(std::vector<WriteFault> faults = {})
    {
        for (int i = 0; i < 3; ++i)
        {
            uint8_t* at = pages.Page(i) + 0x20;
            uint8_t stock[4];
            for (int b = 0; b < 4; ++b)
            {
                stock[b] = static_cast<uint8_t>(0x10 * (i + 1) + b);
                sites[i].patched[b] = static_cast<uint8_t>(0xA0 + 0x10 * i + b);
            }
            gf::WriteCode(at, stock, 4, PAGE_EXECUTE_READ);
            memcpy(sites[i].original, stock, 4);
            sites[i].at = at;
            sites[i].size = 4;
            sites[i].protection = gf::ProtectionOf(at);       // as NameFit_Attach records it
        }
        WsReset(std::move(faults));
    }
    bool IsStock(int i) const { return memcmp(sites[i].at, sites[i].original, 4) == 0; }
    bool IsPatched(int i) const { return memcmp(sites[i].at, sites[i].patched, 4) == 0; }
    bool ReadOnly(int i) const { return gf::ProtectionOf(sites[i].at) == PAGE_EXECUTE_READ; }
    //! Stock bytes, stock protection, nothing installed or incomplete.
    bool Clean(int i) const { return IsStock(i) && ReadOnly(i) && !sites[i].installed && !sites[i].incomplete; }
    bool AllClean() const { return Clean(0) && Clean(1) && Clean(2); }
};

} // namespace

void TestNameFitSites()
{
    CHECK_MSG(NfFixture().sites[0].protection == PAGE_EXECUTE_READ, "the fixture's sites are real read-only code pages");
    {   // success: install all, restore all, then a second restore writes nothing
        NfFixture f;
        CHECK(nf::InstallSites(f.sites, 3, &WsWrite) == nf::InstallResult::Installed);
        CHECK(f.IsPatched(0) && f.IsPatched(1) && f.IsPatched(2) && f.ReadOnly(0) && f.ReadOnly(1) && f.ReadOnly(2));
        CHECK_EQ(nf::InstalledCount(f.sites, 3), 3u);
        CHECK(nf::RestoreSites(f.sites, 3, &WsWrite));
        CHECK(f.AllClean());
        const int before = g_ws.writes;
        CHECK(nf::RestoreSites(f.sites, 3, &WsWrite));
        CHECK_EQ(g_ws.writes, before);
    }
    for (int pos = 1; pos <= 3; ++pos)
    {   // install write `pos` fails before its copy: the earlier writes are rolled back, all clean
        NfFixture f({ { pos, 1 } });
        gf::WriteResult failure;
        CHECK_MSG(nf::InstallSites(f.sites, 3, &WsWrite, &failure) == nf::InstallResult::RolledBack, "pre-copy fail");
        CHECK(f.AllClean() && !failure.copied && failure.error == ERROR_ACCESS_DENIED);
        CHECK_EQ(g_ws.writes, pos + (pos - 1));                  // pos installs, pos-1 rollbacks
    }
    for (int step = 2; step <= 3; ++step)
        for (int pos = 1; pos <= 3; ++pos)
        {   // install write `pos` fails AFTER its copy (protection / flush): that site is rolled back too
            NfFixture f({ { pos, step } });
            gf::WriteResult failure;
            CHECK_MSG(nf::InstallSites(f.sites, 3, &WsWrite, &failure) == nf::InstallResult::RolledBack,
                      "after-copy fail: rolled back");
            CHECK_MSG(failure.copied && !failure.Complete(), "the failure is reported as a copied write");
            CHECK_EQ(g_ws.writes, pos + pos);                    // pos installs, pos rollbacks (the failed one too)
            CHECK_MSG(f.AllClean(), "every site stock, with its stock protection (the rollback restores it)");
        }
    {   // install write 3 fails before its copy, and the rollback of site 0 (write 5) fails before its copy
        NfFixture f({ { 3, 1 }, { 5, 1 } });
        CHECK(nf::InstallSites(f.sites, 3, &WsWrite) == nf::InstallResult::RollbackFailed);
        CHECK(f.sites[0].installed && f.IsPatched(0) && f.Clean(1) && f.Clean(2));
        CHECK(nf::RestoreSites(f.sites, 3, &WsWrite));           // the retry succeeds
        CHECK(f.AllClean());
    }
    {   // install write 3 fails after its copy; its own rollback (write 4) fails before the copy: it stays installed
        NfFixture f({ { 3, 2 }, { 4, 1 } });
        CHECK(nf::InstallSites(f.sites, 3, &WsWrite) == nf::InstallResult::RollbackFailed);
        CHECK(f.sites[2].installed && f.IsPatched(2) && f.Clean(0) && f.Clean(1));
        CHECK_MSG(!f.ReadOnly(2), "the failed write left that page writable");
        CHECK(nf::RestoreSites(f.sites, 3, &WsWrite));
        CHECK_MSG(f.AllClean(), "the retry restores the bytes and the stock protection");
    }
    {   // install write 2 fails at the flush; the rollback of site 1 (write 3) fails at the protection: incomplete
        NfFixture f({ { 2, 3 }, { 3, 2 } });
        CHECK(nf::InstallSites(f.sites, 3, &WsWrite) == nf::InstallResult::RollbackFailed);
        CHECK_EQ(nf::InstalledCount(f.sites, 3), 0u);
        CHECK_EQ(nf::IncompleteCount(f.sites, 3), 1u);
        CHECK(f.IsStock(1) && f.sites[1].incomplete && !f.ReadOnly(1) && f.Clean(0) && f.Clean(2));
        CHECK(nf::RestoreSites(f.sites, 3, &WsWrite));           // an incomplete site is retried too
        CHECK(f.AllClean());
    }
    for (int step = 1; step <= 3; ++step)
        for (int pos = 1; pos <= 3; ++pos)
        {   // restore write `pos` fails at `step` (restores run newest first: site 2, 1, 0)
            NfFixture f;
            CHECK(nf::InstallSites(f.sites, 3, &WsWrite) == nf::InstallResult::Installed);
            WsReset({ { pos, step } });
            gf::WriteResult failure;
            CHECK_MSG(!nf::RestoreSites(f.sites, 3, &WsWrite, &failure), "restore fail position");
            const int site = 3 - pos;
            if (step == 1)
                CHECK_MSG(f.sites[site].installed && f.IsPatched(site) && !failure.copied, "not copied: still ours");
            else
                CHECK_MSG(!f.sites[site].installed && f.sites[site].incomplete && f.IsStock(site) && failure.copied,
                          "copied: stock bytes back, the site incomplete");
            for (int i = 0; i < 3; ++i)
                if (i != site)
                    CHECK(f.Clean(i));
            WsReset();                                           // retry after a failed restoration
            CHECK(nf::RestoreSites(f.sites, 3, &WsWrite));
            CHECK(f.AllClean());
        }
    {   // two independent patch sets: a failure in one leaves the other's state intact
        NfFixture a, b;
        CHECK(nf::InstallSites(a.sites, 3, &WsWrite) == nf::InstallResult::Installed);
        CHECK(nf::InstallSites(b.sites, 1, &WsWrite) == nf::InstallResult::Installed);
        WsReset({ { 1, 1 } });                                   // a's first restore fails
        CHECK(!nf::RestoreSites(a.sites, 3, &WsWrite));
        CHECK(nf::RestoreSites(b.sites, 1, &WsWrite));
        CHECK_EQ(nf::InstalledCount(a.sites, 3), 1u);
        CHECK(b.Clean(0));
    }
    {   // popup description fit: 1 when it fits, capacity / lines otherwise
        CHECK(nf::PopupFitScale(1, 3) == 1.0f && nf::PopupFitScale(3, 3) == 1.0f);
        CHECK(nf::PopupFitScale(4, 3) == 0.75f && nf::PopupFitScale(6, 3) == 0.5f);
        CHECK(nf::PopupFitScale(0, 3) == 1.0f && nf::PopupFitScale(-2, 3) == 1.0f && nf::PopupFitScale(5, 0) == 1.0f);
    }
    {   // popup description fit: re-wrap wider first, then scale so both width and height fit
        CHECK(nf::PopupRewrapScale(3, 3) == 1.0f && nf::PopupRewrapScale(1, 3) == 1.0f);
        CHECK(nf::PopupRewrapScale(12, 3) == 0.5f);
        CHECK(std::fabs(nf::PopupRewrapScale(6, 3) - 0.70710678f) < 1e-6f);
        CHECK(nf::PopupRewrapScale(0, 3) == 1.0f && nf::PopupRewrapScale(5, 0) == 1.0f);
        const float r6 = nf::PopupRewrapScale(6, 3);
        CHECK(nf::PopupFinalScale(r6, 4, 3) == r6);                 // 4 lines at w/0.71: the width limits it
        CHECK(nf::PopupFinalScale(r6, 5, 3) == 0.6f);               // word wrap left 5 lines: the height limits it
        CHECK(nf::PopupFinalScale(r6, 2, 3) == r6);                 // never larger than the re-wrap (width)
        for (int n = 4; n <= 12; ++n)
            for (int after = 1; after <= 2 * n; ++after)
            {   // whatever the re-wrap gives, the scaled block fits: width w/r*s <= w and after*s <= 3
                const float r = nf::PopupRewrapScale(n, 3), s = nf::PopupFinalScale(r, after, 3);
                CHECK_MSG(s <= r + 1e-6f && after * s <= 3.0f + 1e-5f && s > 0.0f, "fits both ways");
            }
    }
    {   // popup description fit: move y so the first line's top returns where it was
        CHECK(nf::PopupTopDelta(500.0f, 488.0f, -1.0f) == -12.0f);  // UI y down: move up by 12
        CHECK(nf::PopupTopDelta(500.0f, 488.0f, 1.0f) == 12.0f);
        CHECK(nf::PopupTopDelta(500.0f, 500.0f, -1.0f) == 0.0f);
        CHECK(nf::PopupTopDelta(500.0f, 488.0f, 0.0f) == 0.0f);     // degenerate slope: leave it
        CHECK(nf::PopupTopDelta(500.0f, 488.0f, std::numeric_limits<float>::quiet_NaN()) == 0.0f);
        CHECK(nf::PopupTopDelta(std::numeric_limits<float>::infinity(), 488.0f, -1.0f) == 0.0f);
    }
    {   // a retried install after a rollback installs cleanly
        NfFixture f({ { 2, 1 } });
        CHECK(nf::InstallSites(f.sites, 3, &WsWrite) == nf::InstallResult::RolledBack);
        WsReset();
        CHECK(nf::InstallSites(f.sites, 3, &WsWrite) == nf::InstallResult::Installed);
        CHECK(f.IsPatched(0) && f.IsPatched(1) && f.IsPatched(2));
    }
}

// ---------------------------------------------------------------- skill popup vertical fit on fake labels (round 8)
//
// The production FitPopupDesc, CP_FitPopupDesc (SEH, log, session policy) and PopupDescThunk run against a fake
// gumi text block: the label fields (+0F4h..+168h), the CCNode vtable slots and the line nodes as
// check_name_fit_site.py proves them, and fake setString / std::string::assign that lay lines out (6 px per
// character, 12-px lines, the block centred on the label's y and scaled about it) and own their copies as the
// client's do.  Scripts: no laid-out lines, a NaN position, a non-linear layout, an access fault.  Not covered:
// the client's allocator and its real CCLabelTTF nodes (the client run covers those).

namespace {

struct FkLine {
    void** vt;
    float y;
    float anchor[2];
    float size[2];
    float scale;
};

struct FkList {
    uint8_t pad[0x14];
    FkLine** begin;
    FkLine** end;
};

struct FkScript {
    int setTextCalls = 0, assignCalls = 0, nodeScaleCalls = 0, disableCalls = 0;
    int emptyFrom = 0, emptyUntil = 0;   // setString calls in [from, until) lay out no nodes (until 0: no end)
    int faultSetText = 0;                // this setString call faults
    int faultNodeScale = 0;              // this line-node setScale call faults
    bool nanWhenScaled = false;          // a node's y reads NaN while its scale is not 1
    float quadratic = 0.0f, y0 = 0.0f;   // the layout bends: y + q (y - y0)^2
    bool outline = false;                // each line has an outline copy (two nodes)
    long heapLive = 0;                   // text blocks allocated minus freed
} g_fk;

void* g_fkLabelVt[0x90 / 4];
void* g_fkLineVt[0x90 / 4];

char* FkAlloc(size_t n) { ++g_fk.heapLive; return static_cast<char*>(malloc(n)); }
void FkFree(void* p) { --g_fk.heapLive; free(p); }
const char* FkData(const nf::ClientString& s)
{
    return s.capacity > 15 ? *reinterpret_cast<char* const*>(s.buf) : reinterpret_cast<const char*>(s.buf);
}
void FkSet(nf::ClientString& s, const char* p, size_t n)
{
    if (n > 15)
    {
        char* h = FkAlloc(n + 1);
        memcpy(h, p, n);
        h[n] = 0;
        memcpy(s.buf, &h, sizeof h);
        s.capacity = static_cast<uint32_t>(n);
    }
    else
    {
        memcpy(s.buf, p, n);
        s.buf[n] = 0;
        s.capacity = 15;
    }
    s.size = static_cast<uint32_t>(n);
}
void FkDrop(nf::ClientString& s)
{
    if (s.capacity > 15)
        FkFree(*reinterpret_cast<char**>(s.buf));
    s = nf::ClientString();
    s.capacity = 15;
}

struct FkLabel {
    alignas(16) uint8_t mem[0x1C0] = {};
    FkList list = {};
    std::vector<FkLine*> nodes;

    float& F(size_t off) { return *reinterpret_cast<float*>(mem + off); }
    int& I(size_t off) { return *reinterpret_cast<int*>(mem + off); }
    nf::ClientString& Text() { return *reinterpret_cast<nf::ClientString*>(mem + nf::kLabelText); }
    float& ScaleX() { return F(0x180); }
    float& ScaleY() { return F(0x184); }
    uint8_t* P() { return mem; }

    //! The label's own layout (its setPosition): the block centred on y, each line scaled about it.
    void Layout()
    {
        const float s = ScaleX();
        const float y = F(nf::kLabelY);
        const float ye = y + g_fk.quadratic * (y - g_fk.y0) * (y - g_fk.y0);
        const int lines = I(nf::kLabelLineCount);
        const float half = lines * 12.0f / 2.0f;
        for (size_t k = 0; k < nodes.size(); ++k)
        {
            const size_t i = g_fk.outline ? k / 2 : k;
            nodes[k]->y = ye + (half - (static_cast<float>(i) + 0.5f) * 12.0f) * s;
        }
    }
    //! setString's line rebuild: the old nodes go, new ones get the label's scale.
    void Rebuild(bool empty)
    {
        for (FkLine* n : nodes)
            delete n;
        nodes.clear();
        const int lines = static_cast<int>(std::ceil(Text().size * 6.0f / F(nf::kLabelWrap)));
        I(nf::kLabelLineCount) = lines;
        if (!empty)
            for (int k = 0; k < lines * (g_fk.outline ? 2 : 1); ++k)
                nodes.push_back(new FkLine{ g_fkLineVt, 0.0f, { 0.5f, 0.5f }, { 200.0f, 12.0f }, ScaleX() });
        list.begin = nodes.empty() ? nullptr : nodes.data();
        list.end = nodes.empty() ? nullptr : nodes.data() + nodes.size();
        Layout();
    }
    //! The label as the client's helper returns it: text, wrap width, scale 1, laid out at (26, 300).
    void Build(size_t textLen, float wrap = 258.0f)
    {
        *reinterpret_cast<void***>(mem) = g_fkLabelVt;
        *reinterpret_cast<FkList**>(mem + nf::kLabelLines) = &list;
        F(nf::kLabelX) = 26.0f;
        F(nf::kLabelY) = 300.0f;
        F(nf::kLabelWrap) = wrap;
        ScaleX() = ScaleY() = 1.0f;
        Text().capacity = 15;
        const std::string text(textLen, 'a');
        FkSet(Text(), text.data(), text.size());
        g_fk.y0 = 300.0f;
        Rebuild(false);
    }
    ~FkLabel()
    {
        for (FkLine* n : nodes)
            delete n;
        FkDrop(Text());
    }
    float FirstTop() const { return nodes[0]->y + 0.5f * 12.0f * nodes[0]->scale; }
    //! The bytes of the label and every node, for "left as built".
    std::vector<uint8_t> Snap() const
    {
        std::vector<uint8_t> s(mem, mem + sizeof mem);
        for (const FkLine* n : nodes)
        {
            const uint8_t* b = reinterpret_cast<const uint8_t*>(n);
            s.insert(s.end(), reinterpret_cast<const uint8_t*>(&n), reinterpret_cast<const uint8_t*>(&n) + sizeof n);
            s.insert(s.end(), b, b + sizeof *n);
        }
        return s;
    }
};

FkLabel* L(void* p) { return reinterpret_cast<FkLabel*>(p); }
FkLine* N(void* p) { return static_cast<FkLine*>(p); }
void FkFault() { *static_cast<volatile int*>(nullptr) = 1; }

float __fastcall FkLabelGetScaleX(void* self, void*) { return L(self)->ScaleX(); }
float __fastcall FkLabelGetScaleY(void* self, void*) { return L(self)->ScaleY(); }
void __fastcall FkLabelSetScale(void* self, void*, float s) { L(self)->ScaleX() = L(self)->ScaleY() = s; }
void __fastcall FkLabelSetPosition(void* self, void*, float x, float y)
{
    L(self)->F(nf::kLabelX) = x;
    L(self)->F(nf::kLabelY) = y;
    L(self)->Layout();
}
float __fastcall FkLineGetScaleY(void* self, void*) { return N(self)->scale; }
void __fastcall FkLineSetScale(void* self, void*, float s)
{
    if (++g_fk.nodeScaleCalls == g_fk.faultNodeScale)
        FkFault();
    N(self)->scale = s;
}
float __fastcall FkLineGetY(void* self, void*)
{
    return g_fk.nanWhenScaled && N(self)->scale != 1.0f ? std::numeric_limits<float>::quiet_NaN() : N(self)->y;
}
const float* __fastcall FkLineGetAnchor(void* self, void*) { return N(self)->anchor; }
const float* __fastcall FkLineGetSize(void* self, void*) { return N(self)->size; }

void __fastcall FkSetText(void* label, void*, int force, nf::ClientString text)
{
    const int call = ++g_fk.setTextCalls;
    if (call == g_fk.faultSetText)
        FkFault();
    (void)force;
    FkDrop(L(label)->Text());
    FkSet(L(label)->Text(), FkData(text), text.size);
    FkDrop(text);                                               // the callee frees the by-value copy
    L(label)->Rebuild(g_fk.emptyFrom && call >= g_fk.emptyFrom && (!g_fk.emptyUntil || call < g_fk.emptyUntil));
}

void* __fastcall FkAssign(nf::ClientString* self, void*, const void* src, size_t pos, size_t count)
{
    ++g_fk.assignCalls;
    const nf::ClientString& s = *static_cast<const nf::ClientString*>(src);
    const size_t n = count < s.size - pos ? count : s.size - pos;
    FkSet(*self, FkData(s) + pos, n);
    return self;
}

void FkDisable() { ++g_fk.disableCalls; }

nf::PopupFitEnv& FkEnv()
{
    g_fkLabelVt[nf::kNodeGetScaleX / 4] = reinterpret_cast<void*>(&FkLabelGetScaleX);
    g_fkLabelVt[nf::kNodeGetScaleY / 4] = reinterpret_cast<void*>(&FkLabelGetScaleY);
    g_fkLabelVt[nf::kNodeSetScale / 4] = reinterpret_cast<void*>(&FkLabelSetScale);
    g_fkLabelVt[nf::kLabelSetPosition / 4] = reinterpret_cast<void*>(&FkLabelSetPosition);
    g_fkLineVt[nf::kNodeGetScaleY / 4] = reinterpret_cast<void*>(&FkLineGetScaleY);
    g_fkLineVt[nf::kNodeSetScale / 4] = reinterpret_cast<void*>(&FkLineSetScale);
    g_fkLineVt[nf::kNodeGetPositionY / 4] = reinterpret_cast<void*>(&FkLineGetY);
    g_fkLineVt[nf::kNodeGetAnchorPoint / 4] = reinterpret_cast<void*>(&FkLineGetAnchor);
    g_fkLineVt[nf::kNodeGetContentSize / 4] = reinterpret_cast<void*>(&FkLineGetSize);
    const long live = g_fk.heapLive;             // every scenario's copies are counted to the end
    g_fk = FkScript();
    g_fk.heapLive = live;
    nf::PopupFitEnv& e = nf::popupEnv();
    e = nf::PopupFitEnv();
    e.labelVtable = reinterpret_cast<uintptr_t>(&g_fkLabelVt[0]);
    e.setText = reinterpret_cast<nf::LabelSetTextFn>(&FkSetText);
    e.assign = reinterpret_cast<nf::StringAssignFn>(&FkAssign);
    e.disable = &FkDisable;
    return e;
}

bool LogHas(const std::string& s) { return Str(ReadFileBytes(LogPath())).find(s) != std::string::npos; }

// PopupDescThunk, called as a description site calls 0x387100: nine stack dwords (caller-cleaned), ecx, edx and
// xmm3 set.  The fake helper records what it got, leaves known ecx/edx/xmm0..7 and returns the label in eax.
uint32_t g_ph_label = 0, g_ph_arg1 = 0, g_ph_arg9 = 0, g_ph_ecx = 0, g_ph_edx = 0;
float g_ph_xmm3 = 0.0f;
alignas(16) uint32_t g_ph_xmm[8][4];      // what the helper leaves in xmm0..7
alignas(16) uint32_t g_pt_xmm[8][4];      // what the site sees after the thunk
uint32_t g_pt_eax = 0, g_pt_ecx = 0, g_pt_edx = 0, g_pt_espBefore = 0, g_pt_espAfter = 0;
const float kPtWidth = 258.0f;

extern "C" __declspec(naked) void FakeLabelHelper()
{
    __asm {
        mov     eax, [esp + 4]
        mov     g_ph_arg1, eax
        mov     eax, [esp + 24h]
        mov     g_ph_arg9, eax
        mov     g_ph_ecx, ecx
        mov     g_ph_edx, edx
        movss   g_ph_xmm3, xmm3
        movdqu  xmm0, xmmword ptr [g_ph_xmm]
        movdqu  xmm1, xmmword ptr [g_ph_xmm + 10h]
        movdqu  xmm2, xmmword ptr [g_ph_xmm + 20h]
        movdqu  xmm3, xmmword ptr [g_ph_xmm + 30h]
        movdqu  xmm4, xmmword ptr [g_ph_xmm + 40h]
        movdqu  xmm5, xmmword ptr [g_ph_xmm + 50h]
        movdqu  xmm6, xmmword ptr [g_ph_xmm + 60h]
        movdqu  xmm7, xmmword ptr [g_ph_xmm + 70h]
        mov     ecx, 0C0C0C0Ch
        mov     edx, 0D0D0D0Dh
        mov     eax, g_ph_label
        ret
    }
}

void CallPopupThunk()
{
    void* thunk = reinterpret_cast<void*>(&PopupDescThunk);
    __asm {
        push    ebx
        push    esi
        push    edi
        mov     g_pt_espBefore, esp
        push    99999999h                 ; the 9th (deepest) argument
        push    88888888h
        push    77777777h
        push    66666666h
        push    55555555h
        push    44444444h
        push    33333333h
        push    22222222h
        push    11111111h                 ; the 1st argument, [esp+4] at the helper
        mov     ecx, 3Ah
        mov     edx, 7
        movss   xmm3, kPtWidth
        call    dword ptr [thunk]
        add     esp, 24h                  ; the site cleans its own arguments
        mov     g_pt_espAfter, esp
        mov     g_pt_eax, eax
        mov     g_pt_ecx, ecx
        mov     g_pt_edx, edx
        movdqu  xmmword ptr [g_pt_xmm], xmm0
        movdqu  xmmword ptr [g_pt_xmm + 10h], xmm1
        movdqu  xmmword ptr [g_pt_xmm + 20h], xmm2
        movdqu  xmmword ptr [g_pt_xmm + 30h], xmm3
        movdqu  xmmword ptr [g_pt_xmm + 40h], xmm4
        movdqu  xmmword ptr [g_pt_xmm + 50h], xmm5
        movdqu  xmmword ptr [g_pt_xmm + 60h], xmm6
        movdqu  xmmword ptr [g_pt_xmm + 70h], xmm7
        pop     edi
        pop     esi
        pop     ebx
    }
}

} // namespace

void TestPopupFit()
{
    nf::PopupFitResult r;
    {   // 3 lines (120 characters at 258): nothing is read past the checks, nothing changes
        nf::PopupFitEnv& e = FkEnv();
        FkLabel l;
        l.Build(120);
        const std::vector<uint8_t> before = l.Snap();
        nf::FitPopupDesc(e, l.P(), r);
        CHECK(r.outcome == nf::PopupFit::NotNeeded && r.lines == 3 && g_fk.setTextCalls == 0 && l.Snap() == before);
    }
    {   // 5 lines: re-wrapped at 258 / sqrt(3/5) to 4 lines, scaled 0.75, first line back on its top
        nf::PopupFitEnv& e = FkEnv();
        FkLabel l;
        l.Build(200);
        const float built = l.FirstTop();                           // 5 lines centred on y 300: top 330
        nf::FitPopupDesc(e, l.P(), r);
        CHECK_MSG(r.outcome == nf::PopupFit::Fitted && r.lines == 5 && r.linesAfter == 4, "5 lines fitted");
        // The target is the re-wrapped 4-line layout's first line (324), not the taller as-built block's (330),
        // which reaches into the skill name (round 8, run v1: SBB/UBB overlapped their titles).
        CHECK_MSG(std::fabs(r.topBuilt - built) <= 1e-3f && std::fabs(r.topBefore - (300.0f + 6.0f * 4)) <= 1e-3f,
                  "the fit keeps the re-wrapped first line's top");
        CHECK(std::fabs(l.FirstTop() - r.topBefore) <= 1e-3f);
        CHECK(std::fabs(r.scale - 0.75f) < 1e-6f && l.ScaleX() == r.scale && l.ScaleY() == r.scale);
        bool allScaled = true;
        for (const FkLine* n : l.nodes)
            allScaled = allScaled && n->scale == r.scale;
        CHECK_MSG(allScaled && l.nodes.size() == 4u, "the label and every line node carry the scale");
        CHECK(std::fabs(r.topAfter - r.topBefore) <= 1e-3f);
        CHECK(std::fabs(l.F(nf::kLabelWrap) - 258.0f / std::sqrt(0.6f)) < 1e-3f);
        CHECK_MSG(g_fk.setTextCalls == 1 && g_fk.assignCalls == 1 && g_fk.heapLive == 1, "one copy, freed by setString");
    }
    {   // 8 lines with outline copies: every node (two per line) scaled; 5 lines after the re-wrap, scale 0.6
        nf::PopupFitEnv& e = FkEnv();
        g_fk.outline = true;
        FkLabel l;
        l.Build(330);
        const float top = l.FirstTop();
        nf::FitPopupDesc(e, l.P(), r);
        CHECK(r.outcome == nf::PopupFit::Fitted && r.lines == 8 && r.linesAfter == 5 && r.nodes == 10u);
        CHECK(std::fabs(r.scale - 0.6f) < 1e-6f && r.linesAfter * r.scale <= 3.0f + 1e-5f);
        bool allScaled = true;
        for (const FkLine* n : l.nodes)
            allScaled = allScaled && n->scale == r.scale;
        CHECK(allScaled && std::fabs(l.FirstTop() - (300.0f + 6.0f * 5)) <= 1e-3f && std::fabs(r.topBuilt - top) <= 1e-3f);
    }
    {   // every check before a change declines with the label exactly as built
        struct Case { const char* name; void (*spoil)(FkLabel&, nf::PopupFitEnv&); };
        const Case cases[] = {
            { "vtable", [](FkLabel& l, nf::PopupFitEnv&) { *reinterpret_cast<void***>(l.mem) = g_fkLineVt; } },
            { "line count", [](FkLabel& l, nf::PopupFitEnv&) { l.I(nf::kLabelLineCount) = 100; } },
            { "wrap width", [](FkLabel& l, nf::PopupFitEnv&) {
                  l.F(nf::kLabelWrap) = std::numeric_limits<float>::quiet_NaN(); } },
            { "text", [](FkLabel& l, nf::PopupFitEnv&) { l.Text().size = l.Text().capacity + 1; } },
            { "line list", [](FkLabel& l, nf::PopupFitEnv&) {
                  *reinterpret_cast<FkList**>(l.mem + nf::kLabelLines) = nullptr; } },
            { "short line list", [](FkLabel& l, nf::PopupFitEnv&) { l.list.end = l.list.begin + 2; } },
            { "scale", [](FkLabel& l, nf::PopupFitEnv&) { l.ScaleY() = 0.9f; } },
            { "position", [](FkLabel& l, nf::PopupFitEnv&) {
                  l.F(nf::kLabelX) = std::numeric_limits<float>::infinity(); } },
            { "setString", [](FkLabel&, nf::PopupFitEnv& e) { e.setText = nullptr; } },
        };
        for (const Case& c : cases)
        {
            nf::PopupFitEnv& e = FkEnv();
            FkLabel l;
            l.Build(200);
            c.spoil(l, e);
            const std::vector<uint8_t> before = l.Snap();
            nf::FitPopupDesc(e, l.P(), r);
            CHECK_MSG(r.outcome == nf::PopupFit::Declined && *r.why && g_fk.setTextCalls == 0 && l.Snap() == before,
                      std::string("declined, untouched: ") + c.name);
            *reinterpret_cast<void***>(l.mem) = g_fkLabelVt;     // let the destructor see a whole label
            *reinterpret_cast<FkList**>(l.mem + nf::kLabelLines) = &l.list;
            l.Text().size = 200;
        }
        nf::PopupFitEnv& e = FkEnv();
        FkLabel l;
        l.Build(200);
        l.I(nf::kLabelLineCount) = 100;
        CP_FitPopupDesc(l.P());
        CHECK(LogHas("skill popup vertical fit: label left as built (100 lines): implausible line count")
              && !e.disabled && g_fk.disableCalls == 0);
    }
    {   // the re-wrap lays out no line nodes: restored as built (stock width, text, scale, first line) and verified
        nf::PopupFitEnv& e = FkEnv();
        g_fk.emptyFrom = 1;
        g_fk.emptyUntil = 2;
        FkLabel l;
        l.Build(200);
        const float top = l.FirstTop();
        nf::FitPopupDesc(e, l.P(), r);
        CHECK_MSG(r.outcome == nf::PopupFit::Restored && r.linesRestored == 5, "restored after the re-wrap");
        CHECK(l.F(nf::kLabelWrap) == 258.0f && l.ScaleX() == 1.0f && l.nodes.size() == 5u);
        CHECK(std::fabs(l.FirstTop() - top) <= 1e-3f && l.Text().size == 200);
        CHECK_MSG(g_fk.setTextCalls == 2 && g_fk.assignCalls == 2 && g_fk.heapLive == 1, "both copies freed");
        g_fk.setTextCalls = 0;
        g_fk.emptyFrom = 1;
        g_fk.emptyUntil = 2;
        FkLabel l2;
        l2.Build(200);
        g_fk.setTextCalls = 0;
        CP_FitPopupDesc(l2.P());
        CHECK(LogHas("skill popup vertical fit: the re-wrapped layout has no usable lines; the label was laid out "
                     "again as built (scale 1.000, wrap 258.0, 5 lines")
              && !e.disabled && g_fk.disableCalls == 0);
    }
    {   // the restore does not verify either: reported, the fit disabled for the session, later calls do nothing
        nf::PopupFitEnv& e = FkEnv();
        g_fk.emptyFrom = 1;
        FkLabel l;
        l.Build(200);
        CP_FitPopupDesc(l.P());
        CHECK(LogHas("the re-wrapped layout has no usable lines, and laying the label out again as built did not "
                     "verify") && LogHas("Vertical fit off for this session"));
        CHECK(e.disabled && g_fk.disableCalls == 1 && g_fk.setTextCalls == 2);
        FkLabel next;
        g_fk.emptyFrom = 0;
        next.Build(200);
        const std::vector<uint8_t> before = next.Snap();
        CP_FitPopupDesc(next.P());
        CHECK_MSG(g_fk.setTextCalls == 2 && next.Snap() == before && g_fk.disableCalls == 1, "disabled: a no-op");
        nf::FitPopupDesc(e, next.P(), r);
        CHECK(r.outcome == nf::PopupFit::Disabled);
    }
    {   // the scaled layout cannot be measured (NaN): restored as built
        nf::PopupFitEnv& e = FkEnv();
        g_fk.nanWhenScaled = true;
        FkLabel l;
        l.Build(200);
        const float top = l.FirstTop();
        nf::FitPopupDesc(e, l.P(), r);
        CHECK(r.outcome == nf::PopupFit::Restored && std::string(r.why) == "the scaled layout cannot be measured");
        CHECK(l.ScaleX() == 1.0f && l.F(nf::kLabelWrap) == 258.0f && std::fabs(l.FirstTop() - top) <= 1e-3f);
        CHECK(g_fk.heapLive == 1);
    }
    {   // a non-linear layout: the measured correction misses the top, so it is restored as built
        nf::PopupFitEnv& e = FkEnv();
        g_fk.quadratic = 0.05f;
        FkLabel l;
        l.Build(200);
        const float top = l.FirstTop();
        nf::FitPopupDesc(e, l.P(), r);
        CHECK(r.outcome == nf::PopupFit::Restored && std::string(r.why) == "the first line did not return to its top");
        CHECK(l.ScaleX() == 1.0f && std::fabs(l.FirstTop() - top) <= 1e-3f && l.F(nf::kLabelY) == 300.0f);
    }
    {   // an access fault while scaling: not touched again (left partly changed), reported, fit disabled
        nf::PopupFitEnv& e = FkEnv();
        g_fk.faultNodeScale = 2;
        FkLabel l;
        l.Build(200);
        CP_FitPopupDesc(l.P());
        CHECK(LogHas("skill popup vertical fit: access fault while scaling (5 lines); the label is not touched again "
                     "and may be left partly changed"));
        CHECK(e.disabled && g_fk.disableCalls == 1 && g_fk.setTextCalls == 1);
        CHECK_MSG(l.F(nf::kLabelWrap) > 258.0f && l.ScaleX() < 1.0f, "the label is left as the fault found it");
    }
    {   // an access fault inside the client's setString (re-wrapping)
        nf::PopupFitEnv& e = FkEnv();
        g_fk.faultSetText = 1;
        FkLabel l;
        l.Build(200);
        CP_FitPopupDesc(l.P());
        CHECK(LogHas("access fault while re-wrapping (5 lines)") && e.disabled && g_fk.disableCalls == 1);
        g_fk.heapLive -= 1;                                         // the copy the faulted setString never freed
    }
    {   // the thunk, called as a description site: arguments reach the helper, the label is fitted, and eax, ecx,
        // edx, xmm0..7 and esp come back exactly as the helper left them
        FkEnv();
        FkLabel l;
        l.Build(200);
        g_ph_label = reinterpret_cast<uint32_t>(l.P());
        for (int i = 0; i < 8; ++i)
            for (int j = 0; j < 4; ++j)
                g_ph_xmm[i][j] = 0x01010101u * static_cast<uint32_t>(i + 1) + static_cast<uint32_t>(j);
        g_cpLabelHelper = reinterpret_cast<uintptr_t>(&FakeLabelHelper);
        CallPopupThunk();
        CHECK_MSG(g_ph_arg1 == 0x11111111u && g_ph_arg9 == 0x99999999u && g_ph_ecx == 0x3Au && g_ph_edx == 7u
                  && g_ph_xmm3 == 258.0f, "the helper sees the site's registers and nine stack arguments");
        CHECK_MSG(g_pt_eax == g_ph_label && g_pt_ecx == 0x0C0C0C0Cu && g_pt_edx == 0x0D0D0D0Du,
                  "eax/ecx/edx as the helper returned them");
        CHECK_MSG(memcmp(g_pt_xmm, g_ph_xmm, sizeof g_ph_xmm) == 0, "xmm0..7 as the helper returned them");
        CHECK_MSG(g_pt_espAfter == g_pt_espBefore, "the stack is balanced");
        CHECK_MSG(std::fabs(l.ScaleX() - 0.75f) < 1e-6f && g_fk.setTextCalls == 1, "the thunk ran the fit on eax");
        CHECK(LogHas("skill popup vertical fit: 5 lines; wrap 258.0 -> 333.1 gives 4 lines; scale 0.750"));
        g_cpLabelHelper = 0;
    }
    CHECK_MSG(g_fk.heapLive == 0, "every text copy the fakes made was freed");
    nf::popupEnv() = nf::PopupFitEnv();
}

int main()
{
    SetLogDirectoryForTests(TempDir().c_str());
    TestNames();
    TestByteForms();
    TestProtocol();
    TestIndexApply();
    TestByteCache();
    TestProvider();
    TestProviderSwitchedOff();
    TestProviderConcurrency();
    TestVersionBinding();
    TestHookLogic();
    TestPrefixThread();
    TestThunkAbi();
    TestInstrumentation();
    TestSignatures();
    TestGateFlashDecision();
    TestGateFlashThunk();
    TestCodeWriteSteps();
    TestNameFitSites();
    TestPopupFit();
    TestGateFlashSignatures();
    TestLiveBroker();
    TestGenerationIsolationQC();
    TestPendingReadinessQC();
    TestEnqueueFilter();
    TestDecisionLogging();
    TestStartupCoverage();
    TestClientInputs();
    TestCoverageCorpus();
    TestStartupDecisions();
    TestStartupProviderStates();
    TestStartupHooks();
    TestStartupSignatures();
    TestSiteSnapshots();
    TestStartupAttachOrder();
    TestLiveStartupCoverage();
    TestAudioHooks();
    TestLiveAudio();
    TestLiveFamilyPolicy();
    TestLiveVisibleSwap();
    TestXmlSaveDedupe();
    printf("content_provider_tests: %d passed, %d failed, %d skipped\n", t::counters().passed, t::counters().failed,
           t::counters().skipped);
    return t::counters().failed ? 1 : 0;
}
