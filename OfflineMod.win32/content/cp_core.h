/**
* @file cp_core.h
* @brief Pure building blocks of the content provider (no game, no network).
*
* Everything here is deterministic and unit-tested in tests/: the flat-name
* path policy, the MSVC text-mode read the game's CSV loader depends on, the
* FileCrypt transform of the client cache, the broker's text protocol, the
* bounded RAM byte cache and the masked byte signatures that gate every hook.
*/
#pragma once

#include <stddef.h>
#include <stdint.h>

#include <condition_variable>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace cp {

// ---------------------------------------------------------------- names ----

//! ASCII lower case (NTFS and the client's flat cache are case-insensitive).
std::string Fold(const std::string& s);

/*!
* A name the client's flat LocalState namespace can hold: non-empty, no
* separators, no drive/stream colon, no control characters, not "." / "..",
* no trailing dot or space (Win32 would silently strip it), at most 255 bytes.
*/
bool IsSafeFlatName(const char* s, size_t n);

/*!
* Client state that the provider must never shadow, whatever an index says:
* UserDefault.xml, XMLFileProcessor.xml, every *.dat (MST parts and the save
* key files), *.xml, *.ini, *.tmp, *.json, *.zip, Thumbs.db, .DS_*.
*/
bool IsProtectedStateName(const std::string& foldedName);

/*!
* If @p path is "<prefix><flat name>" (prefix compared case-insensitively,
* '/' == '\\'), stores the flat name and returns true.
* @param prefixFolded folded writable path, ending in a separator
*/
bool SplitLocalStatePath(const char* path, const std::string& prefixFolded, std::string& name);

//! Folds a path and turns '/' into '\\' (for prefix comparison).
std::string FoldPath(const std::string& path);

// ----------------------------------------------------------- byte forms ----

/*!
* What fopen(path, "r") + fread give an MSVC program: CR LF becomes LF, a lone
* CR stays, and CTRL+Z ends the data.  The game's CSV loader reads in text
* mode, so served CSV bytes must be translated exactly like this.
* @return number of bytes written to @p out (out may alias in)
*/
size_t MsvcTextModeTranslate(const uint8_t* in, size_t n, uint8_t* out);

//! The client cache scramble: c[i] = (b[i] + i*i) & 0xFF (in place).
void FileCryptEncode(uint8_t* data, size_t n);
//! Inverse of FileCryptEncode (in place).
void FileCryptDecode(uint8_t* data, size_t n);

//! "sha256:<64 lower hex>" of the bytes (Windows CNG); empty on failure.
std::string Sha256Tag(const uint8_t* data, size_t n);

//! True for "sha256:" followed by exactly 64 lower-case hex digits.
bool IsDigestTag(const std::string& s);

// ------------------------------------------------------------- protocol ----
//
// "bfcp 2": every F row carries the file's identity (digest) and reads are
// bound to it.  A broker speaking any other version is declined.

struct StatusInfo
{
    bool parsed = false;
    bool enabled = false;
    bool ready = false;
    std::string epoch;
    uint64_t generation = 0;
    std::string reason;
};

//! Parses the broker's "bfcp 2" status body.
bool ParseStatus(const std::string& text, StatusInfo& out, std::string& error);

struct IndexEntry
{
    std::string name;   //!< basename as enumerated
    std::string rel;    //!< exact relative path on the broker
    uint64_t size = 0;
    uint64_t gen = 0;
    std::string digest; //!< "sha256:<hex>": the identity a read of this entry must return
};

struct IndexSnapshot
{
    std::string epoch;
    uint64_t generation = 0;
    bool full = false;
    std::map<std::string, IndexEntry> files;   //!< folded name -> entry (F rows)
    std::map<std::string, uint64_t> removed;   //!< folded name -> gen (D rows)
    std::set<std::string> collisions;          //!< folded names (C rows)
    std::map<std::string, uint64_t> unavailable; //!< folded name -> gen (X rows: incomplete bundle members)
};

//! Parses an index body; rejects unknown rows, bad numbers, unsafe names and a missing "end".
bool ParseIndex(const std::string& text, IndexSnapshot& out, std::string& error);

/*!
* The broker's startup coverage report (Session 16, /offline_mod/content/v1/coverage):
* whether every name the client's login and background-download lists ask for is
* owned and servable, for exactly one epoch and generation of the index.
*/
struct CoverageSet
{
    uint64_t required = 0, ok = 0, absent = 0, unowned = 0, missing = 0, ambiguous = 0, unavailable = 0;
};

/*!
* One of the installed client's own files a startup manifest was derived from (Session 18, the
* report's "I" rows): a master table in LocalState or a file of the package, with its SHA-256.
*/
struct ClientInput
{
    std::string root;      //!< "localstate" or "package"
    std::string path;      //!< a flat LocalState name, or a '/'-separated path inside the package
    std::string digest;    //!< "sha256:<hex>"
};

struct CoverageInfo
{
    bool parsed = false;
    /*!
    * The report PROVES complete coverage: it says "complete 1" and everything else it states
    * agrees -- enabled, ready, built for this client, a loaded manifest and policy, no unknown
    * list, exactly the "login" and "background" sets, each non-empty and fully owned, no problem
    * row, no reason.  A bare "complete 1" is never enough (QC 2026-10-20).
    */
    bool complete = false;
    bool claimed = false;          //!< the report's own "complete 1"
    bool enabled = false, ready = false, buildMatch = false;
    std::string epoch;
    uint64_t generation = 0;
    std::string policy, manifest, manifestBuild, clientBuild, reason;
    bool manifestError = false;
    uint64_t unknown = 0, excluded = 0;
    std::map<std::string, CoverageSet> sets;
    uint64_t problemRows = 0, unknownRows = 0;
    uint64_t absent = 0;           //!< names no source has: a gap, never part of a complete report
    //! The client files the manifest was derived from ("inputs" and its I rows).  A complete report
    //! names at least one; the caller still has to show this client holds them (VerifyClientInputs).
    uint64_t inputCount = 0;
    std::vector<ClientInput> inputs;
};

/*!
* Parses a "bfcp 2" / "coverage 1" body ending in "end"; an unknown field or row, a duplicate,
* a bad number or a missing header field is not a report (false).  A report that parses but
* contradicts itself, or does not prove completeness, comes back parsed with complete false and
* the reason.  With expectBuild, completeness also needs the client and manifest builds to be it.
*/
bool ParseCoverage(const std::string& text, CoverageInfo& out, std::string& error,
                   const std::string& expectBuild = std::string());

/*!
* Whether this client holds exactly the inputs a coverage report names: every file present under
* its root with that SHA-256, and LocalState holding no other version or part of a named master
* table (Ver<v>_<key>[_<n>].dat) -- which one the game reads could not be told.  Fails closed: an
* unknown root directory, an unreadable or different file, an extra version.
* @param localStateDir the game's writable path (with or without a trailing separator)
* @param packageDir    the folder holding the client EXE
*/
bool VerifyClientInputs(const std::vector<ClientInput>& inputs, const std::string& localStateDir,
                        const std::string& packageDir, std::string& why);

enum class Ownership { NotOwned, Present, Absent };

/*!
* The provider's view of which flat names it is authoritative for.  Present
* names are served from the broker; Absent names were owned earlier in this
* session and are reported missing (never handed back to a stale cache).
*/
class ContentIndex
{
public:
    Ownership Lookup(const std::string& foldedName, IndexEntry* entry = nullptr) const;

    /*!
    * Applies a snapshot.  A full snapshot (or a new epoch) replaces the set;
    * names that disappear become tombstones.  Returns the folded names whose
    * bytes may differ from what was served before (for cache eviction).
    */
    std::vector<std::string> Apply(const IndexSnapshot& snap);

    const std::string& Epoch() const { return m_epoch; }
    uint64_t Generation() const { return m_generation; }
    size_t PresentCount() const { return m_present.size(); }
    size_t AbsentCount() const { return m_absent.size(); }
    size_t CollisionCount() const { return m_collisions.size(); }

private:
    std::string m_epoch;
    uint64_t m_generation = 0;
    std::map<std::string, IndexEntry> m_present;
    std::set<std::string> m_absent;
    std::set<std::string> m_collisions;
};

// ----------------------------------------------------------- byte cache ----

struct Blob
{
    std::vector<uint8_t> bytes;
    std::string digest;     //!< "sha256:..." as verified on receipt
    uint64_t gen = 0;
};
typedef std::shared_ptr<const Blob> BlobPtr;

/*!
* Bounded LRU of fetched files.  The provider keys it by content identity
* (broker path + digest), so a key can only ever hold one version's bytes.
* Holds raw bytes only; every caller gets its own copy, so eviction never
* frees memory the game still uses.  Get-or-fetch is single-flight:
* concurrent requests for one key wait for the first fetch instead of
* repeating it.
*
* Scene tokens: a fetch remembers the token it started under.  If the token
* has moved on by the time it completes (a scene change adopted a new index
* meanwhile), its bytes still reach the callers that asked for them, but are
* not cached -- an outstanding read can never repopulate the cache after the
* scene that wanted it is gone.
*/
class ByteCache
{
public:
    //! Token for callers outside the scene protocol: their fetches are always cached.
    static const uint64_t kAnyToken = ~0ull;

    explicit ByteCache(size_t maxBytes, size_t maxEntryBytes);

    BlobPtr Get(const std::string& key);
    void Put(const std::string& key, BlobPtr blob);
    void Evict(const std::string& key);
    void Clear();
    //! Moves the cache to a new scene token (monotonic).
    void SetToken(uint64_t token);

    /*!
    * Returns the cached blob or runs @p fetch once for all concurrent callers.
    * @param fetch returns nullptr on failure and may set @p error
    * @param token scene token the caller read its index entry under
    */
    BlobPtr GetOrFetch(const std::string& key, const std::function<BlobPtr(std::string&)>& fetch,
                       std::string& error, bool* hit = nullptr, uint64_t token = kAnyToken);

    size_t Bytes() const;
    size_t Entries() const;
    uint64_t Hits() const { return Counter(m_hits); }
    uint64_t Misses() const { return Counter(m_misses); }
    uint64_t Coalesced() const { return Counter(m_coalesced); }
    uint64_t Evictions() const { return Counter(m_evictions); }
    //! Fetches that completed after a scene change and were therefore not cached.
    uint64_t Dropped() const { return Counter(m_dropped); }

private:
    struct Flight
    {
        bool done = false;
        BlobPtr result;
        std::string error;
        uint64_t token = kAnyToken;
    };
    void PutLocked(const std::string& key, BlobPtr blob);
    //! 64-bit counters are read under the lock (not atomic on x86).
    uint64_t Counter(const uint64_t& c) const { std::lock_guard<std::mutex> lock(m_mutex); return c; }

    const size_t m_maxBytes;
    const size_t m_maxEntryBytes;
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::list<std::string> m_lru;  //!< front = most recent
    struct Slot { BlobPtr blob; std::list<std::string>::iterator pos; };
    std::unordered_map<std::string, Slot> m_slots;
    std::unordered_map<std::string, std::shared_ptr<Flight>> m_flights;
    size_t m_bytes = 0;
    uint64_t m_token = 0;
    uint64_t m_hits = 0, m_misses = 0, m_coalesced = 0, m_evictions = 0, m_dropped = 0;
};

// ----------------------------------------------------------- signatures ----

struct SiteSignature
{
    const char* name;
    unsigned module;        //!< 0 = game EXE, 1 = cocos2d DLL
    uint32_t rva;
    const char* bytes;      //!< hex pairs
    const char* mask;       //!< 'x' compare, '?' relocated (ignored)
};

struct ModuleIdentity
{
    const char* file;
    uint32_t timeDateStamp;
    uint32_t sizeOfImage;
    uint32_t entryPoint;
};

/*!
* Compares a masked signature against image bytes.
* @param image bytes starting at the site (mapped image or on-disk section)
* @param available readable bytes at @p image
*/
bool MatchSignature(const SiteSignature& sig, const uint8_t* image, size_t available, std::string& why);

/*!
* Checks a PE image's identity fields (in memory or on disk).
* @param headers start of the image (MZ header)
*/
bool MatchIdentity(const ModuleIdentity& id, const uint8_t* headers, size_t available, std::string& why);

//! "TTTTTTTT-SSSSSSSS-EEEEEEEE": the build identity the broker's startup manifest names
//! (TimeDateStamp, SizeOfImage, AddressOfEntryPoint -- the fields MatchIdentity checks).
std::string BuildIdentity(const ModuleIdentity& id);

// ------------------------------------------- sites another component patches ----

/*!
* A Detours detour (x86) one component of this DLL placed on a function, as Detours leaves it:
* the target starts with E9 to the detour, padded with CC to the end of the instructions it
* displaced; the trampoline Detours handed back holds those instructions, then E9 back to the
* first instruction left in place.
*/
struct CodeDetour
{
    const char* owner = nullptr;           //!< the component that placed it (for the log)
    const char* site = nullptr;            //!< that component's signature name for the target
    uintptr_t target = 0;                  //!< the patched function
    uintptr_t detour = 0;                  //!< the hook's code: where the target's E9 must lead
    const uint8_t* trampoline = nullptr;   //!< what Detours wrote back into the target pointer
};

//! A site checked on the untouched image, and the bytes it held then.
struct SiteSnapshot
{
    const SiteSignature* sig = nullptr;
    uintptr_t address = 0;
    std::vector<uint8_t> bytes;
};

//! A site of the verifying component that a detour of another component is expected to patch first.
struct SharedSite
{
    const char* site;          //!< the verifying component's signature name
    const char* detourSite;    //!< the CodeDetour::site expected on it
};

/*!
* Checks sites on the untouched image -- committed executable memory, each matching its masked
* signature -- and keeps their bytes for VerifySitesSince.
* @param base the module the RVAs are relative to (every row must be a module 0 row)
*/
bool SnapshotSites(uintptr_t base, const SiteSignature* sigs, size_t count, std::vector<SiteSnapshot>& out,
                   std::string& why);

/*!
* Checks snapshotted sites again after other components have patched the image.  Each must still
* hold its snapshot bytes exactly (masked bytes included), except a site a SharedSite names: there
* the named detour must be recorded in @p detours with its target inside the site, the site must
* hold exactly that patch (E9 to its detour, CC to the end of the displaced instructions), the
* trampoline must hold exactly the displaced snapshot bytes followed by E9 back to the first
* instruction left in place, and every other byte must be unchanged.  Anything else -- a jump
* elsewhere, a changed byte outside the patch, a detour missing, misplaced or not in place, a
* trampoline that does not resume the original -- is false with the reason.
*/
bool VerifySitesSince(const std::vector<SiteSnapshot>& snapshots, const CodeDetour* detours, size_t detourCount,
                      const SharedSite* shared, size_t sharedCount, std::string& why);

} // namespace cp
