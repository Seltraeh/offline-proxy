/**
* @file cp_provider.h
* @brief The authoritative content provider: broker index + RAM byte cache.
*
* Lifecycle: a background thread polls the server's broker
* (/offline_mod/content/v1/status, then /index) until it is enabled and ready,
* loads the owned-file index, and keeps fetching deltas.  Deltas are only
* PENDING until the game reaches a safe point (a cocos scene change): the
* provider adopts them there, evicts the changed files from its RAM cache and
* reports the changed names so the hooks can drop the game's decoded textures.
*
* A scene keeps one coherent generation from entry to exit: every read is
* bound to the identity (digest) its scene's index pinned.  The bytes are
* fetched as exactly that version and verified against it, cached under it,
* and a fetch that outlives its scene is never cached.  When the server no
* longer has the pinned version (it was edited, or the broker restarted with
* other bytes) the read fails with ReadStatus::Superseded -- the game sees a
* missing file until the next scene change adopts the new version -- instead
* of mixing a newer file into an older scene.
*
* Nothing is ever written to disk: bytes live in a bounded LRU and every
* caller receives its own copy.
*/
#pragma once

#include "cp_core.h"

#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace cp {

struct FetchResult
{
    int status = 0;                 //!< HTTP status, 0 = transport failure
    bool transportFailure = false;
    std::string error;
    std::vector<uint8_t> bytes;
    std::string digest;             //!< X-BFCP-Digest
    std::string epoch;              //!< X-BFCP-Epoch
    uint64_t gen = 0;               //!< X-BFCP-Gen
};

//! Transport to the broker; the real one is WinINet over loopback, tests use a fake.
class IBroker
{
public:
    virtual ~IBroker() {}
    virtual bool GetText(const std::string& pathAndQuery, int& status, std::string& body, std::string& error) = 0;
    //! The file's current bytes.
    virtual FetchResult GetFile(const std::string& rel) = 0;
    /*!
    * The bytes of exactly version @p digest, or status 409
    * ("version-unavailable") when the file no longer has it.  The default asks
    * for the current bytes; Provider::Fetch verifies them against @p digest
    * either way, so a transport that cannot bind the version still never
    * hands a scene another version.
    */
    virtual FetchResult GetFileVersion(const std::string& rel, const std::string& digest)
    {
        (void)digest;
        return GetFile(rel);
    }
};

//! WinINet broker client for SERVICE_IP:SERVICE_PORT (redirected by main.cpp's InternetConnect hooks).
class WinInetBroker : public IBroker
{
public:
    WinInetBroker(const char* host, unsigned short port);
    ~WinInetBroker();
    bool GetText(const std::string& pathAndQuery, int& status, std::string& body, std::string& error) override;
    FetchResult GetFile(const std::string& rel) override;
    //! /file?p=<rel>&d=<digest>: the broker answers 409 rather than other bytes.
    FetchResult GetFileVersion(const std::string& rel, const std::string& digest) override;

private:
    bool Request(const std::string& pathAndQuery, FetchResult& out);
    void* Session();

    std::string m_host;
    unsigned short m_port;
    std::mutex m_sessionLock;
    void* m_session = nullptr;
};

//! Percent-encodes a broker relative path for the p= query parameter.
std::string EncodeQueryValue(const std::string& s);

enum class ProviderState { Idle, Starting, Dormant, Active };

struct ProviderStats
{
    uint64_t lookups = 0, ownedLookups = 0;
    uint64_t reads = 0, readFailures = 0, cacheHits = 0;
    uint64_t bytesFetched = 0, fetches = 0;
    uint64_t fetchMicros = 0;
    uint64_t superseded = 0;   //!< reads refused because the server no longer has the pinned version
    uint64_t safePoints = 0, adoptedChanges = 0;
    uint64_t coalesced = 0;    //!< reads that joined another read's fetch of the same version
    uint64_t dropped = 0;      //!< fetches that outlived their scene and were therefore not cached
};

/*!
* Ok: bytes of the pinned version.  NotOwned: the game's own cache answers.
* Absent: owned but removed from game_content.  Superseded: owned, but the
* server no longer has the version this scene pinned (fails like a missing
* file until the next scene change).  Error: transport / busy / corrupt.
*/
enum class ReadStatus { Ok, NotOwned, Absent, Superseded, Error };

class Provider
{
public:
    Provider(IBroker* broker, size_t cacheBytes, size_t maxEntryBytes);
    ~Provider();

    //! Starts the background thread once (idempotent, cheap to call from hooks).
    void EnsureStarted();
    //! Stops polling; does not join (safe from DLL_PROCESS_DETACH).
    void Stop();

    //! One synchronous status + full index load (the background thread's first step; tests call it directly).
    bool InitializeOnce(std::string& why);
    //! Fetches the delta since the pinned generation into the pending slot.
    bool PollOnce(std::string& why);

    ProviderState State() const { return m_state.load(); }
    bool Active() const { return m_state.load() == ProviderState::Active; }

    /*!
    * Ownership of a flat client name (case-insensitive).  Protected client
    * state names are never owned, whatever the index says.
    */
    Ownership Classify(const std::string& name, IndexEntry* entry = nullptr);

    /*!
    * Raw bytes of an owned name, exactly as the pinned generation names them
    * (cached or fetched, verified against the pinned digest).  Busy answers
    * are retried a few times; transport failures fail fast for a short
    * window so a dead server cannot stall every frame; a superseded version
    * fails without another request until the next scene change.
    */
    ReadStatus Read(const std::string& name, std::vector<uint8_t>& out, std::string& error,
                    IndexEntry* used = nullptr, bool* cacheHit = nullptr);

    /*!
    * Adopts the pending delta (if any).  If the server has switched the
    * broker off, the provider goes dormant here instead and reports every
    * name it served as changed, so the game reloads them from its own cache.  Returns the enumerated names whose
    * bytes changed, so decoded copies held by the game can be released.
    */
    std::vector<std::string> SafePoint(const char* why);

    /*!
    * The broker's startup coverage report for @p build, fetched now (Session 16).  False
    * with @p why when it cannot be read or is not a report -- callers treat that as
    * incomplete.  The report names the epoch and generation it describes; it says nothing
    * about any other.
    */
    bool FetchCoverage(const std::string& build, CoverageInfo& out, std::string& why);

    uint64_t PinnedGeneration() const;
    std::string Epoch() const;
    ProviderStats Stats() const;
    size_t CacheBytes() const { return m_cache.Bytes(); }
    bool HasPending() const;

    //! For tests: background poll interval.
    void SetPollIntervalMs(unsigned ms) { m_pollMs = ms; }
    //! For tests: hooks must not spawn the background thread while a test drives the provider.
    void SetAutoStart(bool on) { m_autoStart = on; }

private:
    void ThreadMain();
    bool LoadStatus(StatusInfo& st, std::string& why);
    BlobPtr Fetch(const IndexEntry& e, std::string& error);
    //! Starts a new scene token (index adopted): outstanding fetches stop being cacheable.
    void AdvanceTokenLocked();
    //! Cache key = content identity: broker path + pinned digest.
    static std::string CacheKey(const IndexEntry& e) { return e.rel + "\n" + e.digest; }

    IBroker* m_broker;
    ByteCache m_cache;
    std::atomic<ProviderState> m_state;
    std::atomic<bool> m_stop;
    std::atomic<unsigned> m_pollMs;
    std::atomic<bool> m_autoStart{ true };
    std::once_flag m_startOnce;
    std::thread m_thread;
    void* m_wakeEvent = nullptr;

    mutable std::mutex m_lock;            //!< index, pending, stats
    ContentIndex m_index;
    bool m_havePending = false;
    bool m_dormantPending = false;   //!< the server switched the broker off: go dormant at the next safe point
    IndexSnapshot m_pending;
    ProviderStats m_stats;
    std::map<std::string, std::string> m_servedRel;   //!< folded name -> cache key of its latest read (set when the read starts)
    uint64_t m_pinToken = 0;                          //!< scene token; advanced whenever an index is adopted
    std::set<std::string> m_superseded;               //!< cache keys the server no longer has (cleared on adoption)
    std::atomic<uint64_t> m_unreachableUntil;   //!< GetTickCount64 deadline
};

} // namespace cp
