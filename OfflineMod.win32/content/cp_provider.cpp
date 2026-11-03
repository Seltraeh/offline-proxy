/**
* @file cp_provider.cpp
* @brief The authoritative content provider (see cp_provider.h).
*/
#include "cp_provider.h"
#include "cp_log.h"

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <wininet.h>

#include <algorithm>
#include <chrono>

namespace cp {

namespace {

const DWORD kConnectTimeoutMs = 1500;
const DWORD kReceiveTimeoutMs = 5000;
const DWORD kSendTimeoutMs = 3000;
const uint64_t kUnreachableBackoffMs = 3000;
const int kBusyRetries = 3;

const DWORD kRequestFlags = INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_PRAGMA_NOCACHE
    | INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_UI | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_AUTO_REDIRECT;

//! Error text prefix for a pinned version the server no longer has (crosses the byte cache as a string).
const char kSuperseded[] = "superseded: ";

bool IsSuperseded(const std::string& error)
{
    return error.compare(0, sizeof kSuperseded - 1, kSuperseded) == 0;
}

//! "sha256:0123abcd" -- enough of a digest for a log line.
std::string ShortDigest(const std::string& d)
{
    return d.empty() ? std::string("?") : d.substr(0, 7 + 8);
}

bool QueryCustomHeader(HINTERNET req, const char* name, std::string& out)
{
    char buffer[256];
    strcpy_s(buffer, name);
    DWORD len = sizeof buffer;
    DWORD index = 0;
    if (!HttpQueryInfoA(req, HTTP_QUERY_CUSTOM, buffer, &len, &index))
        return false;
    out.assign(buffer, len);
    return true;
}

uint64_t ToU64(const std::string& s)
{
    uint64_t v = 0;
    for (size_t i = 0; i < s.size() && s[i] >= '0' && s[i] <= '9'; ++i)
        v = v * 10 + static_cast<uint64_t>(s[i] - '0');
    return v;
}

} // namespace

std::string EncodeQueryValue(const std::string& s)
{
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (size_t i = 0; i < s.size(); ++i)
    {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
            || c == '-' || c == '_' || c == '.' || c == '~' || c == '/')
            out.push_back(static_cast<char>(c));
        else
        {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 15]);
        }
    }
    return out;
}

// ------------------------------------------------------------ WinINet ------

WinInetBroker::WinInetBroker(const char* host, unsigned short port)
    : m_host(host), m_port(port)
{
}

WinInetBroker::~WinInetBroker()
{
    // Deliberately not closing the session: this object lives until process
    // exit and WinINet must not be torn down under the loader lock.
}

void* WinInetBroker::Session()
{
    std::lock_guard<std::mutex> lock(m_sessionLock);
    if (!m_session)
    {
        HINTERNET s = InternetOpenA("OfflineMod-ContentProvider", INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
        if (s)
        {
            DWORD t = kConnectTimeoutMs;
            InternetSetOptionA(s, INTERNET_OPTION_CONNECT_TIMEOUT, &t, sizeof t);
            t = kReceiveTimeoutMs;
            InternetSetOptionA(s, INTERNET_OPTION_RECEIVE_TIMEOUT, &t, sizeof t);
            t = kSendTimeoutMs;
            InternetSetOptionA(s, INTERNET_OPTION_SEND_TIMEOUT, &t, sizeof t);
        }
        m_session = s;
    }
    return m_session;
}

bool WinInetBroker::Request(const std::string& pathAndQuery, FetchResult& out)
{
    out = FetchResult();
    HINTERNET session = static_cast<HINTERNET>(Session());
    if (!session)
    {
        out.transportFailure = true;
        out.error = "InternetOpen failed";
        return false;
    }
    // InternetOpenUrlA, not InternetConnectA + HttpOpenRequestA: main.cpp hooks
    // those two to redirect the GAME's traffic (and prints each call in the
    // standalone build's console).  The broker is already SERVICE_IP:PORT, so
    // the provider needs no redirect and must not spam that console every poll.
    const std::string url = "http://" + m_host + ":" + std::to_string(m_port) + pathAndQuery;
    HINTERNET req = InternetOpenUrlA(session, url.c_str(), nullptr, 0, kRequestFlags, 0);
    bool ok = false;
    if (!req)
    {
        out.transportFailure = true;
        out.error = "InternetOpenUrl failed (" + std::to_string(GetLastError()) + ")";
    }
    else
    {
        DWORD status = 0, len = sizeof status, index = 0;
        HttpQueryInfoA(req, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status, &len, &index);
        out.status = static_cast<int>(status);
        DWORD contentLength = 0;
        len = sizeof contentLength;
        index = 0;
        if (HttpQueryInfoA(req, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &contentLength, &len, &index))
            out.bytes.reserve(contentLength);
        std::string v;
        if (QueryCustomHeader(req, "X-BFCP-Digest", v)) out.digest = v;
        if (QueryCustomHeader(req, "X-BFCP-Epoch", v)) out.epoch = v;
        if (QueryCustomHeader(req, "X-BFCP-Gen", v)) out.gen = ToU64(v);
        if (QueryCustomHeader(req, "X-BFCP-Error", v)) out.error = v;
        char buffer[64 * 1024];
        DWORD got = 0;
        ok = true;
        for (;;)
        {
            if (!InternetReadFile(req, buffer, sizeof buffer, &got))
            {
                out.transportFailure = true;
                out.error = "InternetReadFile failed (" + std::to_string(GetLastError()) + ")";
                ok = false;
                break;
            }
            if (got == 0)
                break;
            out.bytes.insert(out.bytes.end(), buffer, buffer + got);
        }
        if (ok && contentLength && out.bytes.size() != contentLength)
        {
            out.transportFailure = true;
            out.error = "short body";
            ok = false;
        }
    }
    if (req)
        InternetCloseHandle(req);
    return ok;
}

bool WinInetBroker::GetText(const std::string& pathAndQuery, int& status, std::string& body, std::string& error)
{
    FetchResult r;
    const bool ok = Request(pathAndQuery, r);
    status = r.status;
    body.assign(r.bytes.begin(), r.bytes.end());
    error = r.error;
    return ok;
}

FetchResult WinInetBroker::GetFile(const std::string& rel)
{
    FetchResult r;
    Request("/offline_mod/content/v1/file?p=" + EncodeQueryValue(rel), r);
    return r;
}

FetchResult WinInetBroker::GetFileVersion(const std::string& rel, const std::string& digest)
{
    FetchResult r;
    Request("/offline_mod/content/v1/file?p=" + EncodeQueryValue(rel) + "&d=" + EncodeQueryValue(digest), r);
    return r;
}

// ----------------------------------------------------------- Provider ------

Provider::Provider(IBroker* broker, size_t cacheBytes, size_t maxEntryBytes)
    : m_broker(broker), m_cache(cacheBytes, maxEntryBytes), m_state(ProviderState::Idle), m_stop(false),
      m_pollMs(1000), m_unreachableUntil(0)
{
    m_wakeEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
}

Provider::~Provider()
{
    Stop();
    if (m_thread.joinable())
        m_thread.join();
    if (m_wakeEvent)
        CloseHandle(static_cast<HANDLE>(m_wakeEvent));
}

void Provider::EnsureStarted()
{
    if (!m_autoStart)
        return;
    std::call_once(m_startOnce, [this] {
        m_state = ProviderState::Starting;
        m_thread = std::thread([this] { ThreadMain(); });
    });
}

void Provider::Stop()
{
    m_stop = true;
    if (m_wakeEvent)
        SetEvent(static_cast<HANDLE>(m_wakeEvent));
}

bool Provider::LoadStatus(StatusInfo& st, std::string& why)
{
    int status = 0;
    std::string body, error;
    if (!m_broker->GetText("/offline_mod/content/v1/status", status, body, error) || status != 200)
    {
        why = status == 404 ? "server has no content broker (404)" : ("status unreachable: " + error);
        return false;
    }
    if (!ParseStatus(body, st, error))
    {
        why = "status unreadable: " + error;
        return false;
    }
    return true;
}

bool Provider::InitializeOnce(std::string& why)
{
    StatusInfo st;
    if (!LoadStatus(st, why))
        return false;
    if (!st.enabled)
    {
        m_state = ProviderState::Dormant;
        why = "broker disabled by the server" + (st.reason.empty() ? std::string() : (": " + st.reason));
        return false;
    }
    if (!st.ready)
    {
        why = "broker still indexing";
        return false;
    }
    int status = 0;
    std::string body, error;
    if (!m_broker->GetText("/offline_mod/content/v1/index?since=0&epoch=", status, body, error) || status != 200)
    {
        why = "index unavailable (" + std::to_string(status) + ") " + error;
        return false;
    }
    IndexSnapshot snap;
    if (!ParseIndex(body, snap, error) || !snap.full)
    {
        why = "index rejected: " + error;
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(m_lock);
        m_index.Apply(snap);
        m_havePending = false;
        AdvanceTokenLocked();
        m_cache.Clear();
    }
    m_state = ProviderState::Active;
    CP_LOG_INFO("provider active: epoch %s generation %llu, %u owned name(s), %u collision(s) declined",
                snap.epoch.c_str(), static_cast<unsigned long long>(snap.generation),
                static_cast<unsigned>(m_index.PresentCount()), static_cast<unsigned>(m_index.CollisionCount()));
    for (std::set<std::string>::const_iterator it = snap.collisions.begin(); it != snap.collisions.end(); ++it)
        CP_LOG_WARN("collision declined (no alias on the server): %s", it->c_str());
    return true;
}

bool Provider::PollOnce(std::string& why)
{
    uint64_t since;
    std::string epoch;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        since = m_index.Generation();
        epoch = m_index.Epoch();
    }
    int status = 0;
    std::string body, error;
    const std::string q = "/offline_mod/content/v1/index?since=" + std::to_string(since) + "&epoch=" + EncodeQueryValue(epoch);
    if (!m_broker->GetText(q, status, body, error) || status != 200)
    {
        why = "delta unavailable (" + std::to_string(status) + ") " + error;
        // Rollback path: the maintainer switched the broker off (or the server
        // restarted without it).  Hand the names back to the game's own cache
        // at the next scene change rather than failing every read until a
        // relaunch.
        StatusInfo st;
        std::string statusWhy;
        const bool parsed = LoadStatus(st, statusWhy);
        if ((parsed && !st.enabled) || status == 404)
        {
            std::lock_guard<std::mutex> lock(m_lock);
            if (!m_dormantPending)
                CP_LOG_WARN("broker switched off by the server (%s); provider goes dormant at the next scene change",
                            parsed ? (st.reason.empty() ? "enabled 0" : st.reason.c_str()) : "no broker endpoint");
            m_dormantPending = true;
        }
        return false;
    }
    IndexSnapshot snap;
    if (!ParseIndex(body, snap, error))
    {
        why = "delta rejected: " + error;
        return false;
    }
    std::lock_guard<std::mutex> lock(m_lock);
    // Nothing new: keep whatever is already pending.
    const bool changes = snap.full || snap.generation != m_index.Generation() || !snap.files.empty()
        || !snap.removed.empty() || snap.collisions.size() != m_index.CollisionCount();
    if (changes)
    {
        if (!m_havePending || m_pending.generation != snap.generation || m_pending.full != snap.full)
            CP_LOG_INFO("pending generation %llu (%s, %u file row(s), %u removal(s)) -- adopted at the next scene change",
                        static_cast<unsigned long long>(snap.generation), snap.full ? "full" : "delta",
                        static_cast<unsigned>(snap.files.size()), static_cast<unsigned>(snap.removed.size()));
        m_pending = snap;
        m_havePending = true;
    }
    return true;
}

void Provider::ThreadMain()
{
    unsigned backoff = 250;
    while (!m_stop)
    {
        std::string why;
        if (InitializeOnce(why))
            break;
        if (m_state.load() == ProviderState::Dormant)
        {
            CP_LOG_INFO("provider dormant: %s", why.c_str());
            return;
        }
        static std::string lastWhy;
        if (why != lastWhy)
        {
            CP_LOG_INFO("provider waiting: %s", why.c_str());
            lastWhy = why;
        }
        WaitForSingleObject(static_cast<HANDLE>(m_wakeEvent), backoff);
        backoff = (std::min)(backoff * 2, 4000u);
    }
    while (!m_stop)
    {
        WaitForSingleObject(static_cast<HANDLE>(m_wakeEvent), m_pollMs.load());
        // Dormant (switched off mid-session) stays dormant until the next launch.
        if (m_stop || m_state.load() == ProviderState::Dormant)
            break;
        std::string why;
        if (!PollOnce(why))
        {
            static std::string lastWhy;
            if (why != lastWhy)
            {
                CP_LOG_WARN("index poll failed: %s", why.c_str());
                lastWhy = why;
            }
        }
    }
}

Ownership Provider::Classify(const std::string& name, IndexEntry* entry)
{
    const std::string folded = Fold(name);
    if (IsProtectedStateName(folded))
        return Ownership::NotOwned;
    std::lock_guard<std::mutex> lock(m_lock);
    ++m_stats.lookups;
    const Ownership o = m_index.Lookup(folded, entry);
    if (o != Ownership::NotOwned)
        ++m_stats.ownedLookups;
    return o;
}

BlobPtr Provider::Fetch(const IndexEntry& e, std::string& error)
{
    const uint64_t now = GetTickCount64();
    if (now < m_unreachableUntil.load())
    {
        error = "broker unreachable (fast-fail window)";
        return BlobPtr();
    }
    for (int attempt = 0; ; ++attempt)
    {
        LARGE_INTEGER t0, t1, f;
        QueryPerformanceCounter(&t0);
        FetchResult r = m_broker->GetFileVersion(e.rel, e.digest);
        QueryPerformanceCounter(&t1);
        QueryPerformanceFrequency(&f);
        {
            std::lock_guard<std::mutex> lock(m_lock);
            ++m_stats.fetches;
            m_stats.fetchMicros += static_cast<uint64_t>((t1.QuadPart - t0.QuadPart) * 1000000 / (f.QuadPart ? f.QuadPart : 1));
        }
        if (r.transportFailure && r.status == 0)
        {
            m_unreachableUntil = GetTickCount64() + kUnreachableBackoffMs;
            error = "broker unreachable: " + r.error;
            return BlobPtr();
        }
        if (r.status == 503 && r.error == "not-ready")
        {
            // The broker is (re)building its index or switched off: not worth
            // retrying per frame.
            m_unreachableUntil = GetTickCount64() + kUnreachableBackoffMs;
            error = "broker not ready";
            return BlobPtr();
        }
        if (r.status == 503 && attempt < kBusyRetries)
        {
            Sleep(30 * (attempt + 1));
            continue;
        }
        if (r.status == 409)
        {
            // The broker keeps no old versions: this scene's version is gone.
            error = std::string(kSuperseded) + "server copy changed after this scene pinned it (pinned "
                + ShortDigest(e.digest) + " gen " + std::to_string(e.gen) + ", server now "
                + ShortDigest(r.digest) + " gen " + std::to_string(r.gen) + ")";
            return BlobPtr();
        }
        if (r.status != 200)
        {
            error = "broker answered " + std::to_string(r.status) + (r.error.empty() ? std::string() : (" " + r.error));
            return BlobPtr();
        }
        const std::string digest = Sha256Tag(r.bytes.empty() ? nullptr : &r.bytes[0], r.bytes.size());
        if (digest.empty() || digest != r.digest)
        {
            error = "digest mismatch (received " + digest + ", announced " + r.digest + ")";
            return BlobPtr();
        }
        // Complete bytes, but are they the version this scene pinned?  The
        // pinned identity decides, not what the response says about itself.
        if (digest != e.digest)
        {
            error = std::string(kSuperseded) + "server sent another version (pinned " + ShortDigest(e.digest)
                + ", received " + ShortDigest(digest) + ")";
            return BlobPtr();
        }
        std::shared_ptr<Blob> blob = std::make_shared<Blob>();
        blob->bytes.swap(r.bytes);
        blob->digest = digest;
        blob->gen = r.gen;
        {
            std::lock_guard<std::mutex> lock(m_lock);
            m_stats.bytesFetched += blob->bytes.size();
        }
        return blob;
    }
}

void Provider::AdvanceTokenLocked()
{
    ++m_pinToken;
    m_cache.SetToken(m_pinToken);
    m_superseded.clear();
}

ReadStatus Provider::Read(const std::string& name, std::vector<uint8_t>& out, std::string& error,
                          IndexEntry* used, bool* cacheHit)
{
    const std::string folded = Fold(name);
    if (IsProtectedStateName(folded))
        return ReadStatus::NotOwned;
    IndexEntry e;
    std::string key;
    uint64_t token = 0;
    {
        // Entry, identity and scene token are taken together, and the read is
        // registered before it starts: a scene change can never pair this
        // read with the next scene's index, nor miss it when invalidating.
        std::lock_guard<std::mutex> lock(m_lock);
        ++m_stats.lookups;
        const Ownership o = m_index.Lookup(folded, &e);
        if (o == Ownership::NotOwned)
            return ReadStatus::NotOwned;
        ++m_stats.ownedLookups;
        if (o == Ownership::Absent)
        {
            error = "removed from game_content";
            return ReadStatus::Absent;
        }
        key = CacheKey(e);
        token = m_pinToken;
        m_servedRel[folded] = key;
        if (used)
            *used = e;
        if (m_superseded.count(key))
        {
            ++m_stats.reads;
            ++m_stats.readFailures;
            ++m_stats.superseded;
            if (cacheHit)
                *cacheHit = false;
            error = std::string(kSuperseded) + "server copy changed after this scene pinned it (known; no request)";
            return ReadStatus::Superseded;
        }
    }
    bool hit = false;
    BlobPtr blob = m_cache.GetOrFetch(key, [&](std::string& err) { return Fetch(e, err); }, error, &hit, token);
    std::lock_guard<std::mutex> lock(m_lock);
    ++m_stats.reads;
    if (hit)
        ++m_stats.cacheHits;
    if (cacheHit)
        *cacheHit = hit;
    if (!blob)
    {
        ++m_stats.readFailures;
        if (IsSuperseded(error))
        {
            ++m_stats.superseded;
            // Remembered for this scene only, so the game retrying a missing
            // texture every frame does not reach the server every frame.
            if (token == m_pinToken)
                m_superseded.insert(key);
            return ReadStatus::Superseded;
        }
        return ReadStatus::Error;
    }
    out = blob->bytes;
    return ReadStatus::Ok;
}

std::vector<std::string> Provider::SafePoint(const char* why)
{
    std::vector<std::string> names;
    std::vector<std::string> staleKeys;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        ++m_stats.safePoints;
        if (m_dormantPending)
        {
            for (std::map<std::string, std::string>::const_iterator it = m_servedRel.begin(); it != m_servedRel.end(); ++it)
                names.push_back(it->first);
            m_servedRel.clear();
            m_index = ContentIndex();
            m_havePending = false;
            m_pending = IndexSnapshot();
            m_dormantPending = false;
            m_state = ProviderState::Dormant;
            CP_LOG_INFO("safe point (%s): provider dormant; %u served name(s) handed back to the client cache", why,
                        static_cast<unsigned>(names.size()));
        }
        else if (!m_havePending)
            return names;
        // A new index from here on: reads still outstanding from the scene
        // that is ending deliver to their own callers but are not cached.
        AdvanceTokenLocked();
        if (m_state.load() == ProviderState::Dormant)
        {
            m_cache.Clear();
            return names;
        }
        // Cache keys are content identities, so a changed name's new version
        // can never hit its old bytes; evicting the old key just frees RAM.
        const std::vector<std::string> changed = m_index.Apply(m_pending);
        m_stats.adoptedChanges += changed.size();
        CP_LOG_INFO("safe point (%s): adopted generation %llu, %u changed name(s)", why,
                    static_cast<unsigned long long>(m_pending.generation), static_cast<unsigned>(changed.size()));
        for (size_t i = 0; i < changed.size(); ++i)
        {
            names.push_back(changed[i]);
            std::map<std::string, std::string>::const_iterator it = m_servedRel.find(changed[i]);
            if (it != m_servedRel.end())
            {
                staleKeys.push_back(it->second);
                m_servedRel.erase(it);
            }
            CP_LOG_INFO("  changed: %s", changed[i].c_str());
        }
        m_havePending = false;
        m_pending = IndexSnapshot();
    }
    for (size_t i = 0; i < staleKeys.size(); ++i)
        m_cache.Evict(staleKeys[i]);
    return names;
}

bool Provider::FetchCoverage(const std::string& build, CoverageInfo& out, std::string& why)
{
    int status = 0;
    std::string body, error;
    if (!m_broker->GetText("/offline_mod/content/v1/coverage?build=" + EncodeQueryValue(build), status, body, error)
        || status != 200)
    {
        why = status == 404 ? "the server has no coverage report (404: an older broker)"
                            : "coverage report unreachable (" + std::to_string(status) + ") " + error;
        return false;
    }
    // The report must also be for the build this client asked about (client and manifest build).
    if (!ParseCoverage(body, out, error, build))
    {
        why = "coverage report unreadable: " + error;
        return false;
    }
    return true;
}

uint64_t Provider::PinnedGeneration() const
{
    std::lock_guard<std::mutex> lock(m_lock);
    return m_index.Generation();
}

std::string Provider::Epoch() const
{
    std::lock_guard<std::mutex> lock(m_lock);
    return m_index.Epoch();
}

ProviderStats Provider::Stats() const
{
    std::lock_guard<std::mutex> lock(m_lock);
    ProviderStats s = m_stats;
    s.coalesced = m_cache.Coalesced();
    s.dropped = m_cache.Dropped();
    return s;
}

bool Provider::HasPending() const
{
    std::lock_guard<std::mutex> lock(m_lock);
    return m_havePending;
}

} // namespace cp
