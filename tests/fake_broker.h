/**
* @file fake_broker.h
* @brief In-process stand-in for the server's content broker, speaking the
* same "bfcp 2" text protocol (gimuserver/content/ContentBroker.cpp), with
* knobs for the failures the provider must survive.  Like the real broker it
* publishes each file's digest and answers a version-bound read whose version
* is gone with 409 (honorVersion = false plays a broker that ignores d=).
*/
#pragma once

#include "cp_provider.h"

#include <atomic>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

struct FakeFile
{
    std::string name;
    std::vector<uint8_t> bytes;
    uint64_t gen = 1;
};

class FakeBroker : public cp::IBroker
{
public:
    std::mutex lock;
    bool enabled = true;
    bool ready = true;
    std::string epoch = "e1";
    uint64_t generation = 1;
    std::map<std::string, FakeFile> files;        // rel -> file
    std::map<std::string, uint64_t> tombstones;   // folded name -> gen
    std::set<std::string> collisions;             // folded names
    std::atomic<int> fileCalls{ 0 };
    std::atomic<int> busyAnswers{ 0 };            // next N GetFile calls answer 503
    std::atomic<bool> unreachable{ false };
    std::atomic<bool> corruptDigest{ false };
    std::atomic<bool> fileNotReady{ false };      // GetFile answers 503 not-ready
    std::atomic<bool> honorVersion{ true };       // GetFileVersion answers 409 for a version that is gone
    std::string coverage;                         // /coverage body (Session 16); empty = 404, an older broker
    std::string lastCoverageQuery;

    static std::string Base(const std::string& rel)
    {
        const size_t s = rel.find_last_of('/');
        return s == std::string::npos ? rel : rel.substr(s + 1);
    }

    void Put(const std::string& rel, const std::vector<uint8_t>& bytes)
    {
        std::lock_guard<std::mutex> g(lock);
        ++generation;
        FakeFile f;
        f.name = Base(rel);
        f.bytes = bytes;
        f.gen = generation;
        files[rel] = f;
        tombstones.erase(cp::Fold(f.name));
    }

    void Remove(const std::string& rel)
    {
        std::lock_guard<std::mutex> g(lock);
        ++generation;
        tombstones[cp::Fold(Base(rel))] = generation;
        files.erase(rel);
    }

    //! A new generation that changes no owned file -- the real broker's answer
    //! to an unowned file appearing or vanishing: the index head moves, no row does.
    void Bump()
    {
        std::lock_guard<std::mutex> g(lock);
        ++generation;
    }

    void Collide(const std::string& rel)
    {
        std::lock_guard<std::mutex> g(lock);
        ++generation;
        const std::string folded = cp::Fold(Base(rel));
        collisions.insert(folded);
        tombstones[folded] = generation;
        files.erase(rel);
    }

    void Restart()
    {
        std::lock_guard<std::mutex> g(lock);
        epoch += "x";
        generation = 1;
        for (std::map<std::string, FakeFile>::iterator it = files.begin(); it != files.end(); ++it)
            it->second.gen = 1;
        tombstones.clear();
    }

    bool GetText(const std::string& q, int& status, std::string& body, std::string& error) override
    {
        if (unreachable)
        {
            status = 0;
            error = "connection refused";
            return false;
        }
        std::lock_guard<std::mutex> g(lock);
        std::ostringstream o;
        if (q.find("/coverage") != std::string::npos)
        {
            lastCoverageQuery = q;
            status = coverage.empty() ? 404 : 200;
            body = coverage;
            return true;
        }
        if (q.find("/status") != std::string::npos)
        {
            o << "bfcp 2\nenabled " << (enabled ? 1 : 0) << "\nready " << (ready ? 1 : 0) << "\nepoch " << epoch
              << "\ngeneration " << generation << "\nowned " << files.size() << "\n";
            if (!enabled)
                o << "reason disabled by test\n";
            o << "end\n";
            status = 200;
            body = o.str();
            return true;
        }
        if (!enabled || !ready)
        {
            status = 503;
            body = "bfcp 2\nerror not-ready\nend\n";
            return true;
        }
        uint64_t since = 0;
        std::string clientEpoch;
        const size_t s = q.find("since=");
        if (s != std::string::npos)
            since = _strtoui64(q.c_str() + s + 6, nullptr, 10);
        const size_t e = q.find("epoch=");
        if (e != std::string::npos)
            clientEpoch = q.substr(e + 6);
        const bool full = since == 0 || clientEpoch != epoch;
        o << "bfcp 2\nepoch " << epoch << "\ngeneration " << generation << "\nfull " << (full ? 1 : 0) << "\n";
        for (std::map<std::string, FakeFile>::iterator it = files.begin(); it != files.end(); ++it)
            if (full || it->second.gen > since)
                o << "F\t" << it->second.gen << "\t" << it->second.bytes.size() << "\t" << it->second.name << "\t" << it->first
                  << "\t" << Digest(it->second.bytes) << "\n";
        if (!full)
            for (std::map<std::string, uint64_t>::iterator it = tombstones.begin(); it != tombstones.end(); ++it)
                if (it->second > since)
                    o << "D\t" << it->second << "\t" << it->first << "\n";
        for (std::set<std::string>::iterator it = collisions.begin(); it != collisions.end(); ++it)
            o << "C\t" << *it << "\tone/" << *it << "\ttwo/" << *it << "\n";
        o << "end\n";
        status = 200;
        body = o.str();
        return true;
    }

    cp::FetchResult GetFile(const std::string& rel) override
    {
        ++fileCalls;
        cp::FetchResult r;
        if (unreachable)
        {
            r.transportFailure = true;
            r.error = "connection refused";
            return r;
        }
        if (fileNotReady)
        {
            r.status = 503;
            r.error = "not-ready";
            return r;
        }
        if (busyAnswers > 0)
        {
            --busyAnswers;
            r.status = 503;
            r.error = "busy";
            return r;
        }
        std::lock_guard<std::mutex> g(lock);
        std::map<std::string, FakeFile>::iterator it = files.find(rel);
        if (it == files.end())
        {
            r.status = 404;
            r.error = "not-owned";
            return r;
        }
        r.status = 200;
        r.bytes = it->second.bytes;
        r.gen = it->second.gen;
        r.epoch = epoch;
        r.digest = Digest(r.bytes);
        if (corruptDigest)
            r.digest[10] = r.digest[10] == 'a' ? 'b' : 'a';
        return r;
    }

    //! Through the (overridable) GetFile, then the real broker's version check.
    cp::FetchResult GetFileVersion(const std::string& rel, const std::string& digest) override
    {
        cp::FetchResult r = GetFile(rel);
        if (honorVersion && r.status == 200 && Digest(r.bytes) != digest)
        {
            r.status = 409;
            r.error = "version-unavailable";
            r.digest = Digest(r.bytes);
            r.bytes.clear();
        }
        return r;
    }

    static std::string Digest(const std::vector<uint8_t>& bytes)
    {
        return cp::Sha256Tag(bytes.empty() ? nullptr : &bytes[0], bytes.size());
    }
};
