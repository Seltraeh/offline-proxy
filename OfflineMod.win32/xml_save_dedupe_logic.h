/**
* @file xml_save_dedupe_logic.h
* @brief The decision behind xml_save_dedupe.cpp, kept free of Windows and the client so tests can drive it.
*
* A save is skipped only when ALL of these hold:
*   - this path was written by a save that succeeded, and that save printed exactly the same text;
*   - the file is still there, with the size that write left on disk.
* Anything else (first save of the session, different text, a failed save, the file deleted, replaced or resized
* by anyone) goes through to the real write, so the file on disk always holds what the game last asked for.
*/
#pragma once

#include <functional>
#include <map>
#include <mutex>
#include <string>

namespace xmlsave {

//! What the last successful write of one path printed, and the file size it left.
struct Record
{
    std::string text;
    unsigned long long diskSize = 0;
};

//! True when a save printing `text` can be skipped: see the file comment.
inline bool ShouldSkip(const Record* last, const std::string& text, bool exists, unsigned long long sizeNow)
{
    return last != nullptr && exists && last->text == text && last->diskSize == sizeNow;
}

class Deduper
{
public:
    //! Returns false when the file does not exist; otherwise its size.
    using StatFn = std::function<bool(const std::string& path, unsigned long long* size)>;
    //! The real save; returns tinyxml2's XMLError (0 = success).
    using WriteFn = std::function<int()>;

    explicit Deduper(StatFn stat) : m_stat(std::move(stat)) {}

    /*!
    * @param path    the file the game saves to
    * @param text    the document as XMLPrinter prints it
    * @param write   performs the original save
    * @param skipped set to true when the write was skipped
    * @return what the game gets back: 0 for a skip, otherwise the real save's result
    */
    int Save(const std::string& path, const std::string& text, const WriteFn& write, bool* skipped)
    {
        std::lock_guard<std::mutex> lock(m_lock);
        *skipped = false;
        unsigned long long size = 0;
        const bool exists = m_stat(path, &size);
        const auto it = m_last.find(path);
        if (ShouldSkip(it == m_last.end() ? nullptr : &it->second, text, exists, size))
        {
            ++m_skipped;
            *skipped = true;
            return 0;
        }
        const int result = write();
        ++m_written;
        if (result == 0 && m_stat(path, &size))
            m_last[path] = Record{ text, size };
        else
            m_last.erase(path);
        return result;
    }

    unsigned long long Written() const { return m_written; }
    unsigned long long Skipped() const { return m_skipped; }

private:
    StatFn m_stat;
    std::mutex m_lock;
    std::map<std::string, Record> m_last;
    unsigned long long m_written = 0;
    unsigned long long m_skipped = 0;
};

} // namespace xmlsave
