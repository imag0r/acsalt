#include "pch.h"

#include "win32_error.h"

win32_error::win32_error(const std::string& msg, unsigned last_error)
    : std::runtime_error(get_message(last_error, msg)),
      last_error_(last_error)
{
}

unsigned win32_error::last_error() const throw()
{
    return last_error_;
}

std::string win32_error::get_message(unsigned last_error, const std::string& msg)
{
    std::string what = msg;
    if (!what.empty())
    {
        what += ". ";
    }
    what += "Error code: " + std::to_string(last_error);

    LPSTR pszBuffer = NULL;
    if (0 != ::FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, last_error, 0, reinterpret_cast<LPSTR>(&pszBuffer), 1024, NULL))
    {
        what += ": ";
        what += pszBuffer;
        ::LocalFree(pszBuffer);
    }

    while (what.back() == '\n' || what.back() == '\r')
    {
        what.pop_back();
    }

    return what;
}
