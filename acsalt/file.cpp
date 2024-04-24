#include "pch.h"
#include "file.h"
#include "win32_error.h"

namespace file
{
handle::handle(HANDLE handle)
    : handle_(handle)
{
}

handle::~handle()
{
    if (valid())
    {
        ::CloseHandle(handle_);
    }
}

bool handle::valid() const
{
    return handle_ != INVALID_HANDLE_VALUE;
}

handle::operator HANDLE() const
{
    return handle_;
}

std::string read(const std::wstring& path)
{
    handle file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (!file.valid())
    {
        throw win32_error("CreateFileW");
    }

    const auto size = ::GetFileSize(file, nullptr);

    DWORD read = 0;
    std::string data(size, 0);
    if (!::ReadFile(file, &data[0], size, &read, nullptr))
    {
        throw win32_error("ReadFile");
    }

    return data;
}

void write(const std::wstring& path, const std::string& data)
{
    handle file = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!file.valid())
    {
        throw win32_error("CreateFileW");
    }

    DWORD written = 0;
    if (!::WriteFile(file, data.data(), static_cast<DWORD>(data.size()), &written, nullptr))
    {
        throw win32_error("WriteFile");
    }
}

}

