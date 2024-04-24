#pragma once

namespace file
{
    struct handle
    {
        handle(HANDLE handle);

        ~handle();

        bool valid() const;

        operator HANDLE() const;

    private:
        HANDLE handle_;
    };

    std::string read(const std::wstring& path);

    void write(const std::wstring& path, const std::string& data);

}

