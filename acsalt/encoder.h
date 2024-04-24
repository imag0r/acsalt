#pragma once

namespace encoder
{
    std::string base64_encode(LPCBYTE buffer, DWORD size);

    std::string base64_encode(const std::string& input);

    std::string base64_decode(const std::string& input);

    std::wstring url_encode(const std::wstring& str);

    std::string url_encode(const std::string& str);

    std::wstring to_wstring(const std::string& s, int codepage = CP_ACP);

    std::string to_string(const std::wstring& s, int codepage = CP_ACP);

    std::string decrypt_dpapi(const std::string& encrypted, bool machine_context = false);

    std::string encrypt_dpapi(const std::string& plain, bool machine_context = false);
}

