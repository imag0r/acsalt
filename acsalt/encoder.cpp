#include "pch.h"
#include "encoder.h"
#include "win32_error.h"

namespace {

    const int entropy_bytes = 128;

    template <typename CharT>
    std::basic_string<CharT> url_encode_internal(const std::basic_string<CharT>& str)
    {
        std::basic_ostringstream<CharT> escaped;
        escaped.fill('0');
        escaped << std::hex;

        for (const auto c : str)
        {
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            {
                escaped << c;
                continue;
            }

            escaped << std::uppercase;
            escaped << '%' << std::setw(2) << int((unsigned char)c);
            escaped << std::nouppercase;
        }

        return escaped.str();
    }

    std::string generate_entropy(unsigned num_bytes)
    {
        HCRYPTPROV provider = 0;

        if (!::CryptAcquireContextW(&provider, 0, 0, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
        {
            throw win32_error("CryptAcquireContextW");
        }

        std::string entropy(num_bytes, 0);

        DWORD error = ERROR_SUCCESS;
        if (!::CryptGenRandom(provider, num_bytes, reinterpret_cast<BYTE*>(&entropy[0])))
        {
            error = ::GetLastError();
        }

        ::CryptReleaseContext(provider, 0);

        if (error != ERROR_SUCCESS)
        {
            throw win32_error("CryptGenRandom");
        }

        return entropy;
    }
}

namespace encoder {

std::string base64_encode(LPCBYTE buffer, DWORD size)
{
    const DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
    DWORD outsize = 0;
    (void)::CryptBinaryToStringA(buffer, size, flags, NULL, &outsize);
    std::string out(outsize, 0);
    if (!::CryptBinaryToStringA(buffer, size, flags, &out[0], &outsize))
    {
        throw win32_error("CryptBinaryToStringA");
    }
    out.pop_back(); // remove null terminator

    return out;
}

std::string base64_encode(const std::string& input)
{
    return base64_encode(reinterpret_cast<LPCBYTE>(input.data()), static_cast<DWORD>(input.size()));
}

std::string base64_decode(const std::string& input)
{
    const DWORD flags = CRYPT_STRING_BASE64;
    DWORD outsize = 0;
    (void)::CryptStringToBinaryA(input.c_str(), 0, flags, NULL, &outsize, NULL, NULL);
    std::string out(outsize, 0);
    if (!::CryptStringToBinaryA(input.c_str(), 0, flags, reinterpret_cast<BYTE*>(&out[0]), &outsize, NULL, NULL))
    {
        throw win32_error("CryptStringToBinaryA");
    }

    return out;
}

std::wstring url_encode(const std::wstring& str)
{
    return url_encode_internal(str);
}

std::string url_encode(const std::string& str)
{
    return url_encode_internal(str);
}

std::wstring to_wstring(const std::string& s, int codepage)
{
    int size = ::MultiByteToWideChar(codepage, 0, s.c_str(), -1, NULL, 0);
    if (0 == size)
    {
        throw win32_error("MultiByteToWideChar");
    }

    std::wstring wide(size, 0);
    if (0 == ::MultiByteToWideChar(codepage, 0, s.c_str(), -1, &wide[0], static_cast<int>(wide.size())))
    {
        throw win32_error("MultiByteToWideChar");
    }

    if (wide.size() > 0)
    {
        wide.resize(wide.size() - 1);
    }
    return wide;
}

std::string to_string(const std::wstring& s, int codepage)
{
    int size = ::WideCharToMultiByte(codepage, 0, s.c_str(), -1, NULL, 0, NULL, NULL);
    if (0 == size)
    {
        throw win32_error("WideCharToMultiByte");
    }

    std::string ansi(size, 0);
    if (0 == ::WideCharToMultiByte(codepage, 0, s.c_str(), -1, &ansi[0], static_cast<int>(ansi.size()), NULL, NULL))
    {
        throw win32_error("WideCharToMultiByte");
    }
    if (ansi.size() > 0)
    {
        ansi.resize(ansi.size() - 1);
    }
    return ansi;
}

std::string decrypt_dpapi(const std::string& encrypted, bool machine_context)
{
    DATA_BLOB entropy_blob = { 0 };
    entropy_blob.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(encrypted.data()));
    entropy_blob.cbData = entropy_bytes;  // first 128 bytes of the file is entropy

    DATA_BLOB in_blob = { 0 };
    in_blob.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(encrypted.data() + entropy_bytes));
    in_blob.cbData = static_cast<DWORD>(encrypted.size()) - entropy_bytes;

    DATA_BLOB out_blob = { 0 };
    DWORD flags = machine_context ? CRYPTPROTECT_LOCAL_MACHINE : 0;
    if (!::CryptUnprotectData(&in_blob, nullptr, &entropy_blob, nullptr, nullptr, flags, &out_blob))
    {
        throw win32_error("CryptUnprotectData");
    }

    std::string data(reinterpret_cast<char*>(out_blob.pbData), reinterpret_cast<char*>(out_blob.pbData + out_blob.cbData));
    ::LocalFree(out_blob.pbData);
    return data;
}

std::string encrypt_dpapi(const std::string& plain, bool machine_context)
{
    DATA_BLOB in_blob = { 0 };
    in_blob.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(plain.data()));
    in_blob.cbData = static_cast<DWORD>(plain.size());

    auto entropy = generate_entropy(entropy_bytes);

    DATA_BLOB entropy_blob = { 0 };
    entropy_blob.pbData = reinterpret_cast<BYTE*>(&entropy[0]);
    entropy_blob.cbData = static_cast<DWORD>(entropy.size());

    DATA_BLOB out_blob = { 0 };
    DWORD flags = machine_context ? CRYPTPROTECT_LOCAL_MACHINE : 0;
    if (!::CryptProtectData(&in_blob, nullptr, &entropy_blob, nullptr, nullptr, flags, &out_blob))
    {
        throw win32_error("CryptProtectData");
    }

    auto data = entropy;
    data.insert(data.end(), reinterpret_cast<char*>(out_blob.pbData), reinterpret_cast<char*>(out_blob.pbData + out_blob.cbData));
    ::LocalFree(out_blob.pbData);
    return data;
}

}