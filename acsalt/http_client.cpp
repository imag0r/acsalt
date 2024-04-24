#include "pch.h"
#include "exception_strm.h"
#include "http_client.h"
#include "scoped_cleanup.h"
#include "win32_error.h"

#include <deque>
#include <winhttp.h>
#pragma comment(lib, "winhttp")

const DWORD http_client::status_unknown = static_cast<DWORD>(-1);

http_client::http_client() :
    timeouts_(30, 30, 30, 30)
{
}

void http_client::timeouts(int resolve, int connect, int send, int receive)
{
    timeouts_ = std::make_tuple(resolve, connect, send, receive);
}

std::tuple<int, int, int, int> http_client::timeouts() const
{
    return timeouts_;
}

void http_client::proxy(const std::wstring& proxy)
{
    proxy_ = proxy;
}

std::wstring http_client::proxy() const
{
    return proxy_;
}

http_client::response http_client::get(const std::wstring& url, const header_map& headers, unsigned retries)
{
    return send(url, L"GET", "", headers, retries);
}

http_client::response http_client::post(const std::wstring& url, const std::string& body, const header_map& headers, unsigned retries)
{
    return send(url, L"POST", body, headers, retries);
}

http_client::response http_client::send(const std::wstring& url, const std::wstring& verb, const std::string& request_body, const header_map& headers)
{
    response resp;
    resp.status_code = status_unknown;

    auto session = ::WinHttpOpen(L"azhttp", 
                                 proxy_.empty() ? WINHTTP_ACCESS_TYPE_NO_PROXY : WINHTTP_ACCESS_TYPE_NAMED_PROXY,
                                 proxy_.empty() ? WINHTTP_NO_PROXY_NAME : proxy_.c_str(), 
                                 WINHTTP_NO_PROXY_BYPASS, 
                                 0);
    if (!session)
    {
        throw win32_error("WinHttpOpen");
    }

    DWORD options = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    if (!::WinHttpSetOption(session, WINHTTP_OPTION_SECURE_PROTOCOLS, &options, sizeof(options)))
    {
        throw win32_error("WinHttpSetOption");
    }

    const auto session_grd = scoped_cleanup([&session]() { ::WinHttpCloseHandle(session); });

    URL_COMPONENTS components = { 0 };
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = 1;
    components.dwHostNameLength = 1;
    components.dwUrlPathLength = 1;
    if (!::WinHttpCrackUrl(url.c_str(), 0, 0, &components))
    {
        throw win32_error("WinHttpCrackUrl");
    }

    const std::wstring host(components.lpszHostName, components.lpszHostName + components.dwHostNameLength);

    if (!::WinHttpSetTimeouts(session, std::get<0>(timeouts_) * 1000,
                                       std::get<1>(timeouts_) * 1000,
                                       std::get<2>(timeouts_) * 1000,
                                       std::get<3>(timeouts_) * 1000))
    {
        throw win32_error("WinHttpSetTimeouts");
    }

    auto connection = ::WinHttpConnect(session, host.c_str(), components.nPort, 0);
    if (!connection)
    {
        throw win32_error("WinHttpConnect");
    }

    const auto connection_grd = scoped_cleanup([&connection]() { ::WinHttpCloseHandle(connection); });

    const DWORD flags = (components.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;

    auto request = ::WinHttpOpenRequest(connection, verb.c_str(), components.lpszUrlPath, nullptr, nullptr, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request)
    {
        throw win32_error("WinHttpOpenRequest");
    }

    options = WINHTTP_DISABLE_KEEP_ALIVE;
    if (!::WinHttpSetOption(request, WINHTTP_OPTION_DISABLE_FEATURE, &options, sizeof(options)))
    {
        throw win32_error("WinHttpSetOption");
    }

    const auto request_grd = scoped_cleanup([&request]() { ::WinHttpCloseHandle(request); });

    const auto request_headers_str = headers_to_string(headers);
    if (!::WinHttpSendRequest(request, 
                              request_headers_str.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : request_headers_str.c_str(),
                              static_cast<DWORD>(request_headers_str.size()),
                              request_body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char *>(request_body.data()),
                              static_cast<DWORD>(request_body.size()),
                              static_cast<DWORD>(request_body.size()),
                              0))
    {
        const auto error = ::GetLastError();
        if (error == ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED)
        {
            if (!::WinHttpSetOption(request, WINHTTP_OPTION_CLIENT_CERT_CONTEXT, WINHTTP_NO_CLIENT_CERT_CONTEXT, 0))
            {
                return resp;
            }

            if (!::WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
            {
                throw win32_error("WinHttpSendRequest");
            }
        }
        else
        {
            throw win32_error("WinHttpSendRequest");
        }
    }

    if (!::WinHttpReceiveResponse(request, NULL))
    {
        throw win32_error("WinHttpReceiveResponse");
    }

    DWORD status_code = 0;
    DWORD header_size = sizeof(status_code);

    if (!::WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &header_size, WINHTTP_NO_HEADER_INDEX))
    {
        throw win32_error("WinHttpQueryHeaders");
    }

    header_map response_headers;

    // Allocate memory for the buffer.
    if (!::WinHttpQueryHeaders(request, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &header_size, WINHTTP_NO_HEADER_INDEX) &&
        ::GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        std::wstring headers_str(header_size / sizeof(wchar_t), 0);

        if (!::WinHttpQueryHeaders(request, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, &headers_str[0], &header_size, WINHTTP_NO_HEADER_INDEX))
        {
            throw win32_error("WinHttpQueryHeaders");
        }

        response_headers = string_to_headers(headers_str);
    }

    std::string response_body;
    for (;;)
    {
        DWORD available = 0;
        if (!::WinHttpQueryDataAvailable(request, &available))
        {
            throw win32_error("WinHttpQueryDataAvailable");
        }

        if (!available)
        {
            break;
        }

        std::string chunk(available, 0);

        DWORD downloaded = 0;
        if (!::WinHttpReadData(request, &chunk[0], available, &downloaded))
        {
            // Sometimes WinHttpReadData returns FALSE when no data is available
            // In such case last error is ERROR_SUCCESS. This is not an error condition.
            const auto error = ::GetLastError();
            if (error != ERROR_SUCCESS)
            {
                throw win32_error("WinHttpReadData");
            }
        }

        chunk.resize(downloaded);

        response_body += chunk;
    }

    using std::swap;
    swap(resp.status_code, status_code);
    swap(resp.headers, response_headers);
    swap(resp.body, response_body);

    return resp;
}

http_client::response http_client::send(const std::wstring& url, const std::wstring& verb, const std::string& request_body, const header_map& headers, unsigned retries)
{
    for (;;)
    {
        try
        {
            return send(url, verb, request_body, headers);
        }
        catch (const std::exception& exc)
        {
            if (retries-- > 0)
            {
                std::wclog << L"Exception " << exc << L". Retries left: " << retries << std::endl;
                continue;
            }
            throw;
        }
    }
}

http_client::header_map http_client::string_to_headers(const std::wstring& str) const
{
    std::deque<std::wstring> header_kvps;
    boost::iter_split(header_kvps, str, boost::first_finder(L"\r\n"));

    if (!header_kvps.empty())
    {
        // 1st line is http status, skip it.
        header_kvps.pop_front();
    }

    header_map headers;
    for (const auto& header_kvp : header_kvps)
    {
        auto delim_pos = header_kvp.find(L':');
        if (delim_pos == header_kvp.npos)
        {
            continue;
        }

        const auto key = header_kvp.substr(0, delim_pos++);
        while ((delim_pos < header_kvp.size()) && boost::is_any_of(L" \t")(header_kvp[delim_pos]))
        {
            ++delim_pos;
        }
        const auto value = header_kvp.substr(delim_pos);
        headers.insert(std::make_pair(key, value));
    }
    return headers;
}

std::wstring http_client::headers_to_string(const header_map& headers) const
{
    std::vector<std::wstring> header_kvps;

    std::transform(std::begin(headers), std::end(headers),
        std::back_inserter(header_kvps),
        [](const std::pair<std::wstring, std::wstring>& kvp)
        {
            return kvp.first + L": " + kvp.second;
        });

    return boost::join(header_kvps, L"\r\n");
}
