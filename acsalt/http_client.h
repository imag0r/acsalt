#pragma once

#include "iless.h"

class http_client : private boost::noncopyable
{
public:
    http_client();

    void timeouts(int resolve, int connect, int send, int receive);

    std::tuple<int, int, int, int> timeouts() const;

    void proxy(const std::wstring& proxy);

    std::wstring proxy() const;

    typedef std::map<std::wstring, std::wstring, iless<std::wstring>> header_map;

    struct response
    {
        DWORD status_code;
        header_map headers;
        std::string body;
    };

    static const DWORD status_unknown;

    response get(const std::wstring& url, const header_map& headers = header_map(), unsigned retries = 0);

    response post(const std::wstring& url, const std::string& body, const header_map& headers = header_map(), unsigned retries = 0);

private:
    std::tuple<int, int, int, int> timeouts_;
    std::wstring proxy_;

    response send(const std::wstring& url, const std::wstring& verb, const std::string& request_body, const header_map& headers);

    response send(const std::wstring& url, const std::wstring& verb, const std::string& request_body, const header_map& headers, unsigned retries);

    header_map string_to_headers(const std::wstring& str) const;
    
    std::wstring headers_to_string(const header_map& headers) const;
};
