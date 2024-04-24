#pragma once

#include "http_client.h"

class acs : boost::noncopyable
{
public:
    acs(const std::wstring& tenant, const std::wstring& client_id, const std::wstring& client_secret);

    void login();

    struct signing_result
    {
        std::string signature;
        std::string certificate;
    };

    signing_result sign_digest(unsigned alg_id, const std::string& digest, const std::string& endpoint, const std::string& account, const std::string& profile, const std::string& correlation_id);

private:
    void store_token() const;

    std::wstring load_token() const;

    signing_result wait_for_signing_completion(const std::string& endpoint, const std::string& account, const std::string& profile, const std::string& opid);

    http_client client_;
    std::wstring tenant_;
    std::wstring client_id_;
    std::wstring client_secret_;
    std::wstring token_;
    std::wstring token_file_;
};