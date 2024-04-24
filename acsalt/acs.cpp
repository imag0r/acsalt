#include "pch.h"

#include "acs.h"

#include "encoder.h"
#include "exception_strm.h"
#include "file.h"
#include "http_client.h"

namespace
{
    static boost::interprocess::managed_windows_shared_memory managed_shm{ boost::interprocess::open_or_create, "shm", 1024 };
    static boost::interprocess::interprocess_recursive_mutex* ip_mutex = managed_shm.find_or_construct<boost::interprocess::interprocess_recursive_mutex>("mtx")();
    const std::wstring API_VERSION = L"2022-06-15-preview";
}

acs::acs(const std::wstring& tenant, const std::wstring& client_id, const std::wstring& client_secret) :
    client_(),
    tenant_(tenant),
    client_id_(client_id),
    client_secret_(client_secret),
    token_(),
    token_file_(4096, 0)
{
    auto size = ::ExpandEnvironmentStringsW(L"%USERPROFILE%\\.acsalt", &token_file_[0], static_cast<DWORD>(token_file_.size()));
    token_file_.resize(size);

    token_ = load_token();
}

void acs::login()
{
    boost::lock_guard<boost::interprocess::interprocess_recursive_mutex> grd(*ip_mutex);

    std::wclog << L"Logging in tenant: " << tenant_ << L" client id: " << client_id_ << std::endl;

    http_client::header_map headers;
    headers[L"Content-Type"] = L"application/x-www-form-urlencoded";

    static const auto scope = encoder::url_encode(L"api://cf2ab426-f71a-4b61-bb8a-9e505b85bc2e//.default");

    std::wostringstream body;
    body << L"client_id=" << encoder::url_encode(client_id_)
        << L"&grant_type=client_credentials"
        << L"&client_info=1"
        << L"&client_secret=" << encoder::url_encode(client_secret_)
        << L"&scope=" << scope;

    const std::wstring url = L"https://login.microsoftonline.com/" + tenant_ + L"/oauth2/v2.0/token";

    auto resp = client_.post(url, encoder::to_string(body.str()), headers, 2);
    if (resp.status_code != 200)
    {
        std::ostringstream os;
        os << "Login failed, http status: " << resp.status_code << ", msg: " << resp.body;
        throw std::system_error(ERROR_ACCESS_DENIED, std::system_category(), os.str());
    }

    std::wclog << L"Login succeeded." << std::endl;

    const auto jv = boost::json::parse(resp.body);
    const auto token_type = boost::json::value_to<std::string>(jv.at("token_type"));
    const auto token = boost::json::value_to<std::string>(jv.at("access_token"));

    token_ = encoder::to_wstring(token_type + " " + token);

    store_token();
}

void acs::store_token() const
{
    boost::lock_guard<boost::interprocess::interprocess_recursive_mutex> grd(*ip_mutex);

    std::wclog << L"Storing token..." << std::endl;

    boost::json::object jo;
    jo["tenant"] = encoder::to_string(tenant_);
    jo["id"] = encoder::to_string(client_id_);
    jo["secret"] = encoder::to_string(client_secret_);
    jo["token"] = encoder::to_string(token_);

    file::write(token_file_, encoder::encrypt_dpapi(boost::json::serialize(jo)));
    std::wclog << L"Token stored." << std::endl;
}

std::wstring acs::load_token() const
{
    boost::lock_guard<boost::interprocess::interprocess_recursive_mutex> grd(*ip_mutex);

    std::wclog << L"Loading token..." << std::endl;

    std::wstring token;
    if (::GetFileAttributesW(token_file_.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        std::wclog << L"Token file doesn't exist, not logged in yet." << std::endl;
        return token;
    }

    try
    {
        const auto jv = boost::json::parse(encoder::decrypt_dpapi(file::read(token_file_)));
        const auto stored_tenant = encoder::to_wstring(boost::json::value_to<std::string>(jv.at("tenant")));
        const auto stored_client_id = encoder::to_wstring(boost::json::value_to<std::string>(jv.at("id")));
        const auto stored_client_secret = encoder::to_wstring(boost::json::value_to<std::string>(jv.at("secret")));
        if (stored_tenant == tenant_ && stored_client_id == client_id_ && stored_client_secret == client_secret_)
        {
            std::wclog << L"Found a cached token for current credentials." << std::endl;
            token = encoder::to_wstring(boost::json::value_to<std::string>(jv.at("token")));
        }
        else
        {
            std::wclog << L"Found a cached token, but the credentials don't match." << std::endl;
        }
    }
    catch (const std::exception& exc)
    {
        std::wclog << L"Failed to load token file: " << exc << std::endl;
    }

    return token;
}

acs::signing_result acs::sign_digest(unsigned alg_id, const std::string& digest, const std::string& endpoint, const std::string& account, const std::string& profile, const std::string& correlation_id)
{
    std::wclog << L"Signing digest..." << std::endl;

    std::string signature_alg;
    switch (alg_id)
    {
    case CALG_SHA_256:
        signature_alg = "RS256";
        break;
    case CALG_SHA_384:
        signature_alg = "RS384";
        break;
    case CALG_SHA_512:
        signature_alg = "RS512";
        break;
    default:
        throw std::invalid_argument("invalid alg_id");
    }

    if (token_.empty())
    {
        std::wclog << L"Authentication token is missing, requesting one now..." << std::endl;
        login();
    }

    boost::json::object jo;
    jo["signatureAlgorithm"] = signature_alg;
    jo["digest"] = digest;
    jo["correlationId"] = correlation_id;
    const auto body = boost::json::serialize(jo);

    std::wostringstream wos;
    wos << encoder::to_wstring(boost::trim_right_copy_if(endpoint, boost::is_any_of(L"/")))
        << L"/codesigningaccounts/" << encoder::to_wstring(encoder::url_encode(account))
        << L"/certificateprofiles/" << encoder::to_wstring(encoder::url_encode(profile))
        << L"/sign"
        << L"?api-version=" << API_VERSION;
    const auto uri = wos.str();

    http_client::header_map headers;
    headers[L"Accept"] = L"application/json";
    headers[L"Content-Type"] = L"application/json";
    headers[L"Authorization"] = token_;

    auto resp = client_.post(uri, body, headers, 2);
    if (resp.status_code != 202)
    {
        std::wclog << L"Got unexpected http status code: " << resp.status_code << L". refreshing token..." << std::endl;
        login();

        headers[L"Authorization"] = token_;

        resp = client_.post(uri, body, headers, 2);
        if (resp.status_code != 202)
        {
            std::ostringstream os;
            os << "Got another unexpected http status code: " << resp.status_code << ", msg: " << resp.body;
            throw std::system_error(HTTP_E_STATUS_UNEXPECTED_SERVER_ERROR, std::system_category(), os.str());
        }
    }

    auto respjson = boost::json::parse(resp.body);
    const auto status = boost::json::value_to<std::string>(respjson.at("status"));
    if (status != "InProgress")
    {
        std::ostringstream os;
        os << "Unexpected unexpected status in response: " << status;
        throw std::system_error(ERROR_INVALID_STATE, std::system_category(), os.str());
    }

    const auto opid = boost::json::value_to<std::string>(respjson.at("operationId"));
    std::wclog << L"Signing request submitted. Operation id: " << encoder::to_wstring(opid) << std::endl;
    return wait_for_signing_completion(endpoint, account, profile, opid);
}

acs::signing_result acs::wait_for_signing_completion(const std::string& endpoint, const std::string& account, const std::string& profile, const std::string& opid)
{
    std::wclog << L"Waiting for signing to complete..." << std::endl;

    std::wostringstream wos;
    wos << encoder::to_wstring(boost::trim_right_copy_if(endpoint, boost::is_any_of(L"/")))
       << L"/codesigningaccounts/" << encoder::to_wstring(encoder::url_encode(account))
       << L"/certificateprofiles/" << encoder::to_wstring(encoder::url_encode(profile))
       << L"/sign/" << encoder::to_wstring(opid)
       << L"?api-version=" << API_VERSION;

    const auto uri = wos.str();

    http_client::header_map headers;
    headers[L"Authorization"] = token_;

    for (int retry = 0; retry < 100; ++retry)
    {
        ::Sleep(1000);

        auto resp = client_.get(uri, headers, 2);
        if (resp.status_code == 200)
        {
            auto respjson = boost::json::parse(resp.body);
            const auto status = boost::json::value_to<std::string>(respjson.at("status"));
            if (status == "InProgress")
            {
                std::wclog << L"Signing in progress, waiting..." << std::endl;
                continue;
            }
            
            if (status == "Succeeded")
            {
                std::wclog << L"Signing succeded." << std::endl;

                signing_result result;
                result.signature = encoder::base64_decode(boost::json::value_to<std::string>(respjson.at("signature")));
                result.certificate = encoder::base64_decode(boost::json::value_to<std::string>(respjson.at("signingCertificate")));
                return result;
            }

            throw std::system_error(ERROR_INVALID_STATE, std::system_category(), "Unexpected signing status: " + status);
        }
        else
        {
            std::ostringstream os;
            os << "Got another unexpected http status code: " << resp.status_code << ", msg: " << resp.body;
            throw std::system_error(HTTP_E_STATUS_UNEXPECTED_SERVER_ERROR, std::system_category(), os.str());
        }
    }

    throw std::system_error(ERROR_TIMEOUT, std::system_category(), "Retry counter exhausted, giving up.");
}
