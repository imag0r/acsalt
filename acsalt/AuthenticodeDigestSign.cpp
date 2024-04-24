#include "pch.h"

#include "acs.h"
#include "encoder.h"
#include "exception_strm.h"

HRESULT AuthenticodeDigestSignEx(PDATA_BLOB pMetadataBlob, ALG_ID digestAlgId, BYTE* pbToBeSignedDigest, DWORD cbToBeSignedDigest, PCRYPT_DIGEST_BLOB pSignedDigest, PCCERT_CONTEXT* ppSignerCert, void* hCertChainStore)
{
    try
    {
        const auto meta = boost::json::parse(boost::json::string_view(reinterpret_cast<char*>(pMetadataBlob->pbData), pMetadataBlob->cbData));

        const auto tenant = encoder::to_wstring(boost::json::value_to<std::string>(meta.at("tenant")));
        const auto client_id = encoder::to_wstring(boost::json::value_to<std::string>(meta.at("client_id")));
        const auto secret = encoder::to_wstring(boost::json::value_to<std::string>(meta.at("secret")));
        const auto endpoint = boost::json::value_to<std::string>(meta.at("endpoint"));
        const auto account = boost::json::value_to<std::string>(meta.at("account"));
        const auto profile = boost::json::value_to<std::string>(meta.at("profile"));
        const auto correlation_id = boost::json::value_to<std::string>(meta.at("correlation_id"));

        const auto digest = encoder::base64_encode(pbToBeSignedDigest, cbToBeSignedDigest);

        acs acs(tenant, client_id, secret);

        auto result = acs.sign_digest(digestAlgId, digest, endpoint, account, profile, correlation_id);

        pSignedDigest->cbData = static_cast<DWORD>(result.signature.size());
        pSignedDigest->pbData = reinterpret_cast<BYTE*>(::HeapAlloc(::GetProcessHeap(), 0, pSignedDigest->cbData));
        if (!pSignedDigest->pbData)
        {
            return E_POINTER;
        }

        std::memcpy(pSignedDigest->pbData, result.signature.data(), result.signature.size());

        CERT_BLOB blob;
        blob.cbData = static_cast<DWORD>(result.certificate.size());
        blob.pbData = reinterpret_cast<BYTE*>(&result.certificate[0]);

        HCERTSTORE store = nullptr;
        if (!::CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob, CERT_QUERY_CONTENT_FLAG_ALL, CERT_QUERY_FORMAT_FLAG_ALL, 0, nullptr, nullptr, nullptr, &store, nullptr, nullptr))
        {
            const DWORD error = ::GetLastError();
            return HRESULT_FROM_WIN32(error);
        }

        PCCERT_CONTEXT context = nullptr;
        while (nullptr != (context = ::CertEnumCertificatesInStore(store, context)))
        {
            PCCERT_CONTEXT* target_context = nullptr;

            DWORD size = 0;
            if (::CertGetEnhancedKeyUsage(context, 0, nullptr, &size))
            {
                std::vector<BYTE> buffer(size, 0);
                auto eku = reinterpret_cast<PCERT_ENHKEY_USAGE>(buffer.data());
                if (::CertGetEnhancedKeyUsage(context, 0, eku, &size))
                {
                    for (DWORD i = 0; i < eku->cUsageIdentifier; ++i)
                    {
                        if (boost::equals(eku->rgpszUsageIdentifier[i], "1.3.6.1.5.5.7.3.3"))
                        {
                            target_context = ppSignerCert;
                            break;
                        }
                    }
                }
            }

            ::CertAddCertificateContextToStore(hCertChainStore, context, CERT_STORE_ADD_NEW, target_context);
        }

        ::CertCloseStore(store, 0);

        return S_OK;
    }
    catch (const std::exception& exc)
    {
        std::wclog << L"Exception: " << exc << std::endl;
        return E_FAIL;
    }
}
