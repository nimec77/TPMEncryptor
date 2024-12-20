#include "pch.h"
#include "SecureService.h"
#include "WinRTUtil.h"

#include <windows.h>
#include <winrt/base.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <cstring>
#include <vector>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

using namespace winrt;
using namespace Windows::Foundation;


IAsyncOperation<IInspectable> SecureService::CreateAESKey() const
{
	auto&& hPublicKeyBoxed = co_await ImportECCPublicKey();
	auto hPublicKeyRaw = TPMEncryptor::IInspectableWrapper<NCRYPT_KEY_HANDLE>::unbox(hPublicKeyBoxed);
	auto hPublicKey = TPMEncryptor::NCryptDeleteKeyHandle(hPublicKeyRaw);

	auto hPrivateKeyRaw = m_encryptorHelper.GetECDHKey();
	auto hPrivateKey = TPMEncryptor::NCryptHandleFree(hPrivateKeyRaw);

	NCRYPT_PROV_HANDLE hProvRaw = NULL;
	SECURITY_STATUS status = ERROR_SUCCESS;
	status = NCryptOpenStorageProvider(&hProvRaw, MS_PLATFORM_CRYPTO_PROVIDER, 0);
	CheckStatus(status, "Failed to open TPM provider");
	auto hProv = TPMEncryptor::NCryptHandleFree(hProvRaw);

	// Derive shared secret
	NCRYPT_SECRET_HANDLE hSecretRaw = 0;
	status = NCryptSecretAgreement(hPrivateKeyRaw, hPublicKeyRaw, &hSecretRaw, 0);
	CheckStatus(status, "Failed to derive shared secret");

	co_return TPMEncryptor::IInspectableWrapper<int>::box(1);
}

IAsyncOperation<IInspectable> SecureService::ImportPublicKey() const
{
	auto&& publicKeyBuffer = co_await m_winHello.GetWindowsHelloPublicKeyAsync();
	auto peerPublicKey = WinRTUtil::IBufferToVector(publicKeyBuffer);

	CERT_PUBLIC_KEY_INFO* pPubKeyInfo = NULL;
	DWORD cbPubKeyInfo = 0;
	if (!CryptDecodeObjectEx(
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		X509_PUBLIC_KEY_INFO,
		peerPublicKey.data(),
		(DWORD)peerPublicKey.size(),
		CRYPT_ENCODE_ALLOC_FLAG,
		NULL,
		&pPubKeyInfo,
		&cbPubKeyInfo)) {
		auto error = GetLastError();
		throw std::runtime_error("Failed to decode public key: " + std::to_string(error));
	}

	if (strcmp(pPubKeyInfo->Algorithm.pszObjId, szOID_RSA_RSA)) {
		throw std::runtime_error("Public key is not an RSA key");
	}

	SECURITY_STATUS status = ERROR_SUCCESS;

	BCRYPT_KEY_HANDLE hKeyRaw = nullptr;
	if (!CryptImportPublicKeyInfoEx2(
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		pPubKeyInfo,
		0,
		nullptr,
		&hKeyRaw)) {
		auto error = GetLastError();
		throw std::runtime_error("Failed to import public key: " + std::to_string(error));
	}
	auto hKey = TPMEncryptor::BCryptDestroyKeyHandle(hKeyRaw);

	DWORD cbBlob = 0;
	status = BCryptExportKey(
		hKeyRaw,
		NULL,
		BCRYPT_RSAPUBLIC_BLOB,
		nullptr,
		0,
		&cbBlob,
		0);
	CheckStatus(status, "Failed to get public key blob size");

	std::vector<BYTE> blob(cbBlob);
	status = BCryptExportKey(
		hKeyRaw,
		NULL,
		BCRYPT_RSAPUBLIC_BLOB,
		blob.data(),
		(DWORD)blob.size(),
		&cbBlob,
		0);
	CheckStatus(status, "Failed to export public key blob");

	NCRYPT_PROV_HANDLE hProvRaw = NULL;
	status = NCryptOpenStorageProvider(&hProvRaw, MS_PLATFORM_CRYPTO_PROVIDER, 0);
	CheckStatus(status, "Failed to open TPM provider");
	auto hProv = TPMEncryptor::NCryptHandleFree(hProvRaw);

	// Import peer’s public key
	// peerPublicKey should be in ECC public key blob format: BCRYPT_ECCKEY_BLOB + X + Y
	NCRYPT_KEY_HANDLE hPeerPubKeyRaw = NULL;
	status = NCryptImportKey(
		hProvRaw,
		NULL,
		BCRYPT_RSAPUBLIC_BLOB,
		nullptr,
		&hPeerPubKeyRaw,
		blob.data(),
		(DWORD)blob.size(),
		0);
	CheckStatus(status, "Failed to import peer's public key");

	co_return TPMEncryptor::IInspectableWrapper<NCRYPT_KEY_HANDLE>::box(hPeerPubKeyRaw);
}

winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::IInspectable> SecureService::ImportECCPublicKey() const
{
	auto&& publicKeyBuffer = co_await m_winHello.GetWindowsHelloPublicKeyAsync();
	auto peerPublicKey = WinRTUtil::IBufferToVector(publicKeyBuffer);

	NCRYPT_PROV_HANDLE hProvRaw = NULL;
	SECURITY_STATUS status = ERROR_SUCCESS;
	status = NCryptOpenStorageProvider(&hProvRaw, MS_PLATFORM_CRYPTO_PROVIDER, 0);
	CheckStatus(status, "Failed to open TPM provider");
	auto hProv = TPMEncryptor::NCryptHandleFree(hProvRaw);

	// Import peer’s public key
	// peerPublicKey should be in ECC public key blob format: BCRYPT_ECCKEY_BLOB + X + Y
	NCRYPT_KEY_HANDLE hPeerPubKeyRaw = NULL;
	status = NCryptImportKey(
		hProvRaw,
		NULL,
		BCRYPT_RSAPUBLIC_BLOB,
		nullptr,
		&hPeerPubKeyRaw,
		peerPublicKey.data(),
		(DWORD)peerPublicKey.size(),
		0);
	CheckStatus(status, "Failed to import peer's public key");

	co_return TPMEncryptor::IInspectableWrapper<NCRYPT_KEY_HANDLE>::box(hPeerPubKeyRaw);
}
