#include "pch.h"
#include "TMPEncryptorHelper.h"
#include "MemoryDeallocation.h"
#include <vector>
#include <memory>
#include <sstream>
#include <iostream>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")

const LPCWSTR TMPEncryptorHelper::KEY_NAME = L"AdWalletKey";

const LPCWSTR PROVIDER = MS_PLATFORM_CRYPTO_PROVIDER;

TMPEncryptorHelper::TMPEncryptorHelper()
{
}

TMPEncryptorHelper::~TMPEncryptorHelper()
{
}

std::string TMPEncryptorHelper::Encrypt(const std::string& plainText, const SecureDescrData secureDescrData) const
{
    SECURITY_STATUS status = ERROR_SUCCESS;
    std::string cipherText;
	bool isKeyAlreadyExist = false;

    // Use unique_ptr with custom deleters
	std::unique_ptr<void, TPMEncryptor::NCryptHandleDeleter> hProv(nullptr);
	std::unique_ptr<void, TPMEncryptor::NCryptHandleDeleter> hKey(nullptr);

    // Open the storage provider
    NCRYPT_PROV_HANDLE hProvRaw = NULL;
    status = NCryptOpenStorageProvider(&hProvRaw, PROVIDER, 0);
    if (status != ERROR_SUCCESS)
    {
        throw std::runtime_error("Error code: " + std::to_string(status) + " Failed to open TPM provider");
    }
	hProv.reset(reinterpret_cast<void*>(hProvRaw));

    // Create or open an RSA key
    NCRYPT_KEY_HANDLE hKeyRaw = NULL;
    status = NCryptCreatePersistedKey(hProvRaw, &hKeyRaw, NCRYPT_RSA_ALGORITHM, KEY_NAME, 0, 0);
    if (status == NTE_EXISTS)
    {
		isKeyAlreadyExist = true;
        status = NCryptOpenKey(hProvRaw, &hKeyRaw, KEY_NAME, 0, 0);
    }
    if (status != ERROR_SUCCESS)
    {
        throw std::runtime_error("Error code: " + std::to_string(status) +  " Failed to create or open key");
    }
	hKey.reset(reinterpret_cast<void*>(hKeyRaw));

    DWORD keyLength = 2048;
    if (!isKeyAlreadyExist) {
		//Set the key length to 2048 bits
		 status = NCryptSetProperty(hKeyRaw, NCRYPT_LENGTH_PROPERTY, (PBYTE)&keyLength, sizeof(keyLength), 0);
		if (status != ERROR_SUCCESS)
		{
			throw std::runtime_error("Error code: " + std::to_string(status) + " Failed to set key length");
		}

		// Set desired key properties
		DWORD dwFlags = NCRYPT_ALLOW_DECRYPT_FLAG | NCRYPT_ALLOW_SIGNING_FLAG;
		status = NCryptSetProperty(hKeyRaw, NCRYPT_LENGTH_PROPERTY, (PBYTE)&keyLength, sizeof(keyLength), 0);
		if (status != ERROR_SUCCESS)
		{
			throw std::runtime_error("Error code: " + std::to_string(status) + " Failed to set key length");
		}

		// Set the security descriptor
		//status = NCryptSetProperty(
		//	hKeyRaw, 
		//	NCRYPT_SECURITY_DESCR_PROPERTY, 
		//	(PBYTE)secureDescrData.pSD, 
		//	secureDescrData.cbSD, 
		//	OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
		//);
		//if (status != ERROR_SUCCESS)
		//{
		//	throw std::runtime_error("Error code: " + std::to_string(status) + " Failed to set security descriptor");
		//}

		// Set the UI policy to the password
		NCRYPT_UI_POLICY UIPolicy = { 0 };

		UIPolicy.dwVersion = 1;
		UIPolicy.dwFlags = NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG;
		UIPolicy.pszCreationTitle = L"Strong Key UX Sample";
		UIPolicy.pszFriendlyName = L"Sample Friendly Name";
		UIPolicy.pszDescription = L"This is a sample strong key";
		status = NCryptSetProperty(hKeyRaw, NCRYPT_UI_POLICY_PROPERTY, (PBYTE)&UIPolicy, sizeof(UIPolicy), 0);
		if (status != ERROR_SUCCESS) {
			throw std::runtime_error("Error code: " + std::to_string(status) + " Failed to set UI policy");
		}

        // Finalize the key
        status = NCryptFinalizeKey(hKeyRaw, 0);
        if (status != ERROR_SUCCESS)
        {
            throw std::runtime_error("Error code: " + std::to_string(status) + " Failed to finalize key");
        }
    }

    PBYTE pbPlainText = (PBYTE)plainText.data();
    DWORD cbPlainText = (DWORD)plainText.size();

    DWORD dwFlags = NCRYPT_PAD_PKCS1_FLAG;

    // Check if the plaintext size is within the maximum allowed size for RSA encryption
	keyLength = 0;
	DWORD keyLengthSize = sizeof(keyLength);
	status = NCryptGetProperty(hKeyRaw, NCRYPT_LENGTH_PROPERTY, (PBYTE)&keyLength, keyLengthSize, &keyLengthSize, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("Error code: " + std::to_string(status) + " Failed to get key length");
	}

    // Check if the plaintext size is within the maximum allowed size for RSA encryption
    DWORD maxDataSize = (keyLength / 8) - 11; // 11 bytes overhead for PKCS1 padding
    if (cbPlainText > maxDataSize)
    {
        throw std::runtime_error("Error code: " + std::to_string(status) + " Data too large for RSA encryption");
    }

    // Get the required size for the ciphertext buffer
    DWORD cbCipherText = 0;
    status = NCryptEncrypt(hKeyRaw, pbPlainText, cbPlainText, NULL, NULL, 0, &cbCipherText, dwFlags);
    if (status != ERROR_SUCCESS)
    {
        throw std::runtime_error("Error code: " + std::to_string(status) + " Failed to get cipher text length");
    }

    // Allocate the ciphertext buffer and perform the encryption
	std::vector<BYTE> chipherBuffer(cbCipherText);
    status = NCryptEncrypt(hKeyRaw, pbPlainText, cbPlainText, NULL, chipherBuffer.data(), cbCipherText, &cbCipherText, dwFlags);
    if (status != ERROR_SUCCESS)
    {
        throw std::runtime_error("Error code: " + std::to_string(status) +  " Failed to encrypt data");
    }

    // Assign the ciphertext to the output string
    cipherText.assign((char*)chipherBuffer.data(), cbCipherText);

    return cipherText;
}

std::string TMPEncryptorHelper::Decrypt(const std::string& chipherText) const
{
	SECURITY_STATUS status = ERROR_SUCCESS;
	std::string plainText;

	// Use unique_ptr with custom deleters
	std::unique_ptr<void, TPMEncryptor::NCryptHandleDeleter> hProv(nullptr);
	std::unique_ptr<void, TPMEncryptor::NCryptHandleDeleter> hKey(nullptr);

	// Open the storage provider
	NCRYPT_PROV_HANDLE hProvRaw = NULL;
	status = NCryptOpenStorageProvider(&hProvRaw, PROVIDER, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("Error code: " + std::to_string(status) + " Failed to open TPM provider");
	}
	hProv.reset(reinterpret_cast<void*>(hProvRaw));

	// Open an RSA key
	NCRYPT_KEY_HANDLE hKeyRaw = NULL;
	status = NCryptOpenKey(hProvRaw, &hKeyRaw, KEY_NAME, 0, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("Error code: " + std::to_string(status) + " Failed to open key");
	}
	hKey.reset(reinterpret_cast<void*>(hKeyRaw));

	PBYTE pbCipherText = (PBYTE)chipherText.data();
	DWORD cbCipherText = (DWORD)chipherText.size();

	DWORD dwFlags = NCRYPT_PAD_PKCS1_FLAG;

	// Get the required size for the plaintext buffer
	DWORD cbPlainText = 0;
	status = NCryptDecrypt(hKeyRaw, pbCipherText, cbCipherText, NULL, NULL, 0, &cbPlainText, dwFlags);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("Error code: " + std::to_string(status) + " Failed to get plain text length");
	}

	// Allocate the plaintext buffer and perform the decryption
	std::vector<BYTE> plainBuffer(cbPlainText);
	status = NCryptDecrypt(hKeyRaw, pbCipherText, cbCipherText, NULL, plainBuffer.data(), cbPlainText, &cbPlainText, dwFlags);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("Error code: " + std::to_string(status) + " Failed to decrypt data");
	}

	// Assign the plaintext to the output string
	plainText.assign((char*)plainBuffer.data(), cbPlainText);

	return plainText;
}

void TMPEncryptorHelper::DeleteKey() const
{
	SECURITY_STATUS status = ERROR_SUCCESS;

	// Use unique_ptr with custom deleters
	std::unique_ptr<void, TPMEncryptor::NCryptHandleDeleter> hProv(nullptr);
	std::unique_ptr<void, TPMEncryptor::NCryptHandleDeleter> hKey(nullptr);

	// Open the storage provider
	NCRYPT_PROV_HANDLE hProvRaw = NULL;
	status = NCryptOpenStorageProvider(&hProvRaw, PROVIDER, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("Error code: " + std::to_string(status) + " Failed to open TPM provider");
	}
	hProv.reset(reinterpret_cast<void*>(hProvRaw));

	// Open an RSA key
	NCRYPT_KEY_HANDLE hKeyRaw = NULL;
	status = NCryptOpenKey(hProvRaw, &hKeyRaw, KEY_NAME, 0, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("Error code: " + std::to_string(status) + " Failed to open key");
	}
	hKey.reset(reinterpret_cast<void*>(hKeyRaw));

	// Delete the key
	status = NCryptDeleteKey(hKeyRaw, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("Error code: " + std::to_string(status) + " Failed to delete key");
	}
}

int TMPEncryptorHelper::isWindowsTPMSupported() const
{
	SECURITY_STATUS status = ERROR_SUCCESS;

	// Open the storage provider
	NCRYPT_PROV_HANDLE hProvRaw = NULL;
	status = NCryptOpenStorageProvider(&hProvRaw, PROVIDER, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("Error code: " + std::to_string(status) + " Failed to open TPM provider");
	}
	std::unique_ptr<void, TPMEncryptor::NCryptHandleDeleter> hProv(nullptr);
	hProv.reset(reinterpret_cast<void*>(hProvRaw));

	// If we have successfully opened the Platform Crypto Provider, it means TPM is present.
   // Now, let's check the TPM version.
	DWORD cbPlatformType = 0;
	status = NCryptGetProperty(hProvRaw, NCRYPT_PCP_PLATFORM_TYPE_PROPERTY, NULL, NULL, &cbPlatformType, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("Error code: " + std::to_string(status) + " Failed to get platform type");
	}
	std::vector<BYTE> platformTypeBuffer(cbPlatformType);
	status = NCryptGetProperty(hProvRaw, NCRYPT_PCP_PLATFORM_TYPE_PROPERTY, platformTypeBuffer.data(), (DWORD)platformTypeBuffer.size(), &cbPlatformType, 0);
	if (status != ERROR_SUCCESS)
	{
		throw std::runtime_error("Error code: " + std::to_string(status) + " Failed to get platform type");
	}

	
	auto version = std::wstring((wchar_t*)platformTypeBuffer.data(), cbPlatformType);

	auto type = ParsePlatformType(version);

	return std::stoi(type);
}

void TMPEncryptorHelper::CreateECDHKey() const
{
	SECURITY_STATUS status = ERROR_SUCCESS;

	// Open the storage provider
	NCRYPT_PROV_HANDLE hProvRaw = NULL;
	status = NCryptOpenStorageProvider(&hProvRaw, PROVIDER, 0);
	CheckStatus(status, "Failed to open TPM provider");
	std::unique_ptr<void, TPMEncryptor::NCryptHandleDeleter> hProv(nullptr);
	hProv.reset(reinterpret_cast<void*>(hProvRaw));

	NCRYPT_KEY_HANDLE hKeyRaw = NULL;
	status = NCryptCreatePersistedKey(hProvRaw, &hKeyRaw, NCRYPT_ECDH_P384_ALGORITHM, KEY_NAME, 0, 0);
	if (status == NTE_EXISTS)
	{
		status = NCryptOpenKey(hProvRaw, &hKeyRaw, KEY_NAME, 0, 0);
		CheckStatus(status, "Failed to open key");

		return;
	}
	CheckStatus(status, "Failed to create key");
	std::unique_ptr<void, TPMEncryptor::NCryptHandleDeleter> hKey(nullptr);
	hKey.reset(reinterpret_cast<void*>(hKeyRaw));

	// Set the key length to 384 bits
	DWORD keyLength = 384;
	status = NCryptSetProperty(hKeyRaw, NCRYPT_LENGTH_PROPERTY, (PBYTE)&keyLength, sizeof(keyLength), 0);
	CheckStatus(status, "Failed to set key length");

	status = NCryptFinalizeKey(hKeyRaw, 0);
	CheckStatus(status, "Failed to finalize key");
}

NCRYPT_KEY_HANDLE TMPEncryptorHelper::GetECDHKey() const
{
	SECURITY_STATUS status = ERROR_SUCCESS;

	// Open the storage provider
	NCRYPT_PROV_HANDLE hProvRaw = NULL;
	status = NCryptOpenStorageProvider(&hProvRaw, PROVIDER, 0);
	CheckStatus(status, "Failed to open TPM provider");
	std::unique_ptr<void, TPMEncryptor::NCryptHandleDeleter> hProv(nullptr);
	hProv.reset(reinterpret_cast<void*>(hProvRaw));

	NCRYPT_KEY_HANDLE hKey = NULL;

	status = NCryptOpenKey(hProvRaw, &hKey, KEY_NAME, 0, 0);
	CheckStatus(status, "Failed to open key");

	return hKey;
}

BCRYPT_KEY_HANDLE TMPEncryptorHelper::CreateAESKey(const NCRYPT_KEY_HANDLE hPrivKey, const std::vector<uint8_t>& peerPublicKey) const
{
	SECURITY_STATUS status = ERROR_SUCCESS;

	// Open the storage provider
	NCRYPT_PROV_HANDLE hProvRaw = NULL;
	status = NCryptOpenStorageProvider(&hProvRaw, PROVIDER, 0);
	CheckStatus(status, "Failed to open TPM provider");
	std::unique_ptr<void, TPMEncryptor::NCryptHandleDeleter> hProv(reinterpret_cast<void*>(hProvRaw));

	// Import peer’s public key
	// peerPublicKey should be in ECC public key blob format: BCRYPT_ECCKEY_BLOB + X + Y
	NCRYPT_KEY_HANDLE hPeerPubKeyRaw = NULL;
	status = NCryptImportKey(hProvRaw, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, &hPeerPubKeyRaw, (PBYTE)peerPublicKey.data(), (DWORD)peerPublicKey.size(), 0);
	CheckStatus(status, "Failed to import peer public key.");
	std::unique_ptr<void, TPMEncryptor::NCryptHandleDeleter> hPeerPubKey(reinterpret_cast<void*>(hPeerPubKeyRaw));

	// Derive shared secret
	NCRYPT_SECRET_HANDLE hSecret = 0;
	status = NCryptSecretAgreement(hPrivKey, hPeerPubKeyRaw, &hSecret, 0);
	CheckStatus(status, "Failed to derive shared secret.");

	return BCRYPT_KEY_HANDLE();
}

std::wstring TMPEncryptorHelper::ParsePlatformType(const std::wstring& platformVersion)
{
	const std::wstring key = L"TPM-Version:";
	auto start = platformVersion.find(key);
	if (start == std::wstring::npos)
	{
		throw std::runtime_error("TPM-Version not found in input string");
	}
	start += key.size();
	auto end = platformVersion.find(L'.', start);

	return platformVersion.substr(start, end - start);
}

 NCRYPT_KEY_HANDLE TMPEncryptorHelper::GetTPMKey() const
{
	SECURITY_STATUS status = ERROR_SUCCESS;

	// Open the storage provider
	NCRYPT_PROV_HANDLE hProvRaw = NULL;
	status = NCryptOpenStorageProvider(&hProvRaw, PROVIDER, 0);
	CheckStatus(status, "Failed to open TPM provider");
	std::unique_ptr<void, TPMEncryptor::NCryptHandleDeleter> hProv(nullptr);
	hProv.reset(reinterpret_cast<void*>(hProvRaw));

	// Open an RSA key
	NCRYPT_KEY_HANDLE hKey = NULL;
	status = NCryptOpenKey(hProvRaw, &hKey, KEY_NAME, 0, 0);
	CheckStatus(status, "Failed to open key");

	return hKey;
}
