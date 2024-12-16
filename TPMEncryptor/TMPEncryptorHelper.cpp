#include "pch.h"
#include "TMPEncryptorHelper.h"
#include <bcrypt.h>
#include <ncrypt.h>
#include <stdexcept>
#include <vector>
#include <memory>
#include <wincrypt.h>
#include <sstream>
#include <iostream>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")

const LPCWSTR TMPEncryptorHelper::KEY_NAME = L"AdWalletKey";

const LPCWSTR PROVIDER = MS_PLATFORM_CRYPTO_PROVIDER;

// Custom deleter for NCRYPT_KEY_HANDLE
struct NCryptHandleDeleter
{
	void operator()(void* handle) const
	{
		if (handle != NULL)
		{
			NCryptFreeObject(reinterpret_cast<NCRYPT_HANDLE>(handle));
		}
	}
};


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
	std::unique_ptr<void, NCryptHandleDeleter> hProv(nullptr);
	std::unique_ptr<void, NCryptHandleDeleter> hKey(nullptr);

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
	std::unique_ptr<void, NCryptHandleDeleter> hProv(nullptr);
	std::unique_ptr<void, NCryptHandleDeleter> hKey(nullptr);

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
	std::unique_ptr<void, NCryptHandleDeleter> hProv(nullptr);
	std::unique_ptr<void, NCryptHandleDeleter> hKey(nullptr);

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
	std::unique_ptr<void, NCryptHandleDeleter> hProv(nullptr);
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

std::string TMPEncryptorHelper::Base64Encode(const std::string& data)
{
	std::string encodedData;

	DWORD base64Size = 0;
	if (!CryptBinaryToStringA((const BYTE*)data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64Size))
	{
		throw std::runtime_error("Failed to get base64 size");
	}

	std::vector<char> base64String(base64Size);

	if (!CryptBinaryToStringA((const BYTE*)data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64String.data(), &base64Size))
	{
		throw std::runtime_error("Failed to encode data to base64");
	}

	encodedData.assign(base64String.data(), base64Size);

	return encodedData;
}

std::string TMPEncryptorHelper::Base64Decode(const std::string& input)
{
	std::string decodedData;

	DWORD binarySize = 0;
	if (!CryptStringToBinaryA(input.data(), (DWORD)input.size(), CRYPT_STRING_BASE64, NULL, &binarySize, NULL, NULL))
	{
		throw std::runtime_error("Failed to get binary size");
	}

	std::vector<BYTE> binaryData(binarySize);

	if (!CryptStringToBinaryA(input.data(), (DWORD)input.size(), CRYPT_STRING_BASE64, binaryData.data(), &binarySize, NULL, NULL))
	{
		throw std::runtime_error("Failed to decode base64 data");
	}

	decodedData.assign((char*)binaryData.data(), binarySize);

	return decodedData;
}
