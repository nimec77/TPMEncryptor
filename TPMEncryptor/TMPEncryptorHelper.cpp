#include "pch.h"
#include "TMPEncryptorHelper.h"
#include <bcrypt.h>
#include <ncrypt.h>
#include <stdexcept>
#include <windows.h>
#include <vector>
#include <wincrypt.h>
#include <memory>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")

const LPCWSTR TMPEncryptorHelper::KEY_NAME = L"AdWalletKey";

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

std::string TMPEncryptorHelper::Encrypt(const std::string& plainText)
{
    SECURITY_STATUS status = ERROR_SUCCESS;
    std::string cipherText;
	bool isKeyAlreadyExist = false;

    // Use unique_ptr with custom deleters
	std::unique_ptr<void, NCryptHandleDeleter> hProv(nullptr);
	std::unique_ptr<void, NCryptHandleDeleter> hKey(nullptr);

    // Open the storage provider
    NCRYPT_PROV_HANDLE hProvRaw = NULL;
    status = NCryptOpenStorageProvider(&hProvRaw, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
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
        // Set the key length to 2048 bits
        status = NCryptSetProperty(hKeyRaw, NCRYPT_LENGTH_PROPERTY, (PBYTE)&keyLength, sizeof(keyLength), 0);
        if (status != ERROR_SUCCESS)
        {
            throw std::runtime_error("Error code: " + std::to_string(status) + " Failed to set key length");
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
	DWORD keyLenghtSize = sizeof(keyLength);
	status = NCryptGetProperty(hKeyRaw, NCRYPT_LENGTH_PROPERTY, (PBYTE)&keyLength, keyLenghtSize, &keyLenghtSize, 0);
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

std::string TMPEncryptorHelper::Decrypt(const std::string& chipherText)
{
	SECURITY_STATUS status = ERROR_SUCCESS;
	std::string plainText;

	// Use unique_ptr with custom deleters
	std::unique_ptr<void, NCryptHandleDeleter> hProv(nullptr);
	std::unique_ptr<void, NCryptHandleDeleter> hKey(nullptr);

	// Open the storage provider
	NCRYPT_PROV_HANDLE hProvRaw = NULL;
	status = NCryptOpenStorageProvider(&hProvRaw, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
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
