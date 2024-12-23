#pragma once

#include "WinRTErrorExtension.h"
#include "MemoryDeallocation.h"


#include <winrt/windows.foundation.h>
#include <winrt/Windows.Storage.Streams.h>
#include <winrt/Windows.Security.Credentials.h>

class WinHello
{
public:

	static winrt::Windows::Foundation::IAsyncOperation<bool> AuthenticateAsync();

	static winrt::Windows::Foundation::IAsyncOperation<bool> CreateKeyCredentialAsync();

	//static winrt::Windows::Foundation::IAsyncAction DeleteKeyCredential();

	static winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::IInspectable> DeleteKeyCredential();

	static winrt::Windows::Foundation::IAsyncOperation<bool> OpenCredentialAsync();

	static winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer> GetWindowsHelloPublicKeyAsync();

	static winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer> SignAsync();

	static winrt::Windows::Security::Cryptography::Core::CryptographicKey CreateAESKey(winrt::Windows::Storage::Streams::IBuffer signature);

	static winrt::hstring Encrypt(
		winrt::Windows::Security::Cryptography::Core::CryptographicKey key,
		winrt::hstring plainText);

	static winrt::hstring Decrypt(
		winrt::Windows::Security::Cryptography::Core::CryptographicKey key,
		winrt::hstring encryptedText);
	

private:
	static const LPCWSTR CREDETIAL_ID;

	static const LPCWSTR DATA_TO_SIGN;

	static const uint32_t NONCE_LENGTH = 12;

	static const uint32_t TAG_LENGTH = 16;

	static void CheckKeyCredentialStatus(winrt::Windows::Security::Credentials::KeyCredentialStatus status);
};


