#include "pch.h"
#include "WinHello.h"
#include "StringConverter.h"

#include <winrt/Windows.Security.Credentials.UI.h>
#include <winrt/windows.security.cryptography.core.h>
#include <winrt/Windows.Security.Cryptography.h>
#include <stdexcept>

using namespace winrt;
using namespace winrt::impl;
using namespace Windows::Foundation;
using namespace Windows::Storage::Streams;
using namespace Windows::Security::Credentials;
using namespace Windows::Security::Credentials::UI;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;

const LPCWSTR WinHello::CREDETIAL_ID = L"AdWalletCredential";

const LPCWSTR WinHello::DATA_TO_SIGN = L"This example data block fo sign";

IAsyncOperation<bool> WinHello::AuthenticateAsync()
{
	auto available = co_await UserConsentVerifier::CheckAvailabilityAsync();

	switch (available)
	{
	case UserConsentVerifierAvailability::Available:
	{
		OutputDebugString(L"Windows Hello is available. Attempting to authenticate...\n");
		break;
	}

	case UserConsentVerifierAvailability::DeviceNotPresent:
	{
		OutputDebugString(L"No Windows Hello device found. Cannot authenticate with Windows Hello.\n");
		co_return false;
	}

	case UserConsentVerifierAvailability::NotConfiguredForUser:
		OutputDebugString(L"Windows Hello is not configured for this user.\n");
		co_return false;

	case UserConsentVerifierAvailability::DisabledByPolicy:
		OutputDebugString(L"Windows Hello is disabled by policy\n.");
		co_return false;

	case UserConsentVerifierAvailability::DeviceBusy:
		OutputDebugString(L"Windows Hello device is currently busy.\n");
		co_return false;

	default:
	{
		OutputDebugString(L"Unknown availability status.\n");
		co_return false;
	}
	}

	// If we reach here, Windows Hello is available.
	hstring promptMessage = L"Please verify your identity with Windows Hello.";
	// Use the interop interface to request the logged on user's consent via device authentication
	auto verificationResult = co_await UserConsentVerifier::RequestVerificationAsync(promptMessage);

	co_return verificationResult == UserConsentVerificationResult::Verified;	
}

IAsyncOperation<bool> WinHello::CreateKeyCredentialAsync()
{
	auto&& keyCreationResult = co_await KeyCredentialManager::RequestCreateAsync(CREDETIAL_ID, KeyCredentialCreationOption::ReplaceExisting);

	co_return keyCreationResult.Status() == KeyCredentialStatus::Success;
}

IAsyncOperation<IInspectable> WinHello::DeleteKeyCredential()
{
	co_await KeyCredentialManager::DeleteAsync(CREDETIAL_ID);

	co_return TPMEncryptor::IInspectableWrapper<bool>::box(true);
}

IAsyncOperation<bool> WinHello::OpenCredentialAsync()
{
	auto&& keyCredentialRetrievalResult = co_await KeyCredentialManager::OpenAsync(CREDETIAL_ID);
	auto status = keyCredentialRetrievalResult.Status();

	CheckKeyCredentialStatus(status);

	co_return true;
}

IAsyncOperation<IBuffer> WinHello::GetWindowsHelloPublicKeyAsync()
{
	auto isSupported = co_await KeyCredentialManager::IsSupportedAsync();
	if (!isSupported)
	{
		OutputDebugString(L"Windows Hello is not supported on this device.\n");
		throw hresult_error(error_not_implemented, L"Windows Hello is not supported on this device.");
	}

	// Attempt to open existing credential
	auto&& keyCredentialRetrievalResult = co_await KeyCredentialManager::OpenAsync(CREDETIAL_ID);
	auto status = keyCredentialRetrievalResult.Status();
	CheckKeyCredentialStatus(status);

	auto keyCredential = keyCredentialRetrievalResult.Credential();
	auto publicKey = keyCredential.RetrievePublicKey(CryptographicPublicKeyBlobType::BCryptPublicKey);

	co_return publicKey;
}

IAsyncOperation<IBuffer> WinHello::SignAsync()
{
	auto isSupported = co_await KeyCredentialManager::IsSupportedAsync();
	if (!isSupported)
	{
		OutputDebugString(L"Windows Hello is not supported on this device.\n");
		throw hresult_error(error_not_implemented, L"Windows Hello is not supported on this device.");
	}

	// Attempt to open existing credential
	auto&& keyCredentialRetrievalResult = co_await KeyCredentialManager::OpenAsync(CREDETIAL_ID);
	CheckKeyCredentialStatus(keyCredentialRetrievalResult.Status());

	auto keyCredential = keyCredentialRetrievalResult.Credential();
	
	auto dataBuffer = CryptographicBuffer::ConvertStringToBinary(DATA_TO_SIGN, BinaryStringEncoding::Utf16LE);

	auto&& signatureResult = co_await keyCredential.RequestSignAsync(dataBuffer);
	CheckKeyCredentialStatus(signatureResult.Status());

	co_return signatureResult.Result();
}

CryptographicKey WinHello::CreateAESKey(IBuffer signature)
{
	auto sha256Provider = HashAlgorithmProvider::OpenAlgorithm(HashAlgorithmNames::Sha256());
	auto hash = sha256Provider.HashData(signature);
	if (hash.Length() != 32)
	{
		OutputDebugString(L"Hash length is not 32 bytes.\n");
		throw hresult_error(error_fail, L"Hash length is not 32 bytes.");
	}

	auto aesProvider = SymmetricKeyAlgorithmProvider::OpenAlgorithm(SymmetricAlgorithmNames::AesGcm());

	auto aesKey = aesProvider.CreateSymmetricKey(hash);

	return aesKey;
}

hstring WinHello::Encrypt(CryptographicKey key, hstring plainText)
{
	auto nonce = CryptographicBuffer::GenerateRandom(NONCE_LENGTH);

	auto dataToEncrypt = CryptographicBuffer::ConvertStringToBinary(plainText, BinaryStringEncoding::Utf16LE);
	auto encryptedAndAuthData = CryptographicEngine::EncryptAndAuthenticate(key, dataToEncrypt, nonce, nullptr);

	auto encryptedData = encryptedAndAuthData.EncryptedData();
	auto tag = encryptedAndAuthData.AuthenticationTag();

	DataWriter writer;
	writer.WriteBuffer(nonce);
	writer.WriteBuffer(encryptedData);
	writer.WriteBuffer(tag);
	auto encryptedDataBuffer = writer.DetachBuffer();

	auto base64String = CryptographicBuffer::EncodeToBase64String(encryptedDataBuffer);

	return base64String;
}

hstring WinHello::Decrypt(CryptographicKey key, hstring encryptedText)
{
	auto combainedBuffer = CryptographicBuffer::DecodeFromBase64String(encryptedText);

	auto encryptedDataLength = combainedBuffer.Length() - NONCE_LENGTH - TAG_LENGTH;

	auto reader = DataReader::FromBuffer(combainedBuffer);
	auto nonce = reader.ReadBuffer(NONCE_LENGTH);
	auto encryptedData = reader.ReadBuffer(encryptedDataLength);
	auto tag = reader.ReadBuffer(TAG_LENGTH);

	auto decryptedData = CryptographicEngine::DecryptAndAuthenticate(key, encryptedData, nonce, tag, nullptr);
	auto decryptedText = CryptographicBuffer::ConvertBinaryToString(BinaryStringEncoding::Utf16LE, decryptedData);

	return decryptedText;
}

void WinHello::CheckKeyCredentialStatus(KeyCredentialStatus status)
{
	switch (status) {
	case KeyCredentialStatus::Success:
		OutputDebugString(L"Key credential opened successfully.\n");
		break;

	case KeyCredentialStatus::NotFound:
		OutputDebugString(L"Key credential not found.\n");
		throw hresult_error(error_out_of_bounds, L"Key credential not found.");


	case KeyCredentialStatus::UserCanceled:
		OutputDebugString(L"User canceled the operation.\n");
		throw hresult_error(error_canceled, L"User canceled the operation.");

	case KeyCredentialStatus::UnknownError:
		OutputDebugString(L"An unknown error occurred.\n");
		throw hresult_error(error_fail, L"An unknown error occurred.");

	case KeyCredentialStatus::UserPrefersPassword:
		OutputDebugString(L"User prefers password.\n");
		throw hresult_error(error_user_prefers_password, L"User prefers password.");

	case KeyCredentialStatus::CredentialAlreadyExists:
		OutputDebugString(L"Key credential already exists.\n");
		throw hresult_error(error_fail, L"Key credential already exists.");

	case KeyCredentialStatus::SecurityDeviceLocked:
		OutputDebugString(L"Security device is locked.\n");
		throw hresult_error(error_fail, L"Security device is locked.");

	default:
		OutputDebugString(L"Unknown key credential status.\n");
		throw hresult_error(error_fail, L"Unknown key credential status.");
	}
}




