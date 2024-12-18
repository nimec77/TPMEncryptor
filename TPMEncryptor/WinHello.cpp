#include "pch.h"
#include "WinHello.h"
#include "StringConverter.h"

#include <winrt/Windows.Security.Credentials.UI.h>
#include <winrt/windows.security.cryptography.core.h>
#include <stdexcept>

using namespace winrt;
using namespace winrt::impl;
using namespace Windows::Foundation;
using namespace Windows::Storage::Streams;
using namespace Windows::Security::Credentials;
using namespace Windows::Security::Credentials::UI;
using namespace Windows::Security::Cryptography::Core;

const LPCWSTR WinHello::CREDETIAL_ID = L"AdWalletCredential";

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

IAsyncAction WinHello::DeleteKeyCredential()
{
	co_await KeyCredentialManager::DeleteAsync(CREDETIAL_ID);
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




