#include "pch.h"
#include "UserAuth.h"
#include <winrt/Windows.Security.Credentials.UI.h>


using namespace winrt;
using namespace winrt::Windows::Foundation;
using namespace Windows::Security::Credentials::UI;

IAsyncOperation<bool> UserAuth::AuthenticateAsync()
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
