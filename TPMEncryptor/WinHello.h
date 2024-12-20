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

private:
	static const LPCWSTR CREDETIAL_ID;

	static const LPCWSTR DATA_TO_SIGN;

	static void CheckKeyCredentialStatus(winrt::Windows::Security::Credentials::KeyCredentialStatus status);
};


