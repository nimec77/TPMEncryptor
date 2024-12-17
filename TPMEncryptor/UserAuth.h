#pragma once

#include <winrt/windows.foundation.h>

class UserAuth
{
public:

	static winrt::Windows::Foundation::IAsyncOperation<bool> AuthenticateAsync();
	static winrt::Windows::Foundation::IAsyncOperation<bool> CreateKeyCredentialAsync();
	static winrt::Windows::Foundation::IAsyncAction DeleteKeyCredential();

private:
	static const LPCWSTR CREDETIAL_ID;

};

