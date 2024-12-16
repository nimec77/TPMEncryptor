#pragma once

#include <winrt/windows.foundation.h>

class UserAuth
{
public:

	static winrt::Windows::Foundation::IAsyncOperation<bool> AuthenticateAsync();

};

