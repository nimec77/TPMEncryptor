#pragma once

#include "TMPEncryptorHelper.h"
#include "WinHello.h"
#include "MemoryDeallocation.h"

#include <vector>
#include <winrt/Windows.Foundation.h>

class SecureService
{
public:
	winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::IInspectable> CreateAESKey() const;

private:
	winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::IInspectable> ImportPublicKey() const;

	winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::IInspectable> ImportECCPublicKey() const;

	// Helper check
	inline void CheckStatus(const SECURITY_STATUS status, const std::string msg) const {
		if (status != ERROR_SUCCESS) {
			auto message = msg + ": " + std::to_string(status);
			throw std::runtime_error(message);
		}
	}

	TMPEncryptorHelper m_encryptorHelper;
	WinHello m_winHello;
};

