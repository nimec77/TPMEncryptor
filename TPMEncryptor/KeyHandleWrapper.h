#pragma once

#include <winrt/base.h>       // For WinRT basics
#include <bcrypt.h>           // For BCRYPT_KEY_HANDLE
#include <utility>

namespace winrt::TPMEncryptor {

	struct KeyHandleWrapper
	{
		BCRYPT_KEY_HANDLE hKey{ nullptr };

		KeyHandleWrapper(BCRYPT_KEY_HANDLE handle = nullptr) noexcept : hKey(handle) {}
		~KeyHandleWrapper() noexcept { 
			if (hKey) {
				BCryptDestroyKey(hKey);
			}
		}

		// Copy and move constructors
		KeyHandleWrapper(const KeyHandleWrapper&) = delete;
		KeyHandleWrapper& operator=(const KeyHandleWrapper&) = delete;

		KeyHandleWrapper(KeyHandleWrapper&& other) noexcept : hKey(std::exchange(other.hKey, nullptr)) {}

		KeyHandleWrapper& operator=(KeyHandleWrapper&& other) noexcept {
			if (this != &other) {
				if (hKey) {
					BCryptDestroyKey(hKey);
				}
				hKey = std::exchange(other.hKey, nullptr);
			}
			return *this;
		}
	};
}
