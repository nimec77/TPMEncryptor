#pragma once

#include "SecureDescrService.h"

#include <windows.h>
#include <string>
#include <stdexcept>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>


class TMPEncryptorHelper
{
public:
	TMPEncryptorHelper();
	~TMPEncryptorHelper();

	static std::string Base64Encode(const std::string& input);
	static std::string Base64Decode(const std::string& input);

	std::string Encrypt(const std::string& plainText, const SecureDescrData secureDescrData) const;
	std::string Decrypt(const std::string& chipherText) const;
	void DeleteKey() const;
	int isWindowsTPMSupported() const;
	void CreateECDHKey() const;
	NCRYPT_KEY_HANDLE GetECDHKey() const;
	void CreateAESKey() const;

private:
	static const LPCWSTR KEY_NAME;

	static std::wstring ParsePlatformType(const std::wstring& platformVersion);

	// Helper check
	inline void CheckStatus(SECURITY_STATUS status, const std::string msg) const {
		if (status != ERROR_SUCCESS) {
			throw std::runtime_error(msg);
		}
	}
};
