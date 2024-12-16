#pragma once

#include "SecureDescrService.h"

#include <windows.h>
#include <string>

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

private:
	static const LPCWSTR KEY_NAME;

	static std::wstring ParsePlatformType(const std::wstring& platformVersion);
};
