#pragma once

#include "SecureDescrService.h"

#include <windows.h>
#include <string>
#include <stdexcept>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <vector>

class TMPEncryptorHelper
{
public:
	TMPEncryptorHelper();
	~TMPEncryptorHelper();

	std::string Encrypt(const std::string& plainText, const SecureDescrData secureDescrData) const;
	std::string Decrypt(const std::string& chipherText) const;
	void DeleteKey() const;
	int isWindowsTPMSupported() const;
	void CreateECDHKey() const;
	NCRYPT_KEY_HANDLE GetECDHKey() const;
	BCRYPT_KEY_HANDLE CreateAESKey(const NCRYPT_KEY_HANDLE hPrivKey, const std::vector<uint8_t>& peerPublicKey) const;

private:
	static const LPCWSTR KEY_NAME;

	static std::wstring ParsePlatformType(const std::wstring& platformVersion);

	// Helper check
	inline void CheckStatus(const SECURITY_STATUS status, const std::string msg) const {
		if (status != ERROR_SUCCESS) {
			throw std::runtime_error(msg);
		}
	}

	NCRYPT_KEY_HANDLE GetTPMKey() const;
};
