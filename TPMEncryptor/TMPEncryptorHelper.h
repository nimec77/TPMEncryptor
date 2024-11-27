#pragma once

#include <string>

class TMPEncryptorHelper
{
public:
	TMPEncryptorHelper();
	~TMPEncryptorHelper();

	static std::string Base64Encode(const std::string& input);
	static std::string Base64Decode(const std::string& input);

	std::string Encrypt(const std::string& plainText);
	std::string Decrypt(const std::string& chipherText);

private:
	static const LPCWSTR KEY_NAME;
};

