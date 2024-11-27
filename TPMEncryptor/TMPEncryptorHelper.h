#pragma once

#include <string>

class TMPEncryptorHelper
{
public:
	TMPEncryptorHelper();
	~TMPEncryptorHelper();

	static std::string Base64Encode(const std::string& input);
	static std::string Base64Decode(const std::string& input);

	std::string Encrypt(const std::string& plainText, const std:: string& password);
	std::string Decrypt(const std::string& chipherText, const std::string& password);

private:
	static const LPCWSTR KEY_NAME;
};

