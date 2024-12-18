#include "pch.h"
#include "StringConverter.h"
#include <Windows.h>
#include <stdexcept>
#include <wincrypt.h>


std::string StringConverter::ConvertWideStringToString(const std::wstring& wideString)
{
	if (wideString.empty())
	{
		return std::string();
	}

	auto size_needed = WideCharToMultiByte(CP_UTF8, 0, wideString.c_str(), (int)wideString.size(), nullptr, 0, nullptr, nullptr);
	if (size_needed == 0) {
		throw std::runtime_error("WideCharToMultiByte failed to calculate size.");
	}

	std::string strTo(size_needed, 0);
	auto bytes_written = WideCharToMultiByte(CP_UTF8, 0, wideString.c_str(), (int)wideString.size(), strTo.data(), size_needed, nullptr, nullptr);
	if (bytes_written == 0) {
		throw std::runtime_error("WideCharToMultiByte failed to convert.");
	}

	return strTo;
}

std::wstring StringConverter::ConvertStringToWideString(const std::string& string)
{
	if (string.empty())
	{
		return std::wstring();
	}

	auto size_needed = MultiByteToWideChar(CP_UTF8, 0, string.c_str(), (int)string.size(), nullptr, 0);
	if (size_needed == 0) {
		throw std::runtime_error("MultiByteToWideChar failed to calculate size.");
	}

	std::wstring wstrTo(size_needed, 0);
	auto bytes_written = MultiByteToWideChar(CP_UTF8, 0, string.c_str(), (int)string.size(), wstrTo.data(), size_needed);
	if (bytes_written == 0) {
		throw std::runtime_error("MultiByteToWideChar failed to convert.");
	}

	return wstrTo;
}

std::string StringConverter::ConvertHStringToString(const winrt::hstring& hstring)
{
	if (hstring.empty())
	{
		return std::string();
	}

	auto size_needed = WideCharToMultiByte(CP_UTF8, 0, hstring.c_str(), (int)hstring.size(), nullptr, 0, nullptr, nullptr);
	if (size_needed == 0) {
		throw std::runtime_error("WideCharToMultiByte failed to calculate size.");
	}

	std::string strTo(size_needed, 0);
	auto bytes_written = WideCharToMultiByte(CP_UTF8, 0, hstring.c_str(), (int)hstring.size(), strTo.data(), size_needed, nullptr, nullptr);
	if (bytes_written == 0) {
		throw std::runtime_error("WideCharToMultiByte failed to convert.");
	}

	return strTo;
}

std::string StringConverter::Base64Encode(const std::string& data)
{
	std::string encodedData;

	DWORD base64Size = 0;
	if (!CryptBinaryToStringA((const BYTE*)data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64Size))
	{
		throw std::runtime_error("Failed to get base64 size");
	}

	std::vector<char> base64String(base64Size);

	if (!CryptBinaryToStringA((const BYTE*)data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64String.data(), &base64Size))
	{
		throw std::runtime_error("Failed to encode data to base64");
	}

	encodedData.assign(base64String.data(), base64Size);

	return encodedData;
}

std::string StringConverter::Base64Decode(const std::string& input)
{
	std::string decodedData;

	DWORD binarySize = 0;
	if (!CryptStringToBinaryA(input.data(), (DWORD)input.size(), CRYPT_STRING_BASE64, NULL, &binarySize, NULL, NULL))
	{
		throw std::runtime_error("Failed to get binary size");
	}

	std::vector<BYTE> binaryData(binarySize);

	if (!CryptStringToBinaryA(input.data(), (DWORD)input.size(), CRYPT_STRING_BASE64, binaryData.data(), &binarySize, NULL, NULL))
	{
		throw std::runtime_error("Failed to decode base64 data");
	}

	decodedData.assign((char*)binaryData.data(), binarySize);

	return decodedData;
}
