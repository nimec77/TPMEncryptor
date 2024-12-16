#include "pch.h"
#include "SecureDescrService.h"
#include <sddl.h>
#include <stdexcept>
#include <memory>
#include <strsafe.h>
#include <aclapi.h>

#pragma comment(lib, "advapi32.lib")


// Custom deleter for NCRYPT_KEY_HANDLE
struct TokenHandleDeleter
{
	void operator()(void* handle) const
	{
		if (handle != NULL)
		{
			CloseHandle(reinterpret_cast<HANDLE>(handle));
		}
	}
};


std::wstring SecureDescrService::GetTokenUserString() const
{

	// Use unique_ptr with custom deleters
	std::unique_ptr<void, TokenHandleDeleter> hToken(nullptr);
	std::unique_ptr<void, MemoryDeallocation> pTokenUser(nullptr);
	std::unique_ptr<void, MemoryDeallocation> pStringSid(nullptr);

	HANDLE hTokenRaw = NULL;
	PTOKEN_USER pTokenUserRaw = NULL;

	// Get the current user's SID
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTokenRaw)) {
		auto error = GetLastError();
		throw std::runtime_error("Failed to open process token: " + std::to_string(error));
	}
	hToken.reset(reinterpret_cast<void*>(hTokenRaw));

	// First call to get the required buffer size
	DWORD cbTokenUser = 0;
	if (!GetTokenInformation(hTokenRaw, TokenUser, NULL, 0, &cbTokenUser) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		auto error = GetLastError();
		throw std::runtime_error("Failed to get token user length: " + std::to_string(error));
	}

	// Allocate the buffer and get the token user information
	pTokenUserRaw = (PTOKEN_USER)LocalAlloc(LPTR, cbTokenUser);
	if (pTokenUserRaw == NULL) {
		auto error = GetLastError();
		throw std::runtime_error("Failed to allocate memory for token user: " + std::to_string(error));
	}

	if (!GetTokenInformation(hTokenRaw, TokenUser, pTokenUserRaw, cbTokenUser, &cbTokenUser)) {
		auto error = GetLastError();
		throw std::runtime_error("Failed to get token user: " + std::to_string(error));
	}
	pTokenUser.reset(reinterpret_cast<void*>(pTokenUserRaw));

	// Convert the SID to a string
	LPWSTR pStringSidRaw = NULL;
	if (!ConvertSidToStringSid(pTokenUserRaw->User.Sid, &pStringSidRaw)) {
		auto error = GetLastError();
		throw std::runtime_error("Failed to convert SID to string: " + std::to_string(error));
	}	
	pStringSid.reset(reinterpret_cast<void*>(pStringSidRaw));

	auto sid = std::wstring(pStringSidRaw);

	return sid;
}

SecureDescrData SecureDescrService::CreateSecureDescriptor(const std::wstring sid) const
{
	WCHAR sddl[256];
	HRESULT hr = StringCchPrintfW(sddl, ARRAYSIZE(sddl), L"D:(A;;FA;;;%s)",  sid.c_str());
	if (FAILED(hr))
	{
		throw std::runtime_error("Failed to create SDDL string");
	}

	PSECURITY_DESCRIPTOR pSD = NULL;
	ULONG cbSD = 0;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSD, &cbSD))
	{
		auto error = GetLastError();
		throw std::runtime_error("Failed to convert SDDL string to security descriptor: " + std::to_string(error));
	}
	
	return SecureDescrData(pSD, cbSD);
}

PSID SecureDescrService::GetCurrentUserSid() const
{

	HANDLE hTokenRaw = nullptr;
	// Get the current user's SID
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTokenRaw)) {
		auto error = GetLastError();
		throw std::runtime_error("Failed to open process token: " + std::to_string(error));
	}
	std::unique_ptr<void, TokenHandleDeleter> hToken(nullptr);
	hToken.reset(reinterpret_cast<void*>(hTokenRaw));

	// First call to get the required buffer size
	DWORD cbTokenUser = 0;
	if (!GetTokenInformation(hTokenRaw, TokenUser, NULL, 0, &cbTokenUser) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		auto error = GetLastError();
		throw std::runtime_error("Failed to get token user length: " + std::to_string(error));
	}

	PTOKEN_USER pTokenUserRaw = nullptr;
	// Allocate the buffer and get the token user information
	pTokenUserRaw = (PTOKEN_USER)LocalAlloc(LPTR, cbTokenUser);
	if (pTokenUserRaw == nullptr) {
		auto error = GetLastError();
		throw std::runtime_error("Failed to allocate memory for token user: " + std::to_string(error));
	}

	if (!GetTokenInformation(hTokenRaw, TokenUser, pTokenUserRaw, cbTokenUser, &cbTokenUser)) {
		auto error = GetLastError();
		throw std::runtime_error("Failed to get token user: " + std::to_string(error));
	}
	std::unique_ptr<void, MemoryDeallocation> pTokenUser(nullptr);
	pTokenUser.reset(reinterpret_cast<void*>(pTokenUserRaw));

	// Duplicate the SID so we can own it
	DWORD sidLength = GetLengthSid(pTokenUserRaw->User.Sid);
	PSID pSid = LocalAlloc(LPTR, sidLength);
	if (pSid == nullptr) {
		auto error = GetLastError();
		throw std::runtime_error("Failed to allocate memory for SID: " + std::to_string(error));
	}
	if (!CopySid(sidLength, pSid, pTokenUserRaw->User.Sid)) {
		auto error = GetLastError();
		throw std::runtime_error("Failed to copy SID: " + std::to_string(error));
	}

	return pSid;
}

SecureDescrData SecureDescrService::CreateSecureDescriptor(const PSID pSid) const
{
	// Build EXPLICIT_ACCESS to grant full access (GENERIC_ALL) to the current user
	EXPLICIT_ACCESS ea = { 0 };
	ea.grfAccessPermissions = GENERIC_ALL;
	ea.grfAccessMode = SET_ACCESS;
	ea.grfInheritance = NO_INHERITANCE;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
	ea.Trustee.ptstrName = (LPTSTR)pSid;

	// Create a new ACL that contains the new ACE
	PACL pACLRaw = nullptr;
	DWORD dwRes = SetEntriesInAcl(1, &ea, nullptr, &pACLRaw);
	if (ERROR_SUCCESS != dwRes)
	{
		throw std::runtime_error("Failed to set entries in ACL: " + std::to_string(dwRes));
	}
	std::unique_ptr<void, MemoryDeallocation> pACL(nullptr);
	pACL.reset(reinterpret_cast<void*>(pACLRaw));

	// Create and initialize a SECURITY_DESCRIPTOR
	PSECURITY_DESCRIPTOR pSDRaw = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (pSDRaw == nullptr)
	{
		throw std::runtime_error("Failed to allocate memory for security descriptor");
	}
	std::unique_ptr<void, MemoryDeallocation> pSD(nullptr);

	if (!InitializeSecurityDescriptor(pSDRaw, SECURITY_DESCRIPTOR_REVISION))
	{
		auto error = GetLastError();
		throw std::runtime_error("Failed to initialize security descriptor: " + std::to_string(error));
	}

	// Set owner and group to current user SID
	if (!SetSecurityDescriptorOwner(pSDRaw, pSid, FALSE))
	{
		auto error = GetLastError();
		throw std::runtime_error("Failed to set security descriptor owner: " + std::to_string(error));
	}
	if (!SetSecurityDescriptorGroup(pSDRaw, pSid, FALSE))
	{
		auto error = GetLastError();
		throw std::runtime_error("Failed to set security descriptor group: " + std::to_string(error));
	}

	// Set the DACL to the ACL
	if (!SetSecurityDescriptorDacl(pSDRaw, TRUE, pACLRaw, FALSE))
	{
		auto error = GetLastError();
		throw std::runtime_error("Failed to set security descriptor DACL: " + std::to_string(error));
	}

	// Validate the security descriptor
	if (!IsValidSecurityDescriptor(pSDRaw))
	{
		auto error = GetLastError();
		throw std::runtime_error("Security descriptor is not valid: " + std::to_string(error));
	}

	// Convert to self-relative SD
	ULONG cbSD = 0;
	MakeSelfRelativeSD(pSDRaw, nullptr, &cbSD);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		auto error = GetLastError();
		throw std::runtime_error("Failed to get self-relative security descriptor length: " + std::to_string(error));
	}

	PSECURITY_DESCRIPTOR pSDSelfRelative = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, cbSD);
	if (pSDSelfRelative == nullptr)
	{
		auto error = GetLastError();
		throw std::runtime_error("Failed to allocate memory for self-relative security descriptor: " + std::to_string(error));
	}

	if (!MakeSelfRelativeSD(pSDRaw, pSDSelfRelative, &cbSD))
	{
		auto error = GetLastError();
		throw std::runtime_error("Failed to make security descriptor self-relative: " + std::to_string(error));
	}

	return SecureDescrData(pSDSelfRelative, cbSD);
}
