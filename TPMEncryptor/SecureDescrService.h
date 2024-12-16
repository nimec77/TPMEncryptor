#pragma once

#include "MemoryDeallocation.h"

#include <windows.h>
#include <string>		

struct SecureDescrData {	
	PSECURITY_DESCRIPTOR pSD;
	ULONG cbSD;

	SecureDescrData(PSECURITY_DESCRIPTOR pSD = nullptr, ULONG cbSD = 0) : pSD(pSD), cbSD(cbSD) {}
};

class SecureDescrService
{
public:
	std::wstring GetTokenUserString() const;
	SecureDescrData CreateSecureDescriptor(const std::wstring sid) const;

	PSID GetCurrentUserSid() const;
	SecureDescrData CreateSecureDescriptor(const PSID pSid) const;
};

