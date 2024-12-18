#pragma once

#include <windows.h>
#include <memory>
#include <bcrypt.h>
#include <ncrypt.h>


namespace TPMEncryptor
{
	struct MemoryDeallocation
	{
		void operator()(void* pBuffer) const
		{
			if (pBuffer != NULL)
			{
				LocalFree(reinterpret_cast<HLOCAL>(pBuffer));
			}
		}
	};
	struct NCryptHandleDeleter
	{
		void operator()(void* handle) const
		{
			if (handle != NULL)
			{
				NCryptFreeObject(reinterpret_cast<NCRYPT_HANDLE>(handle));
			}
		}
	};
	struct BCryptHandleDeleter
	{
		void operator()(BCRYPT_ALG_HANDLE handle) const
		{
			if (handle != NULL)
			{
				BCryptCloseAlgorithmProvider(handle, 0);
			}
		}
	};
	struct BCryptKeyHandleDeleter
	{
		void operator()(BCRYPT_KEY_HANDLE handle) const
		{
			if (handle != NULL)
			{
				BCryptDestroyKey(handle);
			}
		}
	};

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
}
