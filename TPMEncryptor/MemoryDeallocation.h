#pragma once

#include <windows.h>
#include <memory>

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
