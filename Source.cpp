//  Useful:  https://blog.kowalczyk.info/articles/pefileformat.html
//			 https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format


#include <iostream>
#include <stdio.h>
#include <iomanip>
#include <Windows.h>
#include <Winnt.h>
#include <memoryapi.h>
#include <WinBase.h>
#include <TlHelp32.h>
#include <Sysinfoapi.h>
#include <Libloaderapi.h>
#include <vector>

// Prototypes
BYTE* baseAddr = NULL;
BYTE* sectionAddr = NULL;

DWORD get_pID();
int get_value(BOOL isReplace);
BYTE* enum_modules(HANDLE hSnap);
HANDLE hProc;

std::vector<int*> search_bytes(DWORD offset, DWORD virtualSize, int searchValue);

int main(void)
{
	DWORD pID = get_pID();
	int searchValue = get_value(false);
	int replaceValue;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	IMAGE_NT_HEADERS ntHeader;
	IMAGE_FILE_HEADER fileHeader;
	IMAGE_SECTION_HEADER sectionHeader;
	IMAGE_DOS_HEADER DosHeader;

	SYSTEM_INFO sysInfo;
	GetNativeSystemInfo(&sysInfo);

	HANDLE hSnap;
	std::cout << "Getting process handle" << std::endl;

	//  Open handle towards target process
	hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, pID);
	if (hProc == INVALID_HANDLE_VALUE)
	{
		return 1;
	}

	//  To hold pointers towards mem addresses of interest
	std::vector<int*> addrs;
	addrs.clear();


	//  Determine CPU architecture to know which module flag to use when snapshotting modules.  Doesn't really matter anymore.
	if (sysInfo.wProcessorArchitecture == 9 || sysInfo.wProcessorArchitecture == 12)
	{
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pID); 
	}
	else
	{
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pID);
	}

	//  Get specific module
	baseAddr = enum_modules(hSnap);
	if (baseAddr == NULL) { std::cout << "Module enumeration failed, ending..." << std::endl; return 1; }
	//  Get MS DOS header
	if (!ReadProcessMemory(hProc, reinterpret_cast<const void*>(baseAddr), &DosHeader, sizeof(IMAGE_DOS_HEADER), nullptr))
	{
		std::cout << "Failed reading memory of IMAGE_DOS_HEADER, ending..." << std::endl;
		system("pause");
		return 1;
	}

	//  Get Nt Header
	if (!ReadProcessMemory(hProc, reinterpret_cast<const void*>(baseAddr + DosHeader.e_lfanew), &ntHeader, sizeof(IMAGE_NT_HEADERS), nullptr))
	{
		std::cout << "Failure reading memoryfor IMAGE_NT_HEADERS, ending..." << std::endl;
		system("pause");
		return 1;
	}

	//  Simple pointer addition to get the address of the sections
	IMAGE_SECTION_HEADER* sectionAddr = (IMAGE_SECTION_HEADER*)(baseAddr + DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS));

	//  Verify is PE file
	if (ntHeader.Signature == IMAGE_NT_SIGNATURE && baseAddr != NULL)
	{
		std::cout << "Verified is PE file" << std::endl;
		WORD numSections;
		fileHeader = ntHeader.FileHeader;
		numSections = fileHeader.NumberOfSections;
		//  Get a pointer to the address of the start of the section headers.  It comes after ntHeader.
		if (!ReadProcessMemory(hProc, reinterpret_cast<const void*>(sectionAddr), &sectionHeader, sizeof(IMAGE_SECTION_HEADER), nullptr))
		{
			std::cout << "Failure reading memory for IMAGE_SECTION_HEADER, ending..." << std::endl;
		}
		//  Find specific section holding the global variables (.data)
		for (int i = 0; i < numSections; i++)
		{
			if (memcmp(sectionHeader.Name, ".data", 5) == 0)
			{
				std::cout << "Found data set, header: 0x" << sectionAddr << std::endl;
				//  Search for integer value, save it to vector addrs
				addrs = search_bytes(sectionHeader.VirtualAddress, sectionHeader.Misc.VirtualSize, searchValue);
				break;
			}
			if (!ReadProcessMemory(hProc, reinterpret_cast<const void*>(sectionAddr++), &sectionHeader, sizeof(IMAGE_SECTION_HEADER), nullptr))
			{
				std::cout << "Failure reading memory for IMAGE_SECTION_HEADER, ending..." << std::endl;
				system("pause");
				return 1;
			}
		}
	}

	std::cout << "--------------------------" << std::endl << "Below are the following matches: " << std::endl;

	//  Loop through vector of scanned values
	if (addrs.size() > 1)
	{
		for (std::vector<int*>::iterator i = addrs.begin(); i != addrs.end(); i++)
		{
			std::cout << std::setw(5) << "" << "0x" << *i << std::setw(10) << "" << "Search Value: " << searchValue << std::endl;
		}
	}
	else
	{
		std::cout << std::setw(5) << "" << "None found of value " << searchValue << ", have you already written to it previously? Ending..." << std::endl;
		system("pause");
		return 0;
	}

	std::cout << std::endl << std::endl;
	replaceValue = get_value(true);

	for (std::vector<int*>::iterator i = addrs.begin(); i != addrs.end(); i++)
	{
		if (!WriteProcessMemory(hProc, *i, &replaceValue, sizeof(int), NULL))
		{
			std::cout << "Error writing to memory, ending..." << std::endl;
			system("pause");
			return 0;
		}
		else
		{
			std::cout << "Sucessfully wrote to: 0x" << *i << std::endl;
		}
	}

	std::cout << std::endl << "All done, thank you!" << std::endl << std::endl << std::endl;
	system("pause");
}

//  Enumerate the modules, compare it with executable name
BYTE* enum_modules(HANDLE hSnap)
{
	MODULEENTRY32 mod32;
	mod32.dwSize = sizeof(MODULEENTRY32);

	if (Module32First(hSnap, &mod32))
	{
		std::cout << "Module handle success" << std::endl;
		do
		{
			std::cout << "Searching modules..." << std::endl;
			if ((std::string(mod32.szModule)).find(".exe"))
			{
				std::cout << "Found module match: " << mod32.szModule << std::endl;
				return mod32.modBaseAddr;
			}
		} while (Module32Next(hSnap, &mod32));
	}
	return NULL;
	CloseHandle(hSnap);
}

std::vector<int*> search_bytes(DWORD offset, DWORD virtualSize, int searchValue) // Note:  C++ functions can't return C-style arrays by value. The closest thing is to return a pointer, or use vector.
{
	std::cout << "Searching .data section memory..." << std::endl;
	std::vector<int*> addrs;
	BYTE* ptr = baseAddr + offset;
	int currentVal;
	for (int i = 0; i < (int)virtualSize; i++)
	{
		int* currentPtr = (int*)ptr;

		ReadProcessMemory(hProc, currentPtr, &currentVal, sizeof(int), NULL);

		if (currentVal == searchValue)
		{
			addrs.push_back(currentPtr);
		}

		ptr++;
	}
	return addrs;
}

//  Get target process ID
DWORD get_pID()
{
	DWORD pID;
	std::cout << "Enter process ID: ";

	do
	{
		std::cin >> pID;
	} while (std::cin.fail());

	return pID;
}

int get_value(BOOL isReplace)
{
	int value;
	if (!isReplace)
	{
		std::cout << "Enter integer value to scan for: ";
	}
	else
	{
		std::cout << "Enter new integer value to replace scanned values: ";
	}

	do
	{
		std::cin >> value;
	} while (std::cin.fail());

	return value;
}