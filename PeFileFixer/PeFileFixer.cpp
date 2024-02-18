#include <Windows.h>
#include <iostream>

int main(int argc, char* argv[])
{
	// Read filename from command line
	if (argc < 2) {
		std::cout << "Usage: PeFileFixer <filename>" << std::endl;
		return 1;
	}

	// Open the file
	HANDLE hFile = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::cout << "CreateFile failed! (" << GetLastError() << ")" << std::endl;
		return 1;
	}

	// Read file as buffer
	DWORD fileSize = GetFileSize(hFile, NULL);
	BYTE* buffer = new BYTE[fileSize];
	DWORD bytesRead;
	if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
		std::cout << "ReadFile failed! (" << GetLastError() << ")" << std::endl;
		return 1;
	}

	// Fix the PE header
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(buffer + dosHeader->e_lfanew);
	
	// Get section header
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeader);

	// Fix sections
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		// Fix raw address
		sectionHeader[i].PointerToRawData = sectionHeader[i].VirtualAddress;
		// Fix raw size
		sectionHeader[i].SizeOfRawData = sectionHeader[i].Misc.VirtualSize;
	}

	// Adjust other optional header values
	ntHeader->OptionalHeader.SizeOfImage = sectionHeader[ntHeader->FileHeader.NumberOfSections - 1].VirtualAddress + sectionHeader[ntHeader->FileHeader.NumberOfSections - 1].Misc.VirtualSize;
	ntHeader->OptionalHeader.SizeOfHeaders = sectionHeader[0].PointerToRawData;

	// Adjust data directory values
	ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
	ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
	ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
	ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
	ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
	ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;

	// Adjust import address table
	ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
	ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;

	// Adjust bound import table
	ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
	ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;

	// Write the buffer to the file
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	if (!WriteFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
		std::cout << "WriteFile failed! (" << GetLastError() << ")" << std::endl;
		return 1;
	}

	// Cleanup

	CloseHandle(hFile);


}