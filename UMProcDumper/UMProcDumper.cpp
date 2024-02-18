#include <iostream>
#include <Windows.h>

#define IOCTL_MYDEVICE_DUMP CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MYDEVICE_IMAGESIZE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define ADJUST_OPTONAL_HEADER true
#define MINIMAL_DIRECTORY_ENTRIES false

typedef struct _INPUT_DUMP_INFO
{
	ULONG ProcessId;
	CHAR* ModuleName;
} INPUT_DUMP_INFO, * PINPUT_DUMP_INFO;

int main(int argc, char* argv[])
{
	if (argc > 1 && std::string(argv[1]) == "--list") {
		// TODO: List all modules inside a process
		return 0;
	}

	// Open the device
	HANDLE hDevice = CreateFile(L"\\\\.\\MyDevice3", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile failed! (%d)\n", GetLastError());
		return 1;
	}

	// Get the process id
	DWORD processId;
	printf("Enter the process id: ");
	scanf("%d", &processId);

	// Get the module name
	CHAR moduleName[MAX_PATH];
	printf("Enter the module name: ");
	scanf("%s", moduleName);

	// Initialize the structure to pass to the driver
	INPUT_DUMP_INFO inputDumpInfo;
	inputDumpInfo.ProcessId = processId;
	inputDumpInfo.ModuleName = moduleName;

	// Send the IOCTL to get the image size
	ULONG imageSize;
	DWORD bytesReturned;
	if (!DeviceIoControl(hDevice, IOCTL_MYDEVICE_IMAGESIZE, &inputDumpInfo, sizeof(inputDumpInfo), &imageSize,
		sizeof(imageSize), &bytesReturned, NULL))
	{
		printf("DeviceIoControl failed! (%d)\n", GetLastError());
		return 1;
	}

	// Allocate memory to store the image
	CHAR* image = (CHAR*)malloc(imageSize);

	// Send the IOCTL to dump the process
	if (!DeviceIoControl(hDevice, IOCTL_MYDEVICE_DUMP, &inputDumpInfo, sizeof(inputDumpInfo), image,
		imageSize, &bytesReturned, NULL))
	{
		printf("DeviceIoControl failed! (%d)\n", GetLastError());
		return 1;
	}


	// Save to file
	FILE* file;
	fopen_s(&file, "C:\\Users\\user\\Desktop\\dumpedProcess.bin", "wb");
	fwrite(image, imageSize, 1, file);
	fclose(file);

	// Free the memory
	free(image);


	// Close the device
	CloseHandle(hDevice);

	// Open the file
	HANDLE hFile = CreateFileA("C:\\Users\\user\\Desktop\\dumpedProcess.bin", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

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

	if (ADJUST_OPTONAL_HEADER)
	{
		// Adjust other optional header values
		// ntHeader->OptionalHeader.SizeOfImage = sectionHeader[ntHeader->FileHeader.NumberOfSections - 1].VirtualAddress + sectionHeader[ntHeader->FileHeader.NumberOfSections - 1].Misc.VirtualSize;
		ntHeader->OptionalHeader.SizeOfHeaders = sectionHeader[0].PointerToRawData;

		if (MINIMAL_DIRECTORY_ENTRIES)
		{
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
		}
		else {
			// Read debug directory
			PIMAGE_DEBUG_DIRECTORY debugDirectory = (PIMAGE_DEBUG_DIRECTORY)(buffer + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);

			// Set the pointer to raw data equal to the virtual address
			debugDirectory->PointerToRawData = debugDirectory->AddressOfRawData;
		}
	}

	// Write the buffer to the file
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	if (!WriteFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
		std::cout << "WriteFile failed! (" << GetLastError() << ")" << std::endl;
		return 1;
	}

	// Cleanup

	CloseHandle(hFile);

	return 0;
}

