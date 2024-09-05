#include <windows.h>
#include <iostream>
#include <sstream>

#define IOCTL_READ_BYTE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_BYTE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <kernel_address>" << std::endl;
        return 1;
    }

    // Parse the memory address from argv[1]
    std::stringstream ss;
    ss << std::hex << argv[1];
    PVOID address = nullptr;
    ss >> address;

    BOOL success;
    DWORD bytesReturned;

    if (address == nullptr) {
        std::cerr << "Invalid address provided." << std::endl;
        return 1;
    }

    HANDLE hDevice = CreateFile(
        L"\\\\.\\VulnerableDriver",   // The symbolic link to the device
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open device. Error: " << GetLastError() << std::endl;
        return 1;
    }

    UCHAR buffer[9]; // buffer[0-7] = address, buffer[8] = value

    // Example: Read a byte from the kernel memory address
    memcpy(buffer, &address, sizeof(PVOID)); // Copy the address to buffer[0-7]

    success = DeviceIoControl(
        hDevice,
        IOCTL_READ_BYTE,
        &buffer,
        sizeof(buffer),
        &buffer,
        sizeof(buffer),
        &bytesReturned,
        NULL);

    if (success) {
        std::cout << "Read successful, value: 0x" << std::hex << static_cast<int>(buffer[8]) << std::endl;
    }
    else {
        std::cerr << "Read failed. Error: " << GetLastError() << std::endl;
    }

    // Example: Write a byte to the kernel memory address
    memcpy(buffer, &address, sizeof(PVOID));   // Copy the address to buffer[0-7]
    buffer[8] = 0xAB;                          // Value to write

    success = DeviceIoControl(
        hDevice,
        IOCTL_WRITE_BYTE,
        &buffer,
        sizeof(buffer),
        NULL,
        0,
        &bytesReturned,
        NULL);

    if (success) {
        std::cout << "Write successful" << std::endl;
    }
    else {
        std::cerr << "Write failed. Error: " << GetLastError() << std::endl;
    }

    CloseHandle(hDevice);
    return 0;
}