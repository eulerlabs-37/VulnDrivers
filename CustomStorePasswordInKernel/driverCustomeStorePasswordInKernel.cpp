#include <ntddk.h>

// Global buffer to store file contents at runtime
#define BUFFER_SIZE 256
CHAR GlobalBuffer[BUFFER_SIZE] = { 0 };
ULONG GlobalBufferBytesRead = 0;

NTSTATUS ReadFlagFromFile(PUNICODE_STRING FilePath)
{
    NTSTATUS status;
    HANDLE fileHandle = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    LARGE_INTEGER byteOffset;

    // Initialize object attributes for the file
    InitializeObjectAttributes(&objectAttributes,
        FilePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    // Open the file using ZwCreateFile
    status = ZwCreateFile(&fileHandle,
        GENERIC_READ,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to open file: %08x\n", status);
        return status;
    }

    // Set the byte offset to the beginning of the file
    byteOffset.LowPart = byteOffset.HighPart = 0;

    // Initialize the global buffer
    RtlZeroMemory(GlobalBuffer, sizeof(GlobalBuffer));

    // Read the file content into the global buffer
    status = ZwReadFile(fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        GlobalBuffer,
        sizeof(GlobalBuffer),
        &byteOffset,
        NULL);

    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to read file: %08x\n", status);
        ZwClose(fileHandle);
        return status;
    }

    GlobalBufferBytesRead = (ULONG)ioStatusBlock.Information;

    // Close the file handle
    ZwClose(fileHandle);

    DbgPrint("File read successfully, bytes read: %lu\n", GlobalBufferBytesRead);

    return STATUS_SUCCESS;
}

extern "C" VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("Driver unloaded\n");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    UNICODE_STRING filePath = RTL_CONSTANT_STRING(L"\\??\\C:\\Users\\user\\Desktop\\flag.txt");

    DriverObject->DriverUnload = DriverUnload;

    // Read the flag from the file into the global buffer
    status = ReadFlagFromFile(&filePath);

    if (NT_SUCCESS(status)) {
        DbgPrint("Flag content: %s\n", GlobalBuffer);
    }
    else {
        DbgPrint("Failed to read flag file\n");
    }

    return STATUS_SUCCESS;
}
