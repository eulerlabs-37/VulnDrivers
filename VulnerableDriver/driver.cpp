#include <ntddk.h>

#define IOCTL_READ_BYTE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_BYTE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Forward declarations
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);
extern "C" VOID UnloadDriver(IN PDRIVER_OBJECT DriverObject);
extern "C" NTSTATUS DispatchCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
extern "C" NTSTATUS DispatchIoctl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    // Setup the driver unload routine
    DriverObject->DriverUnload = UnloadDriver;

    // Setup the dispatch routines
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    // Create the device object
    UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, L"\\Device\\MemoryAccessDevice");

    PDEVICE_OBJECT DeviceObject = NULL;
    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0, // No device extension
        &devName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &DeviceObject);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Create symbolic link
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, L"\\DosDevices\\VulnerableDriver");
    status = IoCreateSymbolicLink(&symLink, &devName);

    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(DeviceObject);
    }

    return status;
}

extern "C" VOID UnloadDriver(IN PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, L"\\DosDevices\\VulnerableDriver");
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);
}

extern "C" NTSTATUS DispatchCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DispatchIoctl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0;

    // We expect the user to pass a UCHAR array containing the address and data
    UCHAR* buffer = (UCHAR*)Irp->AssociatedIrp.SystemBuffer;

    switch (ioControlCode)
    {
    case IOCTL_READ_BYTE:
        if (buffer) {
            PVOID address = *(PVOID*)buffer;  // The first 8 bytes in the buffer is the address
            buffer[8] = *(UCHAR*)address;     // Read the byte at the specified address into buffer[8]
            bytesReturned = 9 * sizeof(UCHAR);
            status = STATUS_SUCCESS;
        }
        else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;

    case IOCTL_WRITE_BYTE:
        if (buffer) {
            PVOID address = *(PVOID*)buffer;  // The first 8 bytes in the buffer is the address
            *(UCHAR*)address = buffer[8];     // Write the byte in buffer[8] to the specified address
            bytesReturned = 9 * sizeof(UCHAR);
            status = STATUS_SUCCESS;
        }
        else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
