#include <ntddk.h>

// Define IOCTL codes
#define IOCTL_READ_BUFFER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_BUFFER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Define the size of the kernel buffer
#define BUFFER_SIZE 16

// Declare a buffer in the kernel space
UCHAR KernelBuffer[BUFFER_SIZE];

NTSTATUS DriverUnsupported(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DriverCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DriverClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DriverIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING SymbolicLinkName;

    // Print a debug message
    DbgPrint("DriverUnload Called\n");

    // Define the symbolic link name
    RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\Vulnerable");

    // Delete the symbolic link
    IoDeleteSymbolicLink(&SymbolicLinkName);

    // Delete the device object
    IoDeleteDevice(DriverObject->DeviceObject);
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    UNICODE_STRING DeviceName;
    UNICODE_STRING SymbolicLinkName;
    PDEVICE_OBJECT DeviceObject = NULL;
    NTSTATUS status;

    DbgPrint("DriverEntry Called\n");

    RtlInitUnicodeString(&DeviceName, L"\\Device\\Vulnerable");
    RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\Vulnerable");

    status = IoCreateDevice(
        DriverObject,
        0,
        &DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, // check with article + above
        FALSE,
        &DeviceObject);

    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to create device\n");
        return status;
    }

    status = IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(DeviceObject);
        DbgPrint("Failed to create symbolic link\n");
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoControl;
    DriverObject->DriverUnload = DriverUnload;

    return STATUS_SUCCESS;
}

NTSTATUS DriverCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("DriverCreate Called\n");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DriverClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("DriverClose Called\n");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DriverIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG bytesTransferred = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_READ_BUFFER: {
        ULONG index;
        if (Irp->AssociatedIrp.SystemBuffer != NULL) {
            index = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
            // Read from KernelBuffer and return the address of the read location
            *(UCHAR*)Irp->AssociatedIrp.SystemBuffer = KernelBuffer[index];
            *(PVOID*)((UCHAR*)Irp->AssociatedIrp.SystemBuffer + sizeof(UCHAR)) = &KernelBuffer[index];
            bytesTransferred = sizeof(UCHAR) + sizeof(PVOID);
            status = STATUS_SUCCESS;
        }
        break;
    }

    case IOCTL_WRITE_BUFFER:
    {
        struct WriteBufferInput {
            ULONG index;
            UCHAR value;
        } *input;

        if (Irp->AssociatedIrp.SystemBuffer != NULL) {
            input = (WriteBufferInput*)Irp->AssociatedIrp.SystemBuffer;
            // Write to KernelBuffer and return the address of the written location
            KernelBuffer[input->index] = input->value;
            *(PVOID*)((UCHAR*)Irp->AssociatedIrp.SystemBuffer + sizeof(WriteBufferInput)) = &KernelBuffer[input->index];
            bytesTransferred = sizeof(WriteBufferInput) + sizeof(PVOID);
            status = STATUS_SUCCESS;
        }
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesTransferred;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}