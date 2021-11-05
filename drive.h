/*
  文件系统过滤驱动
  1. 文件系统驱动一般会生成两种设备，一种为 CDO (文件系统控制设备)，用于自身的控制，每个文件系统驱动会生成一个，
     另一种为文件系统卷设备，FS Driver 会为每个为该类型文件系统的卷（逻辑盘）生成一个文件系统卷设备（不同于磁盘卷设备）。
  2.  文件系统过滤驱动就是通过附加到文件系统卷设备来完成功能的。
 */

#ifndef FS_FILTER_HENZOX_H
#define FS_FILTER_HENZOX_H


#include <ntddk.h>


 //#define FSF_MODULE_NAME_PREFIX            "FsFilter!"
#define KdPrintThisFunction()             KdPrint((FSF_MODULE_NAME_PREFIX"%s\n", __FUNCTION__))
#define KdPrintWithFuncPrefix(x, ...)     KdPrint((FSF_MODULE_NAME_PREFIX"%s: "x, __FUNCTION__))

#define FSF_DEVICE_FLAG                   'tfsF'

 // 检查是否是我的文件系统控制设备的过滤设备对象或者是文件系统卷设备过滤设备对象
#define IsMyFilterDevice(x)            (x->DeviceExtension != NULL && *(PULONG)(x->DeviceExtension) == FSF_DEVICE_FLAG)
// 检查是否是我的控制设备对象 CDO
#define IsMyControlDeivce(x)              (x == g_Cdo)

typedef struct _FSF_DEVICE_EXTENSION {
    ULONG TypeFlag;
    PDEVICE_OBJECT AttachedToDeviceObject;
    UNICODE_STRING AttachedToDeviceName;
    WCHAR AttachedToDeviceNameBuff[64];
    PDEVICE_OBJECT StorageDevice;
} FSF_DEVICE_EXTENSION, * PFSF_DEVICE_EXTENSION;

VOID
FsfUnload(
    __in struct _DRIVER_OBJECT* DriverObject
);
NTSTATUS
FsfCreate2(
    __in struct _DEVICE_OBJECT* DeviceObject,
    __inout struct _IRP* Irp
);

NTSTATUS
FsfPassThrough(
    __in struct _DEVICE_OBJECT* DeviceObject,
    __inout struct _IRP* Irp
);

NTSTATUS
FsfCreate(
    __in struct _DEVICE_OBJECT* DeviceObject,
    __inout struct _IRP* Irp
);

NTSTATUS
FsfRead(
    __in struct _DEVICE_OBJECT* DeviceObject,
    __inout struct _IRP* Irp
);

NTSTATUS
FsfWrite(
    __in struct _DEVICE_OBJECT* DeviceObject,
    __inout struct _IRP* Irp
);

NTSTATUS MyCreateNamedPipe(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS
FsfCreatePIPE(
    __in struct _DEVICE_OBJECT* DeviceObject,
    __inout struct _IRP* Irp
);

NTSTATUS
FsfFsControl(
    __in struct _DEVICE_OBJECT* DeviceObject,
    __inout struct _IRP* Irp
);

NTSTATUS
FsfCleanupClose(
    __in struct _DEVICE_OBJECT* DeviceObject,
    __inout struct _IRP* Irp
);

NTSTATUS
FsfSetSecurity(__in struct _DEVICE_OBJECT* DeviceObject,
    __inout struct _IRP* Irp
);

NTSTATUS
FsfCleanupClose2(
    __in struct _DEVICE_OBJECT* DeviceObject,
    __inout struct _IRP* Irp
);

/*--------Fast Io Dispatch--------*/
BOOLEAN
FsfFastIoCheckIfPossible(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __in BOOLEAN CheckForReadOperation,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
);

BOOLEAN
FsfFastIoRead(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __out PVOID Buffer,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
);

BOOLEAN
FsfFastIoWrite(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in BOOLEAN Wait,
    __in ULONG LockKey,
    __in PVOID Buffer,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
);

BOOLEAN
FsfFastIoQueryBasicInfo(
    __in struct _FILE_OBJECT* FileObject,
    __in BOOLEAN Wait,
    __out PFILE_BASIC_INFORMATION Buffer,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
);

BOOLEAN
FsfFastIoQueryStandardInfo(
    __in struct _FILE_OBJECT* FileObject,
    __in BOOLEAN Wait,
    __out PFILE_STANDARD_INFORMATION Buffer,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
);

BOOLEAN
FsfFastIoLock(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PLARGE_INTEGER Length,
    __in PEPROCESS ProcessId,
    __in ULONG Key,
    __in BOOLEAN FailImmediately,
    __in BOOLEAN ExclusiveLock,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
);

BOOLEAN
FsfFastIoUnlockSingle(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PLARGE_INTEGER Length,
    __in PEPROCESS ProcessId,
    __in ULONG Key,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
);

BOOLEAN
FsfFastIoUnlockAll(
    __in struct _FILE_OBJECT* FileObject,
    __in PEPROCESS ProcessId,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
);

BOOLEAN
FsfFastIoUnlockAllByKey(
    __in struct _FILE_OBJECT* FileObject,
    __in PVOID ProcessId,
    __in ULONG Key,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
);

BOOLEAN
FsfFastIoDeviceControl(
    __in struct _FILE_OBJECT* FileObject,
    __in BOOLEAN Wait,
    __in_opt PVOID InputBuffer,
    __in ULONG InputBufferLength,
    __out_opt PVOID OutputBuffer,
    __in ULONG OutputBufferLength,
    __in ULONG IoControlCode,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
);

VOID
FsfFastIoDetachDevice(
    __in struct _DEVICE_OBJECT* SourceDevice,
    __in struct _DEVICE_OBJECT* TargetDevice
);

BOOLEAN
FsfFastIoQueryNetworkOpenInfo(
    __in struct _FILE_OBJECT* FileObject,
    __in BOOLEAN Wait,
    __out struct _FILE_NETWORK_OPEN_INFORMATION* Buffer,
    __out struct _IO_STATUS_BLOCK* IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
);

BOOLEAN
FsfFastIoMdlRead(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __out PMDL* MdlChain,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
);

BOOLEAN
FsfFastIoMdlReadComplete(
    __in struct _FILE_OBJECT* FileObject,
    __in PMDL MdlChain,
    __in struct _DEVICE_OBJECT* DeviceObject
);

BOOLEAN
FsfFastIoPrepareMdlWrite(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __out PMDL* MdlChain,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _DEVICE_OBJECT* DeviceObject
);

BOOLEAN
FsfFastIoWriteComplete(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PMDL MdlChain,
    __in struct _DEVICE_OBJECT* DeviceObject
);

BOOLEAN
FsfFastIoReadCompressed(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __out PVOID Buffer,
    __out PMDL* MdlChain,
    __out PIO_STATUS_BLOCK IoStatus,
    __out struct _COMPRESSED_DATA_INFO* CompressedDataInfo,
    __in ULONG CompressedDataInfoLength,
    __in struct _DEVICE_OBJECT* DeviceObject
);

BOOLEAN
FsfFastIoWriteCompressed(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in ULONG Length,
    __in ULONG LockKey,
    __in PVOID Buffer,
    __out PMDL* MdlChain,
    __out PIO_STATUS_BLOCK IoStatus,
    __in struct _COMPRESSED_DATA_INFO* CompressedDataInfo,
    __in ULONG CompressedDataInfoLength,
    __in struct _DEVICE_OBJECT* DeviceObject
);

BOOLEAN
FsfFastIoReadCompleteCompressed(
    __in struct _FILE_OBJECT* FileObject,
    __in PMDL MdlChain,
    __in struct _DEVICE_OBJECT* DeviceObject
);

BOOLEAN
FsfFastIoWriteCompleteCompressed(
    __in struct _FILE_OBJECT* FileObject,
    __in PLARGE_INTEGER FileOffset,
    __in PMDL MdlChain,
    __in struct _DEVICE_OBJECT* DeviceObject
);

BOOLEAN
FsfFastIoQueryOpen(
    __inout struct _IRP* Irp,
    __out PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
    __in struct _DEVICE_OBJECT* DeviceObject
);

VOID
FsfFsNotification(
    __in struct _DEVICE_OBJECT* DeviceObject,
    __in BOOLEAN FsActive
);

typedef struct _EX_FAST_REF
{
    union
    {
        PVOID Object;
        ULONG RefCnt : 3;
        ULONG Value;
    };
} EX_FAST_REF, * PEX_FAST_REF;



typedef struct _CONTROL_AREA64
{
    PVOID64 Segment;
    PVOID64 p1;
    PVOID64 p2;
    ULONG64 NumberOfSectionReferences;
    ULONG64 NumberOfPfnReferences;
    ULONG64 NumberOfMappedViews;
    ULONG64 NumberOfUserReferences;
    union
    {
        ULONG LongFlags;
        ULONG Flags;
    } u;
    PVOID64 FilePointer;
} CONTROL_AREA64, * PCONTROL_AREA64;

typedef struct _CONTROL_AREA
{
    PVOID Segment;
    LIST_ENTRY DereferenceList;
    ULONG NumberOfSectionReferences;
    ULONG NumberOfPfnReferences;
    ULONG NumberOfMappedViews;
    ULONG NumberOfSystemCacheViews;
    ULONG NumberOfUserReferences;
    union
    {
        ULONG LongFlags;
        ULONG Flags;
    } u;
    PFILE_OBJECT FilePointer;
} CONTROL_AREA, * PCONTROL_AREA;


typedef struct _SEGMENT64
{
    PVOID64 ControlArea;
    ULONG TotalNumberOfPtes;
    ULONG NonExtendedPtes;
    ULONG Spare0;
}SEGMENT64, * PSEGMENT64;

typedef struct _SEGMENT
{
    struct _CONTROL_AREA* ControlArea;
    ULONG TotalNumberOfPtes;
    ULONG NonExtendedPtes;
    ULONG Spare0;
} SEGMENT, * PSEGMENT;



typedef struct _REMOTE_PORT_VIEW {
    ULONG Length;
    SIZE_T ViewSize;		//64位上必须是64位长度
    PVOID ViewBase;
} REMOTE_PORT_VIEW, * PREMOTE_PORT_VIEW;

typedef struct _SECTION_OBJECT
{
    PVOID StartingVa;
    PVOID EndingVa;
    PVOID Parent;
    PVOID LeftChild;
    PVOID RightChild;
    PSEGMENT Segment;
} SECTION_OBJECT, * PSECTION_OBJECT;


typedef struct _SECTION_OBJECT64
{
    PVOID64 StartingVa;
    PVOID64 EndingVa;
    PVOID64 Parent;
    PVOID64 LeftChild;
    PVOID64 RightChild;
    PVOID64 Segment;
} SECTION_OBJECT64, * PSECTION_OBJECT64;
#endif


// 定义消息数据长度.
//32位上，超过304,ZwCreatePort会报c00000f2（WinXP），c000000d（Win7、Win10）；64位上，超过608会报c000000d
//即，32位上Msg最大328（包括消息头24），64位上Msg最大648（包括消息头40）
#ifdef _WIN64
#define MAX_MSG_LEN				648   //0x288
#define MAX_DATA_LEN			608   //0x260     
#else
#define MAX_MSG_LEN				328	  //0x148
#define MAX_DATA_LEN			304   //0x130
#endif
#define LARGE_MESSAGE_SIZE		0x1000

//
// 为port消息定义头
// 注意：32位和64位系统，消息头大小不同，一个为24，一个为40
//
typedef struct _PORT_MESSAGE
{
    USHORT DataLength;				// Length of data following header (bytes)
    USHORT TotalLength;				// Length of data + sizeof(PORT_MESSAGE)
    USHORT Type;					// Type of the message (LPC_TYPE)
    USHORT VirtualRangesOffset;		// Offset of array of virtual address ranges
    CLIENT_ID ClientId;				// Client identifier of the message sender
    ULONG MessageId;				// Identifier of the particular message instance
    union {
        SIZE_T ClientViewSize;      // Only valid on LPC_CONNECTION_REQUEST message
        ULONG CallbackId;           // Only valid on LPC_REQUEST message
    }SizeAndId;
} PORT_MESSAGE, * PPORT_MESSAGE;

typedef struct _MYPORT_MESSAGE
{
    PORT_MESSAGE	Header;
    UCHAR			Data[MAX_DATA_LEN];
} MYPORT_MESSAGE, * PMYPORT_MESSAGE;

typedef struct _PORT_VIEW {
    ULONG Length;
    HANDLE SectionHandle;
    ULONG SectionOffset;
    SIZE_T ViewSize;    //64位上必须是64位长度
    PVOID ViewBase;
    PVOID ViewRemoteBase;
} PORT_VIEW, * PPORT_VIEW;


typedef
NTSTATUS
(NTAPI* pFuncZwConnectPort)(
    __out PHANDLE PortHandle,
    __in PUNICODE_STRING PortName,
    __in PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    __inout_opt PPORT_VIEW ClientView,
    __inout_opt PREMOTE_PORT_VIEW ServerView,
    __out_opt PULONG MaxMessageLength,
    __inout_opt PVOID ConnectionInformation,
    __inout_opt PULONG ConnectionInformationLength
    );

typedef
NTSTATUS
(NTAPI* pFuncZwRequestWaitReplyPort)(
    __in HANDLE PortHandle,
    __in PPORT_MESSAGE RequestMessage,
    __out PPORT_MESSAGE ReplyMessage
    );
typedef
NTSTATUS
(NTAPI* pFuncZwReplyWaitReceivePort)(
    __in HANDLE PortHandle,
    __out_opt PVOID* PortContext,
    __in_opt PPORT_MESSAGE ReplyMessage,
    __out PPORT_MESSAGE ReceiveMessage
    );
