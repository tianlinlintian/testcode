#pragma once

#define STATUS_UNSUCCESSFUL	0xC0000001

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

//
// Valid values for the Attributes field
//

#define OBJ_INHERIT                         0x00000002L
#define OBJ_PERMANENT                       0x00000010L
#define OBJ_EXCLUSIVE                       0x00000020L
#define OBJ_CASE_INSENSITIVE                0x00000040L
#define OBJ_OPENIF                          0x00000080L
#define OBJ_OPENLINK                        0x00000100L
#define OBJ_KERNEL_HANDLE                   0x00000200L
#define OBJ_FORCE_ACCESS_CHECK              0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x00000800L
#define OBJ_DONT_REPARSE                    0x00001000L
#define OBJ_VALID_ATTRIBUTES                0x00001FF2L

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;
typedef CONST OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( p, n, a, r, s ) {   \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

//
// Valid return values for the PORT_MESSAGE Type file
//

#define LPC_REQUEST             1
#define LPC_REPLY               2
#define LPC_DATAGRAM            3
#define LPC_LOST_REPLY          4
#define LPC_PORT_CLOSED         5
#define LPC_CLIENT_DIED         6
#define LPC_EXCEPTION           7
#define LPC_DEBUG_EVENT         8
#define LPC_ERROR_EVENT         9
#define LPC_CONNECTION_REQUEST  10

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

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;		//32 vs 64
	HANDLE UniqueThread;		//32 vs 64
} CLIENT_ID, *PCLIENT_ID;

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
	};
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct _MYPORT_MESSAGE : public PORT_MESSAGE {
	UCHAR Data[MAX_DATA_LEN];
} MYPORT_MESSAGE, *PMYPORT_MESSAGE;

typedef struct _PORT_VIEW {
	ULONG Length;
	HANDLE SectionHandle;	//32 vs 64
	ULONG SectionOffset;
	SIZE_T ViewSize;		//32 vs 64
	PVOID ViewBase;
	PVOID ViewRemoteBase;
} PORT_VIEW, *PPORT_VIEW;

typedef struct _REMOTE_PORT_VIEW {
	ULONG Length;
	SIZE_T ViewSize;		//32 vs 64
	PVOID ViewBase;
} REMOTE_PORT_VIEW, *PREMOTE_PORT_VIEW;

BOOL LpcInit();
VOID LpcUinit();
DWORD LpcServer(LPCWSTR pwszPortName);
DWORD LpcClient(LPCWSTR pwszPortName);

