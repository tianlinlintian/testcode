#include <Windows.h>
#include <stdio.h>
#include "lpc.h"
#include <TlHelp32.h>
#define TEST_VIEW	1
#include <Aclapi.h> 
#pragma comment (lib,"Advapi32.lib")
#include <Psapi.h>
#include <profileapi.h>
#include <Strsafe.h>
#include <iostream>
#include <Windows.h>
#include <sddl.h>
#include <aclapi.h>
#define CREATE_DIRECTORY 0x03000000
#define MAX_NAME 260


#pragma warning (disable: 4996)

#define OBJ_CASE_INSENSITIVE   0x00000040

#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)

#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)



void SetRegPrivilege(LPSTR NAME)
{
	DWORD dwRet;

	// 下面这个字符串的值修改为想要进行权限操作的注册表项，注册表每一级的权限是不一样的，所以需要很具体地指定到某一级
	LPSTR SamName = NAME;
	PSECURITY_DESCRIPTOR pSD = NULL;
	PACL pOldDacl = NULL;
	PACL pNewDacl = NULL;
	EXPLICIT_ACCESSA ea;
	HKEY hKey = NULL;

	// 获取SAM主键的DACL 
	dwRet = GetNamedSecurityInfoA(SamName, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
		NULL, NULL, &pOldDacl, NULL, &pSD);
	if (dwRet != ERROR_SUCCESS)
	{
		printf("GetNamedSecurityInfo Error: %d\n", dwRet);
		exit(-1);
	}

	// 创建一个ACE，允许Everyone完全控制对象，并允许子对象继承此权限 
	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	BuildExplicitAccessWithNameA(&ea, (char*)"Everyone", KEY_ALL_ACCESS, SET_ACCESS,
		SUB_CONTAINERS_AND_OBJECTS_INHERIT);

	// 将新的ACE加入DACL 
	dwRet = SetEntriesInAclA(1, &ea, pOldDacl, &pNewDacl);
	if (dwRet != ERROR_SUCCESS)
	{
		printf("SetEntriesInAcl Error: %d\n", dwRet);
		exit(-1);
	}

	// 更新SAM主键的DACL 
	dwRet = SetNamedSecurityInfoA(SamName, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
		NULL, NULL, pNewDacl, NULL);
	if (dwRet != ERROR_SUCCESS)
	{
		printf("SetNamedSecurityInfo Error: %d\n", dwRet);
		exit(-1);
	}
}


typedef struct _REPARSE_DATA_BUFFER {
	ULONG  ReparseTag;
	USHORT ReparseDataLength;
	USHORT Reserved;
	union {
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			ULONG Flags;
			WCHAR PathBuffer[1];
		} SymbolicLinkReparseBuffer;
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR PathBuffer[1];
		} MountPointReparseBuffer;
		struct {
			UCHAR  DataBuffer[1];
		} GenericReparseBuffer;
	} DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef VOID(WINAPI* RtlInitUnicodeString_t)(IN OUT PUNICODE_STRING DestinationString,
	IN PCWSTR              SourceString OPTIONAL);
#define InitializeObjectAttributes(i, o, a, r, s) {  \
                (i)->Length = sizeof(OBJECT_ATTRIBUTES); \
                (i)->RootDirectory = r;                  \
                (i)->Attributes = a;                     \
                (i)->ObjectName = o;                     \
                (i)->SecurityDescriptor = s;             \
                (i)->SecurityQualityOfService = NULL;    \
            }
RtlInitUnicodeString_t        RtlInitUnicodeString;

typedef NTSTATUS(WINAPI* NtCreateSymbolicLinkObject_t)(OUT PHANDLE           SymbolicLinkHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PUNICODE_STRING    TargetName);

NtCreateSymbolicLinkObject_t  NtCreateSymbolicLinkObject;

void  CreateSymlink(HANDLE hRoot, LPCWSTR SymbolicLinkName, LPCWSTR TargetName) {
	HANDLE SymbolicLinkHandle = NULL;
	UNICODE_STRING TargetObjectName = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	UNICODE_STRING SymbolicLinkObjectName = { 0 };

	LPCSTR nt = "ntdll";
	HMODULE hntdll = GetModuleHandleA(nt);
	RtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddress(hntdll, "RtlInitUnicodeString");
	NtCreateSymbolicLinkObject = (NtCreateSymbolicLinkObject_t)GetProcAddress(hntdll, "NtCreateSymbolicLinkObject");

	RtlInitUnicodeString(&SymbolicLinkObjectName, SymbolicLinkName);
	RtlInitUnicodeString(&TargetObjectName, TargetName);

	InitializeObjectAttributes(&ObjectAttributes,
		&SymbolicLinkObjectName,
		OBJ_CASE_INSENSITIVE,
		hRoot,
		NULL);

	int NtStatus = NtCreateSymbolicLinkObject(&SymbolicLinkHandle,
		SYMBOLIC_LINK_ALL_ACCESS,
		&ObjectAttributes,
		&TargetObjectName);

	if (NtStatus != 0) {
		printf("\t\t[-] 设置符号链接失败: 0x%X\n", NtStatus);
		exit(-1);
	}

}


HANDLE GetProcessHandle(LPCWSTR lpName)
{
	DWORD dwPid = 0;
	HANDLE hProcess = NULL;
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("Error: CreateToolhelp32Snapshot (of processes)\r\n");
		return NULL;
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	 // and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		printf("Error: Process32First\r\n"); // show cause of failure
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return NULL;
	}

	// Now walk the snapshot of processes, and
	 // display information about each process in turn
	int namelen = 200;
	char name[201] = { 0 };
	do
	{
		if (!wcscmp(pe32.szExeFile, lpName)) {
			dwPid = pe32.th32ProcessID;
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
			break;
		}

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return hProcess;
}
HMODULE g_hNtDLL = NULL;


NTSTATUS
(NTAPI* ZwCreatePort)(
	__out PHANDLE PortHandle,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in ULONG MaxConnectionInfoLength,
	__in ULONG MaxMessageLength,
	__in_opt ULONG MaxPoolUsage
	);

NTSTATUS
(NTAPI* ZwListenPort)(
	__in HANDLE PortHandle,
	__in PPORT_MESSAGE ConnectMsg
	);

NTSTATUS
(NTAPI* ZwReplyWaitReceivePort)(
	__in HANDLE PortHandle,
	__out_opt PVOID* PortContext,
	__in_opt PPORT_MESSAGE ReplyMessage,
	__out PPORT_MESSAGE ReceiveMessage
	);

NTSTATUS
(NTAPI* ZwAcceptConnectPort)(
	__out PHANDLE PortHandle,
	__in_opt PVOID PortContext,
	__in PPORT_MESSAGE ConnectionRequest,
	__in BOOLEAN AcceptConnection,
	__inout_opt PPORT_VIEW ServerView,
	__out_opt PREMOTE_PORT_VIEW ClientView
	);

NTSTATUS
(NTAPI* ZwCompleteConnectPort)(
	__in HANDLE PortHandle
	);

NTSTATUS
(NTAPI* ZwReplyPort)(
	__in HANDLE PortHandle,
	__in PPORT_MESSAGE LpcReply
	);

NTSTATUS
(NTAPI* ZwConnectPort)(
	__out PHANDLE PortHandle,
	__in PUNICODE_STRING PortName,
	__in PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	__inout_opt PPORT_VIEW ClientView,
	__inout_opt PREMOTE_PORT_VIEW ServerView,
	__out_opt PULONG MaxMessageLength,
	__inout_opt PVOID ConnectionInformation,
	__inout_opt PULONG ConnectionInformationLength
	);

NTSTATUS
(NTAPI* ZwRequestWaitReplyPort)(
	__in HANDLE PortHandle,
	__in PPORT_MESSAGE RequestMessage,
	__out PPORT_MESSAGE ReplyMessage
	);

NTSTATUS
(NTAPI* NtCreateSection)(
	OUT PHANDLE SectionHandle,
	IN  ACCESS_MASK DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN  PLARGE_INTEGER MaximumSize OPTIONAL,
	IN  ULONG SectionPageProtection,
	IN  ULONG AllocationAttributes,
	IN  HANDLE FileHandle OPTIONAL
	);

NTSTATUS
(NTAPI* ZwClose)(
	HANDLE Handle
	);

BOOL LpcInit()
{
	g_hNtDLL = GetModuleHandleW(L"ntdll.dll");
	if (g_hNtDLL == NULL)
		return FALSE;

	(FARPROC&)RtlInitUnicodeString =
		GetProcAddress(g_hNtDLL, "RtlInitUnicodeString");

	(FARPROC&)ZwCreatePort =
		GetProcAddress(g_hNtDLL, "ZwCreatePort");

	(FARPROC&)ZwListenPort =
		GetProcAddress(g_hNtDLL, "ZwListenPort");

	(FARPROC&)ZwReplyWaitReceivePort =
		GetProcAddress(g_hNtDLL, "ZwReplyWaitReceivePort");

	(FARPROC&)ZwAcceptConnectPort =
		GetProcAddress(g_hNtDLL, "ZwAcceptConnectPort");

	(FARPROC&)ZwCompleteConnectPort =
		GetProcAddress(g_hNtDLL, "ZwCompleteConnectPort");

	(FARPROC&)ZwReplyPort =
		GetProcAddress(g_hNtDLL, "ZwReplyPort");

	(FARPROC&)ZwConnectPort =
		GetProcAddress(g_hNtDLL, "ZwConnectPort");

	(FARPROC&)ZwRequestWaitReplyPort =
		GetProcAddress(g_hNtDLL, "ZwRequestWaitReplyPort");

	(FARPROC&)NtCreateSection =
		GetProcAddress(g_hNtDLL, "NtCreateSection");

	(FARPROC&)ZwClose =
		GetProcAddress(g_hNtDLL, "ZwClose");

	if (!RtlInitUnicodeString || !ZwCreatePort ||
		!ZwListenPort || !ZwReplyWaitReceivePort || !ZwAcceptConnectPort ||
		!ZwCompleteConnectPort || !ZwReplyPort || !ZwConnectPort || !ZwRequestWaitReplyPort ||
		!NtCreateSection || !ZwClose)
	{
		return FALSE;
	}

	return TRUE;
}



int EnableFileAccountPrivilege(const CHAR* pszPath, const CHAR* pszAccount)
{
	BOOL bSuccess = TRUE;
	EXPLICIT_ACCESSA ea;
	PACL pNewDacl = NULL;
	PACL pOldDacl = NULL;
	do
	{
		// 获取文件(夹)安全对象的DACL列表

		if (ERROR_SUCCESS != GetNamedSecurityInfoA(pszPath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDacl, NULL, NULL))
		{
			bSuccess = FALSE;
			break;
		}

		// 此处不可直接用AddAccessAllowedAce函数,因为已有的DACL长度是固定,必须重新创建一个DACL对象

		// 生成指定用户帐户的访问控制信息(这里指定赋予全部的访问权限)

		::BuildExplicitAccessWithNameA(&ea, (CHAR*)pszAccount, GENERIC_ALL, GRANT_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);

		// 创建新的ACL对象(合并已有的ACL对象和刚生成的用户帐户访问控制信息)

		if (ERROR_SUCCESS != ::SetEntriesInAclA(1, &ea, pOldDacl, &pNewDacl))
		{
			bSuccess = FALSE;
			break;
		}

		// 设置文件(夹)安全对象的DACL列表
		if (ERROR_SUCCESS != ::SetNamedSecurityInfoA((CHAR*)pszPath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDacl, NULL))
		{
			bSuccess = FALSE;
		}

		//还原
		::SetNamedSecurityInfoA((CHAR*)pszPath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pOldDacl, NULL);

	} while (FALSE);

		if (NULL != pNewDacl)
		{
			::LocalFree(pNewDacl);
		}

		return bSuccess;
}



//判断是否有WRITE_DAC权限以及是否是所有者
BOOL IsDirectoryWrite(CHAR* filePath, ULONG type)
{

	if (EnableFileAccountPrivilege(filePath, "ztl"))
	{
		return 1;
	}
	//SECURITY_INFORMATION  securityInfo = DACL_SECURITY_INFORMATION;
	//SECURITY_DESCRIPTOR test;
	//SECURITY_DESCRIPTOR* pSecurityDes = &test;
	//DWORD needBuffer;
	//BOOL need;


	////获取需要的内存大小
	//GetFileSecurityA(filePath, securityInfo, NULL, 0, &needBuffer);

	//
	//if (needBuffer <= 0)
	//{
	//	return 0;
	//}

	//CHAR UserName[36] = { 0 };
	//// LookupAccountName函数所需要的变量
	//DWORD cbUserName = sizeof(UserName);

	//GetUserNameA(UserName, &cbUserName);

	//GetFileSecurityA(filePath, securityInfo, pSecurityDes, needBuffer, &needBuffer);
	//if (pSecurityDes == NULL)
	//{
	//	return 0;
	//}

	//char ownerSID[MAX_NAME] = "";

	//
	//CHAR Sid[1024] = { 0 };
	//DWORD cbSid = sizeof(Sid);
	//CHAR DomainBuffer[128] = { 0 };
	//DWORD cbDomainBuffer = sizeof(DomainBuffer);
	//SID_NAME_USE eUse;



	////获取用户名SID
	//char sid[MAX_NAME] = "";

	//DWORD sidSize = sizeof(Sid);
	//DWORD domainSize = sizeof(cbDomainBuffer);

	//LookupAccountNameA(
	//	NULL, UserName, &Sid,
	//	&cbSid, DomainBuffer, &cbDomainBuffer, &eUse);

	////PSID_IDENTIFIER_AUTHORITY psia = GetSidIdentifierAuthority(Sid);
	////sidSize = sprintf(sid, "S-%lu-", SID_REVISION);
	////sidSize += sprintf(sid + strlen(sid), "%-lu", psia->Value[5]);

	////int i = 0;
	////int subAuthorities = *GetSidSubAuthorityCount(Sid);
	////if (GetLastError() != 0)
	////{
	////	printf("[-] 无法获取安全5\n");
	////	return 0;
	////}
	////for (i = 0; i < subAuthorities; i++)
	////{
	////	sidSize += sprintf(sid + sidSize, "-%lu", *GetSidSubAuthority(Sid, i));
	////}
	////printf("%s\n",sid);

	//if (GetSecurityDescriptorOwner(pSecurityDes, (PSID*)&ownerSID, &need))
	//{
	//	if (type)
	//	{
	//		// 更改所有者 如果能更改则代表是所有者
	//		if (!SetNamedSecurityInfoA
	//		(filePath,
	//			SE_FILE_OBJECT, /* 注册表为:SE_REGISTRY_KEY */
	//			OWNER_SECURITY_INFORMATION, /* 更改所有者 */
	//			&Sid, /* 需要更改所有者的SID */
	//			NULL, NULL, NULL))
	//		{
	//			return 1;
	//		}
	//	}
	//	else
	//	{
	//		// 更改所有者 如果能更改则代表是所有者
	//		if (!SetNamedSecurityInfoA
	//		(filePath,
	//			SE_REGISTRY_KEY, /* 注册表为:SE_REGISTRY_KEY */
	//			OWNER_SECURITY_INFORMATION, /* 更改所有者 */
	//			&Sid, /* 需要更改所有者的SID */
	//			NULL, NULL, NULL))
	//		{
	//			return 1;
	//		}
	//	}

	//}


	//DWORD dwRtnCode = 0;
	//PSID pSidOwner = NULL;
	//BOOL bRtnBool = TRUE;
	//CHAR* AcctName = NULL;
	//CHAR* DomainName = NULL;
	//DWORD dwAcctName = 1, dwDomainName = 1;
	//HANDLE hFile;
	//PSECURITY_DESCRIPTOR pSD = NULL;

	//// Get the handle of the file object.
	//hFile = CreateFileA(
	//	filePath,
	//	GENERIC_READ,
	//	FILE_SHARE_READ,
	//	NULL,
	//	OPEN_EXISTING,
	//	FILE_FLAG_BACKUP_SEMANTICS,
	//	NULL);

	//// Check GetLastError for CreateFile error code.
	//if (hFile == INVALID_HANDLE_VALUE) {
	//	DWORD dwErrorCode = 0;
	//	printf("[-] 无法获取安全4\n");
	//	return -1;
	//}

	//// Get the owner SID of the file.
	//dwRtnCode = GetSecurityInfo(
	//	hFile,
	//	SE_FILE_OBJECT,
	//	OWNER_SECURITY_INFORMATION,
	//	&pSidOwner,
	//	NULL,
	//	NULL,
	//	NULL,
	//	&pSD);

	//CloseHandle(hFile);

	//// Check GetLastError for GetSecurityInfo error condition.
	//if (dwRtnCode != ERROR_SUCCESS) {
	//	DWORD dwErrorCode = 0;
	//	printf("[-] 无法获取安全3\n");
	//	return -1;
	//}

	//// First call to LookupAccountSid to get the buffer sizes.
	//bRtnBool = LookupAccountSidA(
	//	NULL,           // local computer
	//	pSidOwner,
	//	AcctName,
	//	(LPDWORD)&dwAcctName,
	//	DomainName,
	//	(LPDWORD)&dwDomainName,
	//	&eUse);

	//// Reallocate memory for the buffers.
	//AcctName = (char*)GlobalAlloc(
	//	GMEM_FIXED,
	//	dwAcctName);


	//DomainName = (char*)GlobalAlloc(
	//	GMEM_FIXED,
	//	dwDomainName);

	//// Second call to LookupAccountSid to get the account name.
	//bRtnBool = LookupAccountSidA(
	//	NULL,                   // name of local or remote computer
	//	pSidOwner,              // security identifier
	//	AcctName,               // account name buffer
	//	(LPDWORD)&dwAcctName,   // size of account name buffer 
	//	DomainName,             // domain name
	//	(LPDWORD)&dwDomainName, // size of domain name buffer
	//	&eUse);                 // SID type

	//if (!strcmp(AcctName, UserName))
	//{
	//	return 2;
	//}

	//if (AcctName)
	//{
	//	free(AcctName);
	//}
	//if (DomainName)
	//{
	//	free(DomainName);
	//}



	////ACL变量，安全信息链表指针
	//PACL  pACL = NULL;
	//BOOL DaclPresent;
	//BOOL DaclDefault;
	//GetSecurityDescriptorDacl(pSecurityDes, &DaclPresent, &pACL, &DaclDefault);
	//if (GetLastError() != 0)
	//{
	//	printf("[-] 无法获取安全2\n");
	//	return 0;
	//}
	////获取ACl所有信息
	//ACL_SIZE_INFORMATION AclInfo;
	//AclInfo.AceCount = 0;
	//AclInfo.AclBytesFree = 0;
	//AclInfo.AclBytesInUse = sizeof(ACL);

	//GetAclInformation(pACL, &AclInfo, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation);
	//if (GetLastError() != 0)
	//{
	//	printf("[-] 无法获取安全1\n");
	//	return 0;
	//}
	////每个ACE信息
	//LPVOID pTempAce = NULL;
	//BYTE nAceType;
	//if (DaclPresent && AclInfo.AceCount)
	//{
	//	for (int i = 0; i < AclInfo.AceCount; i++)
	//	{
	//		GetAce(pACL, i, &pTempAce);
	//		nAceType = ((ACCESS_ALLOWED_ACE*)pTempAce)->Header.AceType;

	//		char* stringsid;
	//		if (nAceType == ACCESS_MIN_MS_ACE_TYPE)
	//		{
	//			PSID sid2 = (SID*)&((ACCESS_DENIED_ACE*)pTempAce)->SidStart;
	//			ConvertSidToStringSidA(sid2, &stringsid);
	//			//获取当前用户sid对应的alc的mask
	//			if (!strcmp(sid, stringsid))
	//			{
	//				//    printf("%s\n", sid);
	//					//文件请求的标准访问权限
	//				ULONG GDesiredAccess = ((ACCESS_ALLOWED_ACE*)pTempAce)->Mask & 0xff000000;
	//				//文件请求的SACL访问权限
	//				ULONG SDesiredAccess = (((ACCESS_ALLOWED_ACE*)pTempAce)->Mask - GDesiredAccess) & 0xff0000;
	//				//如果有WRITE_DAC
	//				if (SDesiredAccess == WRITE_DAC | READ_CONTROL ||
	//					SDesiredAccess == WRITE_DAC | SYNCHRONIZE ||
	//					SDesiredAccess == WRITE_DAC | DELETE ||
	//					SDesiredAccess == WRITE_DAC ||
	//					SDesiredAccess == WRITE_DAC | DELETE | SYNCHRONIZE ||
	//					SDesiredAccess == WRITE_DAC | READ_CONTROL | SYNCHRONIZE ||
	//					SDesiredAccess == WRITE_DAC | DELETE | READ_CONTROL 

	//		/*			SDesiredAccess == DELETE ||
	//					SDesiredAccess == DELETE | SYNCHRONIZE ||
	//					SDesiredAccess == DELETE | READ_CONTROL ||
	//					SDesiredAccess == DELETE | READ_CONTROL | SYNCHRONIZE*/
	//					)
	//				{
	//					return 2;
	//				}
	//			}
	//		}
	//	}
	//}

	return 0;
}

#define BLUE "\033[0;32;34m"

//传入要遍历的文件夹路径
BOOL TraverseDirectory(wchar_t Dir[MAX_PATH], wchar_t Dir2[MAX_PATH])
{
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	wchar_t DirSpec[MAX_PATH];                  //定义要遍历的文件夹的目录
	DWORD dwError;
	StringCchCopy(DirSpec, MAX_PATH, Dir);
	StringCchCat(DirSpec, MAX_PATH, TEXT("\\*"));   //定义要遍历的文件夹的完整路径\*

	hFind = FindFirstFile(DirSpec, &FindFileData);          //找到文件夹中的第一个文件

	if (hFind == INVALID_HANDLE_VALUE)                               //如果hFind句柄创建失败，输出错误信息
	{
		FindClose(hFind);
	}
	else
	{
		while (FindNextFile(hFind, &FindFileData) != 0)                            //当文件或者文件夹存在时
		{
			if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 && wcscmp(FindFileData.cFileName, L".") == 0 || wcscmp(FindFileData.cFileName, L"..") == 0)        //判断是文件夹&&表示为"."||表示为"."
			{
				continue;
			}
			if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)      //判断如果是文件夹
			{

				wchar_t DirAdd[MAX_PATH];
				StringCchCopy(DirAdd, MAX_PATH, Dir);
				StringCchCat(DirAdd, MAX_PATH, TEXT("\\"));
				StringCchCat(DirAdd, MAX_PATH, FindFileData.cFileName);       //拼接得到此文件夹的完整路径
				//如果是这次操作irp的文件目录则直接无视
				if (!wcscmp(DirAdd, Dir2))
				{
					continue;
				}
				if (TraverseDirectory(DirAdd, Dir2) == 0) //实现递归调用
				{
					return 0;
				}
				HANDLE hFile = CreateFileW(DirAdd,      //第一个参数:路径
					DELETE,                       //打开方式:
					0,                                  //共享模式:0为独占  
					NULL,
					OPEN_EXISTING,                      //打开已存在的文件
					FILE_FLAG_BACKUP_SEMANTICS,         //FILE_FLAG_BACKUP_SEMANTICS表示为目录，NULL表示文件
					NULL);
				if (hFile == INVALID_HANDLE_VALUE)
				{
					return 0;
				}
				CloseHandle(hFile);
			}

			if ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)    //如果不是文件夹
			{
				WCHAR path[1000] = { 0 };
				wcscpy(path, Dir);
				wcscat(path, L"\\");
				wcscat(path, FindFileData.cFileName);
				HANDLE hFILE = CreateFileW(path, DELETE, 0, NULL, OPEN_EXISTING, NULL, NULL);
				if (hFILE == INVALID_HANDLE_VALUE)
				{
					return 0;
				}
				CloseHandle(hFILE);
			}
		}
		FindClose(hFind);
	}

	return 1;
}

VOID LpcUinit()
{
	if (g_hNtDLL != NULL)
	{
		FreeLibrary(g_hNtDLL);
	}
}

int checkstr(char* s, char* t, int flag, int lenstr)
{
	char* q;
	for (; *(s + lenstr); s++)
	{
		if (flag)  // 不区分大小写
		{
			for (q = t; (*s == *q || *s - 32 == *q || *s + 32 == *q) && *q; s++, q++)
				;

		}
		else  //区分大小写
		{
			for (q = t; *s == *q && *q; s++, q++)
				;
		}

		if (!*q)
		{
			return 1;
		}
	}

	return 0;
}

VOID Log(const CHAR* path, const CHAR* buf, ULONG Type) {
	HANDLE hd = CreateFileA(path, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dwHigh;
	SetFilePointer(hd, 0, NULL, FILE_END);
	DWORD dwWritenSize = 0;
	WriteFile(hd, " boomboomboom!!!\r\n", sizeof(" boomboomboom!!!\r\n"), &dwWritenSize, NULL);
	WriteFile(hd, "   文件名 :", sizeof("   文件名 :"), &dwWritenSize, NULL);
	WriteFile(hd, (char*)&buf[2], strlen((char*)&buf[2]), &dwWritenSize, NULL);
	WriteFile(hd, "   进程名 :", sizeof("   进程名 :"), &dwWritenSize, NULL);
	WriteFile(hd, (char*)&buf[260], strlen((char*)&buf[260]), &dwWritenSize, NULL);
	WriteFile(hd, "\r\n    进程id :", sizeof("\r\n    进程id :"), &dwWritenSize, NULL);
	WriteFile(hd, (char*)&buf[260] + strlen((char*)&buf[260]) + 2, 6, &dwWritenSize, NULL);
	switch (buf[MAX_DATA_LEN - 2])
	{
	case DACL_SECURITY_INFORMATION:
		WriteFile(hd, " 访问控制列表(DACL)", sizeof(" 访问控制列表(DACL)"), &dwWritenSize, NULL);
		break;
	case GROUP_SECURITY_INFORMATION:
		WriteFile(hd, " 所属组", sizeof(" 所属组"), &dwWritenSize, NULL);
		break;
	case OWNER_SECURITY_INFORMATION:
		WriteFile(hd, " 拥有者", sizeof(" 拥有者"), &dwWritenSize, NULL);
		break;
	case SACL_SECURITY_INFORMATION:
		WriteFile(hd, " 审核控制列表(SACL)", sizeof(" 审核控制列表(SACL)"), &dwWritenSize, NULL);
		break;
	}
	if (Type)
	{
		WriteFile(hd, "   所在目录有部分文件没有写入权限或者正在被其他程序独占中", sizeof("   所在目录有部分文件没有写入权限或者正在被其他程序独占中"), &dwWritenSize, NULL);
	}
	else
	{
		WriteFile(hd, "   可以直接设置符号链接", sizeof("   可以直接设置符号链接"), &dwWritenSize, NULL);
	}


	WriteFile(hd, "\r\n", sizeof("\r\n"), &dwWritenSize, NULL);

	CloseHandle(hd);
}
DWORD LpcServer(LPCWSTR pwszPortName)
{

	NTSTATUS			status = STATUS_UNSUCCESSFUL;
#ifdef TEST_VIEW
	HANDLE				m_SectionHandle;	// 共享内存句柄
	PORT_VIEW			m_ServerView;		// 服务端共享内存映射
	REMOTE_PORT_VIEW	m_ClientView = { 0 };		// 客户端共享内存映射
	LARGE_INTEGER		m_SectionSize = { LARGE_MESSAGE_SIZE };

	status = NtCreateSection(&m_SectionHandle,
		SECTION_ALL_ACCESS,
		NULL,
		&m_SectionSize,
		PAGE_READWRITE,
		SEC_COMMIT,
		NULL);

	if (!NT_SUCCESS(status))
	{
		printf("ZwCreateSection failed, st=%x\n", status);
		return status;
	}

	// 初始化用于服务端写入的PORT_VIEW
	m_ServerView.Length = sizeof(PORT_VIEW);   //必须是此值
	m_ServerView.SectionHandle = m_SectionHandle;
	m_ServerView.SectionOffset = 0;
	m_ServerView.ViewSize = (ULONG)LARGE_MESSAGE_SIZE;

	// 初始化用于读取客户端REMOTE_PORT_VIEW
	m_ClientView.Length = sizeof(REMOTE_PORT_VIEW);
#endif
	DWORD nError;
	HANDLE				hPortServer = INVALID_HANDLE_VALUE;
	HANDLE				hPortClient = INVALID_HANDLE_VALUE;
	UNICODE_STRING		ustrPortName;
	OBJECT_ATTRIBUTES	ObjectAttr = { 0 };

	// 初始化对象属性结构
	RtlInitUnicodeString(&ustrPortName, pwszPortName);

	InitializeObjectAttributes(&ObjectAttr, &ustrPortName, 0, NULL, NULL);

	// 创建命名端口. 
	status = ZwCreatePort(&hPortServer, &ObjectAttr, sizeof(PORT_MESSAGE), sizeof(MYPORT_MESSAGE), 0);
	if (status != 0) {
		//若失败请以system权限启动该程序
		printf("[-] 创建命名端口失败，请尝试以system权限启动该程序\n");
		nError = GetLastError();
		return nError;
	}
	else
	{
		printf("[+] 创建命名端口成功\n");
	}
	HANDLE tokenHandle = NULL;

	//模拟explorer.exe
	HANDLE processHandle = GetProcessHandle(L"explorer.exe");


	// 获取指定进程的句柄令牌
	BOOL getToken = OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tokenHandle);
	if (tokenHandle != NULL)
		printf("[+] 打开explorer进程句柄成功!\n");
	else
	{

		printf("[-] 打开explorer进程句柄失败 错误代码: %i\n", GetLastError());
		exit(-1);
	}
	//模拟一个登陆用户的访问令牌的安全上下文
	BOOL impersonateUser = ImpersonateLoggedOnUser(tokenHandle);
	if (impersonateUser != NULL)
	{
		//如果模拟成功则应该是medium权限，看看在C:\\Windows\\System32上是否会创建文件
		HANDLE hFILE = CreateFileA("C:\\Windows\\System32\\1.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFILE == INVALID_HANDLE_VALUE)
		{
			printf("[+] 模拟explorer.exe成功!\n");
		}
		else
		{
			printf("[-] explorer有问题\n");
			exit(-1);
		}
	}
	else
	{
		printf("[-] 模拟explorer.exe失败 : %i\n", getToken);
		exit(-1);
	}

	printf("[+] 此时可启动驱动程序!\n");
	MYPORT_MESSAGE    RecvPortMsg;

	//MYPORT_MESSAGE    ReplyPortMsg;
	//memset(&ReplyPortMsg, 0, sizeof(ReplyPortMsg));
	//printf("MYPORT_MESSAGE size:%zu %zu\n", sizeof(MYPORT_MESSAGE), sizeof(PORT_MESSAGE));

	short msg_type = 0;
	while (1)
	{
		printf("\n-----------------------------------------\n");
		memset(&RecvPortMsg, 0, sizeof(RecvPortMsg));
		status = ZwReplyWaitReceivePort(hPortServer, NULL/*(PVOID*)&Ctxt*/, NULL, &RecvPortMsg);
		//status = ZwListenPort(hPortServer, &RecvPortMsg);
		if (status != 0) {
			printf("LpcReplyWaitReceivePort failed: 0x%08x\n", status);
			break;
		}

		msg_type = RecvPortMsg.Type;
		/*printf("msg_type: %d \n", msg_type);
		printf("RecvPortMsg.DataLength %d\n", RecvPortMsg.DataLength);
		printf("RecvPortMsg.TotalLength:%d\n", RecvPortMsg.TotalLength);
		printf("RecvPortMsg.UniqueProcess:%zu\n", (SIZE_T)RecvPortMsg.ClientId.UniqueProcess);
		printf("RecvPortMsg.UniqueThread:%zu\n", (SIZE_T)RecvPortMsg.ClientId.UniqueThread);*/

		switch (msg_type)
		{
		case LPC_CONNECTION_REQUEST:
			//printf("recv Msg: %s \n", (LPSTR)RecvPortMsg.Data);

			// 填写发送数据.
			lstrcpyA((LPSTR)RecvPortMsg.Data, "reply");

			// 获得连接请求.
#ifdef TEST_VIEW
			status = ZwAcceptConnectPort(
				&hPortClient,
				NULL,
				&RecvPortMsg,
				TRUE, // 接受
				NULL/*&m_ServerView*/,
				&m_ClientView);
#else
			status = ZwAcceptConnectPort(
				&hPortClient,
				NULL,
				&RecvPortMsg,
				TRUE, // 接受
				NULL/*&m_ServerView*/,
				NULL/*&m_ClientView*/);
#endif

			if (status != 0) {
				printf("LpcAcceptConnectPort failed, status=%x\n", status);
				break;
			}
			//	printf("LpcAcceptConnectPort ok\n");

				//printf("m_ClientView.ViewSize: %d\n", m_ClientView.ViewSize);
				//printf("m_ClientView.Length: %d\n", m_ClientView.Length);
				//printf("m_ClientView.ViewBase: %p\n", m_ClientView.ViewBase);

			status = ZwCompleteConnectPort(hPortClient);
			if (status != 0) {
				CloseHandle(hPortClient);
				printf("LpcCompleteConnectPort failed, status=%x\n", status);
				break;
			}
			printf("[+] 驱动连接端口成功 接下来以medium启动test.exe 否则驱动不开始过滤工作!\n");
			break;

		case LPC_REQUEST:
		{
			lstrcpyA((LPSTR)m_ClientView.ViewBase, "mapview");
			//如果驱动发送过来的消息是任意文件写入那么就先判断该文件所在目录是否有写入权限
			char Dir[0x1000];
			strcpy(Dir, (char*)&RecvPortMsg.Data[2]);
			ULONG type = 0;
			if (RecvPortMsg.Data[0] == '@')
			{
				if (RecvPortMsg.Data[1] == '1')
				{
					printf("[+] 高权限进程正在创建可写目录: %s \n", (char*)&RecvPortMsg.Data[2]);
					type = 1;
				}
				else if (RecvPortMsg.Data[1] == '2')
				{
					printf("[+] 无法在内核判断的目录: %s \n", (char*)&RecvPortMsg.Data[2]);
					type = 2;

				}
				else if (RecvPortMsg.Data[1] == '3')
				{
					printf("[+] 高权限进程正在删除文件: %s \n", (char*)&RecvPortMsg.Data[2]);
					type = 3;
				}
				else if (RecvPortMsg.Data[1] == '4')
				{
					printf("[+] 高权限进程设置文件安全属性: %s \n", (char*)&RecvPortMsg.Data[2]);
					type = 4;
				}
				wchar_t  wss[0x1000];
				swprintf(wss, 0x1000, L"%hs", Dir);
				for (size_t i = strlen(Dir); i > 0; i--)
				{
					if (Dir[i] == '\\')
					{
						Dir[i] = 0;
						break;
					}
				}
				ULONG save = 0;

				printf("[+] 检查是否可以对%s设置符号链接\n", Dir);

				//是否能创建该文件所在的目录 如果目录已存在再进一步判断
				HANDLE hFILE = 0;
				ULONG ret = 0;
				CreateDirectoryA(Dir, 0);
				ULONG er = GetLastError();
				//如果文件所在目录不存在那么则往上级一层层创建直到创建成功或者提示拒绝访问
				if (er == 2 || er == 3)
				{
					while (true)
					{
						for (size_t i = strlen(Dir); i > 0; i--)
						{
							if (Dir[i] == '\\')
							{
								Dir[i] = 0;
								break;
							}
						}
						CreateDirectoryA(Dir, 0);
						ULONG er = GetLastError();
						if (er != 2 && er != 3)
						{
							//	printf("%d\n", er);
							break;
						}
						else if (er == 5)
						{
							printf("[-] 该文件所在目录没有写入权限 不做记录\n");
							memset(RecvPortMsg.Data, 0x00, MAX_DATA_LEN - 1);
							ZwReplyPort(hPortServer, &RecvPortMsg);
							break;
						}
					}
				}
				if (er != 0 && er != 5)
				{
					hFILE = CreateFileA(Dir, DELETE, FILE_SHARE_DELETE | FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

					//如果没有DELETE权限也没有WRITE_DAC权限也不是所有者
					if (hFILE == INVALID_HANDLE_VALUE && !IsDirectoryWrite(Dir, 1))
					{
						printf("[-] 该文件所在目录没有写入权限 不做记录\n");
						memset(RecvPortMsg.Data, 0x00, MAX_DATA_LEN - 1);
						ZwReplyPort(hPortServer, &RecvPortMsg);
						break;
					}
					CloseHandle(hFILE);


					wchar_t  ws[0x1000];
					swprintf(ws, 0x1000, L"%hs", Dir);
					//为了能创建符号链接，必须先确保该目录下没有文件 否则设置挂载点将会返回错误145 
					if (!TraverseDirectory(ws, wss))
					{
						printf("[+++] 该文件所在目录下有部分文件没有写入权限或者正在被其他程序独占中 已记录\n");
						CHAR buf[MAX_DATA_LEN];
						memcpy(&buf[2], (char*)&RecvPortMsg.Data[2], MAX_DATA_LEN - 2);

						if (type == 1)
						{
							Log("C:\\Users\\ztl\\Desktop\\BoomUsersCreate.txt", buf, 1);
						}
						else if (type == 3)
						{
							Log("C:\\Users\\ztl\\Desktop\\BoomUsersCL2.txt", buf, 1);
						}
						else if (type == 2)
						{
							Log("C:\\Users\\ztl\\Desktop\\BoomUsersCreate2.txt", buf, 1);
						}
						else if (type == 4)
						{
							Log("C:\\Users\\ztl\\Desktop\\BoomSecurity.txt", buf, 1);
						}
						type = 0;
						memset(RecvPortMsg.Data, 0xf6, MAX_DATA_LEN - 1);
						ZwReplyPort(hPortServer, &RecvPortMsg);
						break;
					}
					else
					{
						save = 1;
					}
				}
				else
				{
					save = 1;
				}
				if (save == 1)
				{
					CHAR buf[MAX_DATA_LEN];
					memcpy(&buf[2], (char*)&RecvPortMsg.Data[2], MAX_DATA_LEN - 2);
					printf("[+++] 该文件所在目录可以设置符号链接  已记录\n");
					if (type == 1)
					{
						Log("C:\\Users\\ztl\\Desktop\\BoomUsersCreate.txt", buf, 0);
					}
					else if (type == 3)
					{
						Log("C:\\Users\\ztl\\Desktop\\BoomUsersCL2.txt", buf, 0);
					}
					else if (type == 2)
					{
						Log("C:\\Users\\ztl\\Desktop\\BoomUsersCreate2.txt", buf, 0);
					}
					else if (type == 4)
					{
						Log("C:\\Users\\ztl\\Desktop\\BoomSecurity.txt", buf, 0);
					}
					type = 0;
					memset(RecvPortMsg.Data, 0xff, MAX_DATA_LEN - 1);
					ZwReplyPort(hPortServer, &RecvPortMsg);
				}
			}
			else
			{
				printf("[+] %s \n", (LPSTR)RecvPortMsg.Data);

				// 填写发送数据.
				//lstrcpyA((LPSTR)&RecvPortMsg + dataOffset, "111111");
				memset(RecvPortMsg.Data, 0, MAX_DATA_LEN - 1);
				ZwReplyPort(hPortServer, &RecvPortMsg);
			}


			//	printf("ZwReplyPort ok\n");
		}
		break;
		case LPC_PORT_CLOSED:
			if (hPortClient != INVALID_HANDLE_VALUE)
			{
				CloseHandle(hPortClient);
				hPortClient = INVALID_HANDLE_VALUE;
			}
			break;
		default:
			printf("othre type: %d\n", msg_type);
			break;
		}
	}

	CloseHandle(hPortServer);
	//Once the handle pointed to by SectionHandle is no longer in use, the driver must call ZwClose to close it.
	ZwClose(m_SectionHandle);

	nError = GetLastError();
	return nError;
}

DWORD LpcClient(LPCWSTR pwszPortName)
{
	NTSTATUS			status;
#ifdef TEST_VIEW
	HANDLE				m_SectionHandle;	// 共享内存句柄
	PORT_VIEW			m_ClientView = { 0 };		// 服务端共享内存映射
	REMOTE_PORT_VIEW	m_ServerView = { 0 };		// 客户端共享内存映射
	LARGE_INTEGER		m_SectionSize = { LARGE_MESSAGE_SIZE };

	//If the call to this function occurs in user mode, you should
	//use the name "NtCreateSection" instead of "ZwCreateSection".
	status = NtCreateSection(&m_SectionHandle,
		SECTION_ALL_ACCESS,
		NULL,
		&m_SectionSize,
		PAGE_READWRITE,
		SEC_COMMIT,
		NULL);
	if (!NT_SUCCESS(status))
	{
		printf("ZwCreateSection failed, st=%x\n", status);
		return status;
	}

	// 初始化用于客户端写入的PORT_VIEW
	m_ClientView.Length = sizeof(PORT_VIEW);    //必须是此值
	m_ClientView.SectionHandle = m_SectionHandle;
	m_ClientView.SectionOffset = 0;
	m_ClientView.ViewSize = (ULONG)LARGE_MESSAGE_SIZE;

	// 初始化用于读取服务REMOTE_PORT_VIEW
	m_ServerView.Length = sizeof(REMOTE_PORT_VIEW);
#endif	
	DWORD nError;
	HANDLE				hClientPort;
	UNICODE_STRING		ustrPortName;

	// 初始化对象属性结构.
	RtlInitUnicodeString(&ustrPortName, pwszPortName);

	SECURITY_QUALITY_OF_SERVICE sqos;
	sqos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
	sqos.ImpersonationLevel = SecurityImpersonation;
	sqos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
	sqos.EffectiveOnly = FALSE;

	//ULONG len = FIELD_OFFSET(LPC_MESSAGE, Data) + MAX_DATA_LEN;
	char ConnectDataBuffer[MAX_DATA_LEN];
	strcpy_s(ConnectDataBuffer, MAX_DATA_LEN, "123");
	ULONG Size = sizeof(ConnectDataBuffer);

	ULONG		max_msglen = 0;
	//m_ClientView.Length = sizeof("send");

#ifdef TEST_VIEW
	status = ZwConnectPort(&hClientPort,
		&ustrPortName,
		&sqos,
		&m_ClientView,
		NULL/*&m_ServerView*/,
		&max_msglen,
		ConnectDataBuffer,
		&Size);
#else
	status = ZwConnectPort(&hClientPort,
		&ustrPortName,
		&sqos,
		NULL/*&m_ClientView*/,
		NULL/*&m_ServerView*/,
		&max_msglen,
		ConnectDataBuffer,
		&Size);
#endif
	if (status != 0) {
		printf("Connect failed, status=%x\n", status);
		nError = GetLastError();
		return nError;
	}

	printf("Connect success.\n");
	printf("ConnectDataBuffer: %s\n", ConnectDataBuffer);

	MYPORT_MESSAGE Msg;
	MYPORT_MESSAGE Out;

	memset(&Msg, 0, sizeof(Msg));
	memset(&Out, 0, sizeof(Out));

	Msg.DataLength = MAX_DATA_LEN;   //如果长度过小，消息可能会被截断
	Msg.TotalLength = (short)sizeof(MYPORT_MESSAGE);
	printf("Msg.DataLength %d, Msg.TotalLength:%d\n", Msg.DataLength, Msg.TotalLength);
	memset(Msg.Data, 0x4A, MAX_DATA_LEN - 1);

#ifdef TEST_VIEW
	//m_ClientView.Length = sizeof("send");
	lstrcpyA((LPSTR)m_ClientView.ViewBase, "send");
#endif
	status = ZwRequestWaitReplyPort(hClientPort, &Msg, &Out);
	if (status != 0) {
		printf("ZwRequestWaitReplyPort failed, status=%x\n", status);
	}
	else
	{
		printf("ZwRequestWaitReplyPort ok\n");
		printf("recv Msg: %s \n", (LPSTR)Out.Data);

#ifdef TEST_VIEW
		//printf("m_ServerView.ViewSize: %d\n", m_ServerView.ViewSize);
		//printf("m_ServerView.Length: %d\n", m_ServerView.Length);
		//printf("m_ServerView.ViewBase: %s\n", m_ServerView.ViewBase);
		printf("m_ClientView.ViewSize: %zu\n", m_ClientView.ViewSize);
		printf("m_ClientView.Length: %d\n", m_ClientView.Length);
		printf("m_ClientView.ViewBase: %p\n", m_ClientView.ViewBase);
		printf("m_ClientView.ViewBase: %s\n", (LPSTR)m_ClientView.ViewBase);
		printf("m_ClientView.ViewRemoteBase: %p\n", m_ClientView.ViewRemoteBase);
#endif
	}

	CloseHandle(hClientPort);

	//Once the handle pointed to by SectionHandle is no longer in use, the driver must call ZwClose to close it.
	ZwClose(m_SectionHandle);

	nError = GetLastError();
	return nError;
}
