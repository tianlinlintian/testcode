驱动：drive.h drive.c   
需要将所有ztl改为当前普通用户名   
需要将0x450改为当前操作系统版本PEORCESS进程名称偏移        


用户程序：LpcServer.cpp  lpc.cpp  lpc.h    
需要将所有ztl改为当前普通用户名        
    
使用姿势：   
编译后驱动和用户程序后，以systme权限启动LpcServer.exe,然后安装并启动驱动，最后以medium权限启动一个名为test的进程,test.exe必须一直运行     



