驱动：drive.h drive.c        

用户程序：LpcServer.cpp  lpc.cpp  lpc.h    
    
使用姿势：   
1 修改代码中所有出现过ztl和0x450,ztl改为当前普通用户名,0x450改为当前操作系统版本EPROCESS进程名称偏移   
2 编译驱动和用户程序LpcServer    
3 以system权限启动LpcServer.exe     
4 安装并启动驱动   
5 以medium权限启动名为test的进程,test.exe保持一直运行      


注：卸载驱动蓝屏，请在虚拟机内玩耍
