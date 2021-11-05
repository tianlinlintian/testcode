驱动：drive.h drive.c   
需要将所有ztl改为当前普通用户名   
需要将所有0x450改为当前操作系统版本PEORCESS进程名称偏移        


用户程序：LpcServer.cpp  lpc.cpp  lpc.h    
需要将所有ztl改为当前普通用户名        
    
使用姿势：   
1 编译驱动和用户程序LpcServer   
2 以system权限启动LpcServer.exe   
3 安装并启动驱动   
4 以medium权限启动一个名为test的进程,test.exe保持一直运行      


注：卸载驱动蓝屏
