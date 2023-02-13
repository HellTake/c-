#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define debug 1
BYTE ShellCode[] =
{
    0x6A,0x00,0x6A,0x00,0x68,0x00,0x00,0x00,0x00,0x6A,0x00, //MessageBox push 0的硬编码
    0xE8,00,00,00,00,  // call汇编指令E8和后面待填充的硬编码
    0xE9,00,00,00,00,   // jmp汇编指令E9和后面待填充的硬编码
    0xC4,0xE3,0xBA,0xC3 
};
char name[] ="F:\\study\\pehead\\PETool 1.0.0.5.exe";
//char name[]="LORDPE.exe";

class File_Control
{
public:
    int getfunaddr(); // 获取MessageBoxA地址
    
};
//类方法声明 
int File_Control::getfunaddr()
{
        HMODULE Handle = GetModuleHandle("user32.dll");
        int Msgaddress = 0;
        if (Handle)
        {
            Msgaddress = (int)GetProcAddress(Handle, "MessageBoxA");
            if (!Msgaddress)
            {
                MessageBox(0, TEXT("无法获取MessageBox地址"), 0, 0);
                exit(0);
                return 0; // 环境错误
            }
            return Msgaddress; // 环境无误
        }
        else
        {
            MessageBox(0, TEXT("无法获取user32库地址"), 0, 0);
            exit(0);
            return 0; // 环境错误
        }
    }
//主函数 
int main()
{
    // 文件变量
    FILE *PointToFile = NULL; // 文件指针
    int FileSize = 0;         // 记录文件大小
    int *StrBuffer = NULL;    // 存放读取内存地址
    File_Control file;
    // PE头变量
    int stdpe = 0;               // 标准PE头偏移
    int SizeOfOptionHeader = 0;  // 可选PE头大小
    int choicepe = 0;            // 可选PE头偏移
    int section = 0;             // 节表偏移
    int VirtualAddress=0;		 //节在内存中的大小 
    int PointerToRawData=0;		 //节在文件中的偏移
	int PointerToVirtual=0;		 //节在内存中的偏移 
    unsigned char *EmptyAddrEnd; // 第一个节最后一字节地址
    
    unsigned int *OEP;           // OEP地址
    // 注入变量
    int CodeStart = 0;            // 注入代码文件中偏移
    int VirtualCodeStart=0;		  // 注入代码内存中偏移 
    unsigned int jmp_to_home = 0; // 与jmp联合使用，跳回到程序入口
    int msgbox = 0;               // msgbox函数地址
    unsigned int call_msgbox = 0; // 与call联合使用，实现call messagebox函数
    unsigned int str_addr = 0;			//	字符串地址 
    int ShellcodeLength=sizeof(ShellCode);
    if ((PointToFile = fopen(name, "rb+")) == NULL)
    {
        MessageBox(0, TEXT("打开文件失败!"), 0, 0);
        exit(1);
    }
    if (debug)
        printf("打开文件成功!\n");

    // 获取文件大小
    fseek(PointToFile, 0, 2);
    FileSize = ftell(PointToFile); // 获取文件指针当前位置相对于文件首的偏移字节数
    fseek(PointToFile, 0, 0);

    StrBuffer = (int *)(malloc(FileSize));
    fread(StrBuffer, FileSize, 1, PointToFile);
    
    // 获取PE头变量
    stdpe = 0 + *(unsigned short *)((unsigned char *)StrBuffer + 0x3c);
    SizeOfOptionHeader = *(unsigned short *)((int)StrBuffer + stdpe + 0x14);
    choicepe = stdpe + 0x18;
    section = choicepe + SizeOfOptionHeader;
    
//    EmptySectionEnd = *(unsigned int *)((unsigned char *)StrBuffer + section + 0x10);
//    EmptyAddrEnd = (unsigned char *)((unsigned char *)StrBuffer + EmptySectionEnd + 0xfff);
    VirtualAddress=*(unsigned int *)((unsigned char *)StrBuffer + section + 8);
    PointerToVirtual=*(unsigned int *)((unsigned char *)StrBuffer + section + 0xc);
    PointerToRawData=*(unsigned int *)((unsigned char *)StrBuffer + section + 0x14);
    
    CodeStart=VirtualAddress+PointerToRawData;
    OEP = (unsigned int *)((unsigned char *)StrBuffer + *(unsigned short *)((unsigned char *)StrBuffer + 0x3c) + 0x18 + 0x10);
	if (debug)
        printf("注入代码在文件中的位置:%x\n", CodeStart);
	
    // 计算代码注入偏移
    EmptyAddrEnd=(unsigned char *)((unsigned char *)StrBuffer + CodeStart);
    int i = 0;
    while (!*EmptyAddrEnd)
    {
        EmptyAddrEnd = (unsigned char *)((unsigned char *)StrBuffer + CodeStart + i);
        i++;
    }
    if (i==0){
    	MessageBox(0, TEXT("程序可用空间不足"), 0, 0);
        fclose(PointToFile);
        exit(0);
	}
    if (debug)
        printf("空白节可用大小:%x\n", i-1);
	
	VirtualCodeStart=VirtualAddress+PointerToVirtual;
    if (*OEP == CodeStart)
    {
        MessageBox(0, TEXT("程序已被修改,无序重复修改"), 0, 0);
        fclose(PointToFile);
        exit(0);
    }
	
    // 注入
    jmp_to_home = *OEP - VirtualCodeStart - ShellcodeLength + 4;
    msgbox = file.getfunaddr();
    call_msgbox = msgbox - 0x400000 - VirtualCodeStart - 16;
    str_addr=0x400000+VirtualCodeStart+21;

    memcpy((unsigned char *)StrBuffer + choicepe + 0x10,&VirtualCodeStart,4);
    memcpy((unsigned char *)StrBuffer + CodeStart,ShellCode,ShellcodeLength);
    memcpy((unsigned char *)StrBuffer + CodeStart + 5,&str_addr,4);
    memcpy((unsigned char *)StrBuffer + CodeStart + 12,&call_msgbox,4);
    memcpy((unsigned char *)StrBuffer + CodeStart + 17,&jmp_to_home,4);
    MessageBox(0, TEXT("注入完成！"), TEXT("成功"), 0);
	fclose(PointToFile);
    PointToFile = fopen(name, "wb+");
    fwrite(StrBuffer, FileSize, 1, PointToFile);
	fclose(PointToFile);	
}
