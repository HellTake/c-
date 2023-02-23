#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define PE_SIGNA 0x5a4d // "PE"
#define MZ_SIGNA 0x4550 // "MZ"
#define MAGIC 0x10b // 32位程序
#define MACHINE 0x014c //32位机器架构

#define STR_ADDR_OFFSET 0x5
#define MESSAGE_BOX_OFFSET 0xc
#define JMP_TO_HOME 0x11
#define debug 1

BYTE ShellCode[] =
{
    0x6A,0x00,0x6A,0x00,0x68,0x00,0x00,0x00,0x00,0x6A,0x00, //MessageBox push 0的硬编码
    0xE8,00,00,00,00,  // call汇编指令E8和后面待填充的硬编码
    0xE9,00,00,00,00,   // jmp汇编指令E9和后面待填充的硬编码
    0xC4,0xE3,0xBA,0xC3
};
char name[50];


class File_Control
{
public:
    int FileSize = 0;         // 记录文件大小
    char FileName[100];		  // 文件名
    void init(const char* Name);
    int getfunaddr(); // 获取MessageBoxA地址
    void output_error(const TCHAR* error_message);
    int* read_file();
    int * write_file(int* buffer);
};
//类方法声明
void File_Control::init(const char* Name)
{
    strcpy(FileName,Name);
}
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
int* File_Control::read_file()
{
    FILE* fp;				  // 文件指针
    int* buffer;			  // 存放读取内存地址
    if ((fp = fopen(FileName, "rb")) == NULL)
    {
        MessageBox(0, TEXT("文件打开失败！"), 0, 0);
        exit(1);
    }
    // 获取文件大小
    fseek(fp, 0, 2);
    FileSize = ftell(fp); // 获取文件指针当前位置相对于文件首的偏移字节数
    fseek(fp, 0, 0);
    buffer=(int *)(malloc(FileSize));
    if (fread(buffer, FileSize, 1, fp) != 1)
    {
        MessageBox(0, TEXT("文件读取失败！"), 0, 0);
        fclose(fp);
        exit(1);
    }
    fclose(fp);
    return buffer;
}
int* File_Control::write_file(int* buffer)
{
    FILE* fp;				  // 文件指针
    if ((fp = fopen(FileName, "wb")) == NULL)
    {
        MessageBox(0, TEXT("文件打开失败！"), 0, 0);
        exit(1);
    }
    if (fwrite(buffer, FileSize, 1, fp) != 1)
    {
        MessageBox(0, TEXT("文件写入失败！"), 0, 0);
        fclose(fp);
        exit(1);
    }
    fclose(fp);
    return buffer;
}
void File_Control::output_error(const TCHAR* error_message)
{
    MessageBox(0, error_message, 0, 0);
    exit(1);
}
//主函数
int main(int argc, char* argv[])
{
    // 文件变量
    int *StrBuffer=0;		 //文件指针
    unsigned short PEflag=0; //PE头标志
    unsigned short MZflag=0; //MZ标志
    unsigned short Magic=0; //运行环境32 or 64
    File_Control file;		//文件操作对象
    // PE头变量
    IMAGE_DOS_HEADER* dos_header = 0; //DOS头结构体指针
    IMAGE_NT_HEADERS* nt_headers = 0; //NT头结构体指针
    IMAGE_OPTIONAL_HEADER32* optional_headers = 0; //可选头结构体指针
    IMAGE_SECTION_HEADER* section_headers = 0; //节表结构体指针
    unsigned char *OEP;           // OEP地址

    // 注入变量
    int Blank_Section_Length = 0; //空白节长度
    int CodeStart = 0;            // 注入代码文件中偏移
    int VirtualCodeStart=0;		  // 注入代码内存中偏移
    unsigned int jmp_to_home = 0; // 与jmp联合使用，跳回到程序入口
    int msgbox = 0;               // msgbox函数地址
    unsigned int call_msgbox = 0; // 与call联合使用，实现call messagebox函数
    unsigned int str_addr = 0;			//	字符串地址
    int ShellcodeLength=sizeof(ShellCode);
    if (debug)
    {
        file.init("base.exe");
        StrBuffer=file.read_file();
    }
    else
    {
        if (argc <2)
        {
            char buff[100];
            printf(buff,"用法: %s <path_of_injected_file>\n",argv[0]);
        }
        if(sizeof(argv[1])>=100)
            file.output_error("文件路径过长！");
        file.init(argv[1]);
        StrBuffer=file.read_file();
    }
    if (debug)
        printf("打开文件成功!\n");

    //PE头变量赋值
    dos_header=(IMAGE_DOS_HEADER*)StrBuffer;
    nt_headers=(IMAGE_NT_HEADERS*)((BYTE*)StrBuffer + dos_header->e_lfanew);
    optional_headers=&nt_headers->OptionalHeader;
    section_headers=IMAGE_FIRST_SECTION(nt_headers);

    // 判断文件是否可注入
    if(dos_header->e_magic != PE_SIGNA)
    {
        file.output_error(TEXT("文件不是一个可执行文件！"));
    }
    if(nt_headers->Signature != MZ_SIGNA)
    {
        file.output_error(TEXT("缺少PE头！"));
    }
    if(nt_headers->FileHeader.Machine != MACHINE)
    {
        file.output_error(TEXT("文件不是一个32位程序！"));
    }
    if(nt_headers->OptionalHeader.Magic != MAGIC)
    {
        file.output_error(TEXT("文件不是一个32位程序！"));
    }

    CodeStart=section_headers->PointerToRawData+section_headers->Misc.VirtualSize;
    OEP=(unsigned char *)StrBuffer + CodeStart;
    VirtualCodeStart=section_headers->VirtualAddress+section_headers->Misc.VirtualSize;
    if (debug)
        printf("注入代码在文件中的位置:%x,在内存中的位置:%x\n", CodeStart,VirtualCodeStart);

    // 计算代码注入偏移
    Blank_Section_Length=section_headers->SizeOfRawData-section_headers->Misc.VirtualSize;
    if (Blank_Section_Length<=0)
    {
        file.output_error(TEXT("程序可用空间不足"));
    }
    if (debug)
        printf("空白节可用大小:%x\n", Blank_Section_Length);
    if (optional_headers->AddressOfEntryPoint == CodeStart)
    {
        file.output_error(TEXT("程序已被修改,无序重复修改"));
    }

    // 注入
    jmp_to_home = optional_headers->AddressOfEntryPoint - VirtualCodeStart - ShellcodeLength + 4;
    msgbox = file.getfunaddr();
    call_msgbox = msgbox - 0x400000 - VirtualCodeStart - 16;
    str_addr=0x400000+VirtualCodeStart+21;

    optional_headers->AddressOfEntryPoint=VirtualCodeStart;
    memcpy(OEP,ShellCode,ShellcodeLength);
    memcpy(OEP + STR_ADDR_OFFSET,&str_addr,4);
    memcpy(OEP + MESSAGE_BOX_OFFSET,&call_msgbox,4);
    memcpy(OEP + JMP_TO_HOME,&jmp_to_home,4);

    file.write_file(StrBuffer);
    MessageBox(0, TEXT("注入完成！"), TEXT("成功"), 0);
}
