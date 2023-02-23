#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define PE_SIGNA 0x5a4d // "PE"
#define MZ_SIGNA 0x4550 // "MZ"
#define MAGIC 0x10b // 32位程序
#define MACHINE 0x014c //32位机器架构

#define PUSH_STR_OFFSET 0x5
#define STR_OFFSET 0x15
#define MESSAGE_BOX_OFFSET 0xc
#define JMP_TO_HOME 0x11

#define addr 0,0,0,0
#define Push1 0x6A
#define Push4 0x68
#define Call 0xE8
#define Jmp 0xE9
#define hello 0xC4,0xE3,0xBA,0xC3
#define debug 0

BYTE ShellCode[] =
{
    Push1,0,
    Push1,0,
    Push4,addr,
    Push1,0, //MessageBox push 0的硬编码
    Call,addr,  // call汇编指令E8和后面待填充的硬编码
    Jmp,addr,   // jmp汇编指令E9和后面待填充的硬编码
    hello
};
char name[50];

class File_Control
{
public:
    //文件变量
    int FileSize = 0;         // 记录文件大小
    char FileName[100];		  // 文件名
    int *StrBuffer=0;		 //文件指针

    // PE头变量
    IMAGE_DOS_HEADER* dos_header = 0; //DOS头结构体指针
    IMAGE_NT_HEADERS* nt_headers = 0; //NT头结构体指针
    IMAGE_OPTIONAL_HEADER32* optional_headers = 0; //可选头结构体指针
    IMAGE_SECTION_HEADER* section_headers = 0; //节表结构体指针
    int section_count = 0; //节数量
    char section_name[8]; //注入节名字
    unsigned char *OEP;           // OEP地址

    //注入变量
    int Msgaddress = 0;     //Message_box地址
    int Blank_Section_Length = 0; //空白节长度
    int CodeStart = 0;            // 注入代码文件中偏移
    int VirtualCodeStart=0;		  // 注入代码内存中偏移
    unsigned int jmp_to_home = 0; // 与jmp联合使用，跳回到程序入口
    unsigned int call_msgbox = 0; // 与call联合使用，实现call messagebox函数
    unsigned int str_addr = 0;			//	字符串地址
    int ShellcodeLength=sizeof(ShellCode);

    //方法
    void init(const char* Name);
    void getfunaddr(); // 获取MessageBoxA地址
    void output_error(const TCHAR* error_message);
    void read_file();
    void write_file();
    void inject();
};
//类方法声明
void File_Control::init(const char* Name)
{
    strcpy(FileName,Name);
    read_file();

    //PE头变量赋值
    dos_header=(IMAGE_DOS_HEADER*)StrBuffer;
    nt_headers=(IMAGE_NT_HEADERS*)((BYTE*)StrBuffer + dos_header->e_lfanew);
    optional_headers=&nt_headers->OptionalHeader;
    section_headers=IMAGE_FIRST_SECTION(nt_headers);

    // 判断文件是否可注入
    if(dos_header->e_magic != PE_SIGNA)
    {
        output_error(TEXT("文件不是一个可执行文件！"));
    }
    if(nt_headers->Signature != MZ_SIGNA)
    {
        output_error(TEXT("缺少PE头！"));
    }
    if(nt_headers->FileHeader.Machine != MACHINE)
    {
        output_error(TEXT("文件不是一个32位程序！"));
    }
    if(nt_headers->OptionalHeader.Magic != MAGIC)
    {
        output_error(TEXT("文件不是一个32位程序！"));
    }

    //注入变量初始化
    CodeStart=section_headers->PointerToRawData+section_headers->Misc.VirtualSize;
    OEP=(unsigned char *)StrBuffer + CodeStart;
    VirtualCodeStart=section_headers->VirtualAddress+section_headers->Misc.VirtualSize;
    if (debug)
        printf("注入代码在文件中的位置:%x,在内存中的位置:%x\n", CodeStart,VirtualCodeStart);
}
void File_Control::getfunaddr()
{
    HMODULE Handle = GetModuleHandle("user32.dll");
    if (Handle)
    {
        Msgaddress = (int)GetProcAddress(Handle, "MessageBoxA");
        if (!Msgaddress)
        {
            MessageBox(0, TEXT("无法获取MessageBox地址"), 0, 0);
            exit(0);
            return; // 环境错误
        }
    }
    else
    {
        MessageBox(0, TEXT("无法获取user32库地址"), 0, 0);
        exit(0);
        return; // 环境错误
    }
}
void File_Control::read_file()
{
    FILE* fp;				  // 文件指针
    if ((fp = fopen(FileName, "rb")) == NULL)
    {
        MessageBox(0, TEXT("文件打开失败！"), 0, 0);
        exit(1);
    }
    // 获取文件大小
    fseek(fp, 0, 2);
    FileSize = ftell(fp); // 获取文件指针当前位置相对于文件首的偏移字节数
    fseek(fp, 0, 0);
    StrBuffer=(int *)(malloc(FileSize));
    if (fread(StrBuffer, FileSize, 1, fp) != 1)
    {
        MessageBox(0, TEXT("文件读取失败！"), 0, 0);
        fclose(fp);
        exit(1);
    }
    fclose(fp);
}
void File_Control::write_file()
{
    FILE* fp;				  // 文件指针
    if ((fp = fopen(FileName, "wb")) == NULL)
    {
        MessageBox(0, TEXT("文件打开失败！"), 0, 0);
        exit(1);
    }
    if (fwrite(StrBuffer, FileSize, 1, fp) != 1)
    {
        MessageBox(0, TEXT("文件写入失败！"), 0, 0);
        fclose(fp);
        exit(1);
    }
    fclose(fp);
}
void File_Control::output_error(const TCHAR* error_message)
{
    MessageBox(0, error_message, 0, 0);
    exit(1);
}
void File_Control::inject(){
// 计算代码注入偏移
    Blank_Section_Length=section_headers->SizeOfRawData-section_headers->Misc.VirtualSize;
    section_count = nt_headers->FileHeader.NumberOfSections;

    for (int i = 0; i < section_count; i++){
    // 计算代码注入偏移
    if(section_headers[i].SizeOfRawData - section_headers[i].Misc.VirtualSize > Blank_Section_Length && (int)(section_headers[i].Characteristics & 0x20000000) != 0){
        memset(section_name,0,sizeof(section_name));
        Blank_Section_Length=section_headers[i].SizeOfRawData-section_headers[i].Misc.VirtualSize;
        if(debug)
            printf("可用空白节名：%s，大小：%x\n", section_headers[i].Name, Blank_Section_Length);
        strcpy(section_name,(char *)section_headers[i].Name);
    }
    }

    if (Blank_Section_Length<=0)
    {
        output_error(TEXT("没有足够的可注入空白节"));
    }
    if (debug)
        printf("注入节：%s\n",section_name);
    if (optional_headers->AddressOfEntryPoint == VirtualCodeStart)
    {
        output_error(TEXT("程序已被修改,无序重复修改"));
    }

    // 注入
    jmp_to_home = optional_headers->AddressOfEntryPoint - VirtualCodeStart - JMP_TO_HOME - 4;
    getfunaddr();
    call_msgbox = Msgaddress - 0x400000 - VirtualCodeStart - MESSAGE_BOX_OFFSET-4;
    str_addr=0x400000 + VirtualCodeStart + STR_OFFSET;
    if( (int)(optional_headers->DllCharacteristics & 0x40) == 0x40 ){                   //关闭aslr
        optional_headers->DllCharacteristics = optional_headers->DllCharacteristics & 0xff0f;
    }
    optional_headers->AddressOfEntryPoint = VirtualCodeStart;
    memcpy(OEP,ShellCode,ShellcodeLength);
    memcpy(OEP + PUSH_STR_OFFSET,&str_addr,4);
    memcpy(OEP + MESSAGE_BOX_OFFSET,&call_msgbox,4);
    memcpy(OEP + JMP_TO_HOME,&jmp_to_home,4);
    if(!debug)
        write_file();
    MessageBox(0, TEXT("注入完成！"), TEXT("成功"), 0);
}
//主函数
int main(int argc, char* argv[])
{
    File_Control file;		//文件操作对象

    if (debug)
    {
        file.init("F:\\软件\\WeChat\\WeChat.exe");
    }
    else
    {
        if (argc <2)
        {
            printf("用法: %s <path_of_injected_file>\n","injection.exe");
        }
        if(sizeof(argv[1])>=100)
            file.output_error("文件路径过长！");
        file.init(argv[1]);
    }
    if (debug)
        printf("打开文件成功!\n");

    file.inject();
}
