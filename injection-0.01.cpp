#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

int getfunaddr(){
HMODULE hModule=GetModuleHandle("user32.dll");
if (hModule)
{
int lpfnRegister;
lpfnRegister=(int)GetProcAddress(hModule,"MessageBoxA");
if (!lpfnRegister)
{
MessageBox(0,TEXT("无法获取user32库地址"),0,0);
}
//printf("%p\n",lpfnRegister);
return lpfnRegister;
}else{
	MessageBox(0,TEXT("无法获取MessageBox地址"),0,0);
}
}

int* OpenFile()
{
    FILE* PointToFile = NULL;
    int FileSize = 0;
    int* StrBuffer = NULL;
    int Num = 0;
    char addr[100];
    //打开文件
//    printf("输入要修改的文件:");
//    scanf("%s",addr);
    if ((PointToFile = fopen("F:\\study\\pehead\\WinHex 20.6 SR-1_x86_x64.exe","rb+")) == NULL) {
        printf("打开文件失败!");
        exit(1);
    }
	printf("打开文件成功!\n");
    //获取文件大小
    fseek(PointToFile,0,2);//设置文件指针指向文件尾 
    FileSize = ftell(PointToFile);//获取文件指针当前位置相对于文件首的偏移字节数
    //重定位指针
    fseek(PointToFile,0,0);
    StrBuffer = (int*)(malloc(FileSize));//申请一个内存用来存放读取的数据
    fread(StrBuffer,FileSize,1,PointToFile);
    int stdpe=0+*(unsigned short*)((unsigned char*)StrBuffer+0x3c);
    int SizeOfOptionHeader=*(unsigned short*)((int)StrBuffer+stdpe+0x14);
    int choicepe=stdpe+0x18;
    int section=choicepe+SizeOfOptionHeader;
    int EmptySectionEnd=*(unsigned int*)((unsigned char*)StrBuffer+section+0x10);
    printf("空白段起始位置:%x\n",EmptySectionEnd); 
    unsigned char* EmptyAddrEnd=(unsigned char*)((unsigned char*)StrBuffer+EmptySectionEnd+0xfff);
    int i=1;
    while(!*EmptyAddrEnd){
    	EmptyAddrEnd=(unsigned char*)((unsigned char*)StrBuffer+EmptySectionEnd+0xfff-i);
    	i++;
    }
    i=i/16*16;
    printf("空白节可用大小:%x\n",i);
    int CodeStart=EmptySectionEnd+0x1000-i;
    printf("注入代码位置:%x\n",CodeStart);
    unsigned int* OEP=(unsigned int*)((unsigned char*)StrBuffer+*(unsigned short*)((unsigned char*)StrBuffer+0x3c)+0x18+0x10);
    if(*OEP==CodeStart-0x20){
    	printf("程序已被修改,无序重复修改");
    	fclose(PointToFile);
    	return StrBuffer;
	}
    unsigned int addr1=*OEP-CodeStart-18;
    unsigned int *p1=&addr1;//需要的第一个值，程序的起始地址相对于注入代码段的结束位置的偏移 
    int *WrightPoint=&CodeStart;
    int msgbox=getfunaddr();
    unsigned int addr2=msgbox-0x400000-CodeStart-0xd;
    unsigned int *p2=&addr2;//需要的第二个值，msgbox的起始地址相对于调用处偏移 
    fseek(PointToFile,choicepe+0x10,0);//注入位置1，改变文件OEP 
    fprintf(PointToFile,"%c%c%c%c",*((char*)WrightPoint),*((char*)WrightPoint+1),*((char*)WrightPoint+2),*((char*)WrightPoint+3));
    printf("OEP修改成功!\n");
    fseek(PointToFile,CodeStart,0);//注入位置 2，向空白段写入机器码 
    fprintf(PointToFile,"%c%c%c%c%c%c%c%c",0x6a,0x00,0x6a,0x00,0x6a,0x00,0x6a,0x00);//写入的机器码,参数入栈 
    fseek(PointToFile,CodeStart+8,0);
    fprintf(PointToFile,"%c",0xe8);//call指令 
    fseek(PointToFile,CodeStart+9,0);
    fprintf(PointToFile,"%c%c%c%c",*(unsigned char*)p2,*((unsigned char*)p2+1),*((unsigned char*)p2+2),*((unsigned char*)p2+3));
    fseek(PointToFile,CodeStart+13,0);
    fprintf(PointToFile,"%c",0xe9);//jmp指令 
    fseek(PointToFile,CodeStart+14,0);
    fprintf(PointToFile,"%c%c%c%c",*(unsigned char*)p1,*((unsigned char*)p1+1),*((unsigned char*)p1+2),*((unsigned char*)p1+3));
    printf("机器码注入完成!\n");
    fclose(PointToFile);
    //将缓冲区内的文件内容的地址返回到调用函数的地方
    return StrBuffer;
}

int* FileSizes = OpenFile();

int PrintfNtHeaders()
{
    //文件指针
    unsigned short* PointBuffer = (unsigned short*)FileSizes;
    unsigned short* pBuffer = (unsigned short*)PointBuffer;
    unsigned char* pcBuffer = (unsigned char*)PointBuffer;

//    //判断MZ和PE的标志
//    unsigned short Cmp1 = 0x5A4D;
//    unsigned int Cmp2 = 0x4550;
//
//    //判断文件是否读取成功
//    if(!PointBuffer)
//    {
//        printf("文件读取失败！");
//        free(PointBuffer);
//        return 0;
//    }
//
//    //判断是否为MZ标志
//    if (*pBuffer != Cmp1)
//    {
//        printf("不是有效MZ标志！");
//        printf("%X\n",*pBuffer);
//        free(PointBuffer);
//        return 0;
//    }
//    printf("*********打印DOS头*********\n");
//    printf("e_magic:			%X\n",*(pBuffer));
//    printf("e_ifanew:			%08X\n",*((unsigned short*)((unsigned char*)PointBuffer+0x3c)));
//    //判断是否为PE标志
//    unsigned char* sdpe=((unsigned char*)PointBuffer+*(unsigned short*)((unsigned char*)PointBuffer+0x3c));
//    if (*(unsigned short*)sdpe!= Cmp2)
//    {
//        printf("不是有效的PE标志！");
//        printf("%X\n",*sdpe);
//        free(PointBuffer);
//        return 0;
//    }
//	
//	unsigned char* choicepe=(unsigned char*)(sdpe+0x18);
//	*(unsigned int*)(choicepe+0x10)=0x1caa0;
//    printf("*********打印标准PE文件头*********\n");
//    printf("PE标志:				%04X\n",*(unsigned short*)sdpe);
//    printf("Machine:			%04X\n",*(unsigned short*)(sdpe+0x4));
//    printf("NumberOfSection:		%04X\n",*(unsigned short*)(sdpe+0x6));
//    printf("TimeDateStamp:			%08X\n",*(unsigned int*)(sdpe+0x8));
//    printf("PointerToSymbolTable:		%08X\n",*(unsigned int*)(sdpe+0xc));
//    printf("NumberOfSymbols:		%08X\n",*(unsigned int*)(sdpe+0x10));
//    printf("SizeOfOptionalHeader:		%04X\n",*(unsigned short*)(sdpe+0x14));
//    printf("Chrarcteristics:		%04X\n",*(unsigned short*)(sdpe+0x16));
	
//    printf("*********打印标准可选PE头*********\n");
//
//    printf("Magic:				%04X\n", *(unsigned short*)(choicepe));
//    printf("MajorLinkerVersion:		%02X\n", *(unsigned char*)(choicepe+0x2));
//    printf("MinorLinkerVersion:		%02X\n", *(unsigned char*)(choicepe+0x3));
//    printf("SizeOfCode:			%08X\n", *(unsigned int*)(choicepe+0x4));
//    printf("SizeOfInitializedData:		%08X\n", *(unsigned int*)(choicepe+0x8));
//    printf("SizeOfUninitializedData:	%08X\n", *(unsigned int*)(choicepe+0xc));
//    printf("BaseOfCode:			%08X\n", *(unsigned int*)(choicepe+0x14));
//    printf("BaseOfData:			%08X\n", *(unsigned int*)(choicepe+0x18));
//    printf("ImageBase:			%08X\n", *(unsigned int*)(choicepe+0x1c));
//    printf("SectionAlignment:		%08X\n", *(unsigned int*)(choicepe+0x20));
//    printf("FileAlignment:			%08X\n", *(unsigned int*)(choicepe+0x24));
//    printf("MajorOperatingSystemVersion:	%04X\n", *(unsigned short*)(choicepe+0x28));
//    printf("MinorOperatingSystemVersion:	%04X\n", *(unsigned short*)(choicepe+0x2a));
//    printf("MajorImageVersion:		%04X\n", *(unsigned short*)(choicepe+0x2c));
//    printf("MinorImageVersion:		%04X\n", *(unsigned short*)(choicepe+0x2e));
//    printf("MajorSubsystemVersion:		%04X\n", *(unsigned short*)(choicepe+0x30));
//    printf("MinorSubsystemVersion:		%04X\n", *(unsigned short*)(choicepe+0x32));
//    printf("Win32VersionValue:		%08X\n", *(unsigned int*)(choicepe+0x34));
//    printf("SizeOfImage:			%08X\n", *(unsigned int*)(choicepe+0x38));
//    printf("SizeOfHeaders:			%08X\n", *(unsigned int*)(choicepe+0x3c));
//    printf("CheckSum:			%08X\n", *(unsigned int*)(choicepe+0x40));
//    printf("Subsystem:			%04X\n", *(unsigned short*)(choicepe+0x44));
//    printf("DllCharacteristics:		%04X\n", *(unsigned short*)(choicepe+0x46));
//    printf("SizeOfStackReserve:		%016X\n", *(unsigned int*)(choicepe+0x48));
//    printf("SizeOfStackCommit:		%016X\n", *(unsigned int*)(choicepe+0x50));
//    printf("SizeOfHeapReserve:		%016X\n", *(unsigned int*)(choicepe+0x58));
//    printf("SizeOfHeapCommit:		%016X\n", *(unsigned int*)(choicepe+0x60));
//    printf("LoaderFlags:			%08X\n", *(unsigned int*)(choicepe+0x68));
//    printf("NumberOfRvaAndSizes:		%08X\n", *(unsigned int*)(choicepe+0x6c));
//    free(PointBuffer);
    return 0;
}

int main()
{
    PrintfNtHeaders();
//    OpenFile();
    return 0;
}
