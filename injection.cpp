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
MessageBox(0,TEXT("�޷���ȡuser32���ַ"),0,0);
}
//printf("%p\n",lpfnRegister);
return lpfnRegister;
}else{
	MessageBox(0,TEXT("�޷���ȡMessageBox��ַ"),0,0);
}
}

int* OpenFile()
{
    FILE* PointToFile = NULL;
    int FileSize = 0;
    int* StrBuffer = NULL;
    int Num = 0;
    char addr[100];
    //���ļ�
//    printf("����Ҫ�޸ĵ��ļ�:");
//    scanf("%s",addr);
    if ((PointToFile = fopen("F:\\study\\pehead\\WinHex 20.6 SR-1_x86_x64.exe","rb+")) == NULL) {
        printf("���ļ�ʧ��!");
        exit(1);
    }
	printf("���ļ��ɹ�!\n");
    //��ȡ�ļ���С
    fseek(PointToFile,0,2);//�����ļ�ָ��ָ���ļ�β 
    FileSize = ftell(PointToFile);//��ȡ�ļ�ָ�뵱ǰλ��������ļ��׵�ƫ���ֽ���
    //�ض�λָ��
    fseek(PointToFile,0,0);
    StrBuffer = (int*)(malloc(FileSize));//����һ���ڴ�������Ŷ�ȡ������
    fread(StrBuffer,FileSize,1,PointToFile);
    int stdpe=0+*(unsigned short*)((unsigned char*)StrBuffer+0x3c);
    int SizeOfOptionHeader=*(unsigned short*)((int)StrBuffer+stdpe+0x14);
    int choicepe=stdpe+0x18;
    int section=choicepe+SizeOfOptionHeader;
    int EmptySectionEnd=*(unsigned int*)((unsigned char*)StrBuffer+section+0x10);
    printf("�հ׶���ʼλ��:%x\n",EmptySectionEnd); 
    unsigned char* EmptyAddrEnd=(unsigned char*)((unsigned char*)StrBuffer+EmptySectionEnd+0xfff);
    int i=1;
    while(!*EmptyAddrEnd){
    	EmptyAddrEnd=(unsigned char*)((unsigned char*)StrBuffer+EmptySectionEnd+0xfff-i);
    	i++;
    }
    i=i/16*16;
    printf("�հ׽ڿ��ô�С:%x\n",i);
    int CodeStart=EmptySectionEnd+0x1000-i;
    printf("ע�����λ��:%x\n",CodeStart);
    unsigned int* OEP=(unsigned int*)((unsigned char*)StrBuffer+*(unsigned short*)((unsigned char*)StrBuffer+0x3c)+0x18+0x10);
    if(*OEP==CodeStart-0x20){
    	printf("�����ѱ��޸�,�����ظ��޸�");
    	fclose(PointToFile);
    	return StrBuffer;
	}
    unsigned int addr1=*OEP-CodeStart-18;
    unsigned int *p1=&addr1;//��Ҫ�ĵ�һ��ֵ���������ʼ��ַ�����ע�����εĽ���λ�õ�ƫ�� 
    int *WrightPoint=&CodeStart;
    int msgbox=getfunaddr();
    unsigned int addr2=msgbox-0x400000-CodeStart-0xd;
    unsigned int *p2=&addr2;//��Ҫ�ĵڶ���ֵ��msgbox����ʼ��ַ����ڵ��ô�ƫ�� 
    fseek(PointToFile,choicepe+0x10,0);//ע��λ��1���ı��ļ�OEP 
    fprintf(PointToFile,"%c%c%c%c",*((char*)WrightPoint),*((char*)WrightPoint+1),*((char*)WrightPoint+2),*((char*)WrightPoint+3));
    printf("OEP�޸ĳɹ�!\n");
    fseek(PointToFile,CodeStart,0);//ע��λ�� 2����հ׶�д������� 
    fprintf(PointToFile,"%c%c%c%c%c%c%c%c",0x6a,0x00,0x6a,0x00,0x6a,0x00,0x6a,0x00);//д��Ļ�����,������ջ 
    fseek(PointToFile,CodeStart+8,0);
    fprintf(PointToFile,"%c",0xe8);//callָ�� 
    fseek(PointToFile,CodeStart+9,0);
    fprintf(PointToFile,"%c%c%c%c",*(unsigned char*)p2,*((unsigned char*)p2+1),*((unsigned char*)p2+2),*((unsigned char*)p2+3));
    fseek(PointToFile,CodeStart+13,0);
    fprintf(PointToFile,"%c",0xe9);//jmpָ�� 
    fseek(PointToFile,CodeStart+14,0);
    fprintf(PointToFile,"%c%c%c%c",*(unsigned char*)p1,*((unsigned char*)p1+1),*((unsigned char*)p1+2),*((unsigned char*)p1+3));
    printf("������ע�����!\n");
    fclose(PointToFile);
    //���������ڵ��ļ����ݵĵ�ַ���ص����ú����ĵط�
    return StrBuffer;
}

int* FileSizes = OpenFile();

int PrintfNtHeaders()
{
    //�ļ�ָ��
    unsigned short* PointBuffer = (unsigned short*)FileSizes;
    unsigned short* pBuffer = (unsigned short*)PointBuffer;
    unsigned char* pcBuffer = (unsigned char*)PointBuffer;

//    //�ж�MZ��PE�ı�־
//    unsigned short Cmp1 = 0x5A4D;
//    unsigned int Cmp2 = 0x4550;
//
//    //�ж��ļ��Ƿ��ȡ�ɹ�
//    if(!PointBuffer)
//    {
//        printf("�ļ���ȡʧ�ܣ�");
//        free(PointBuffer);
//        return 0;
//    }
//
//    //�ж��Ƿ�ΪMZ��־
//    if (*pBuffer != Cmp1)
//    {
//        printf("������ЧMZ��־��");
//        printf("%X\n",*pBuffer);
//        free(PointBuffer);
//        return 0;
//    }
//    printf("*********��ӡDOSͷ*********\n");
//    printf("e_magic:			%X\n",*(pBuffer));
//    printf("e_ifanew:			%08X\n",*((unsigned short*)((unsigned char*)PointBuffer+0x3c)));
//    //�ж��Ƿ�ΪPE��־
//    unsigned char* sdpe=((unsigned char*)PointBuffer+*(unsigned short*)((unsigned char*)PointBuffer+0x3c));
//    if (*(unsigned short*)sdpe!= Cmp2)
//    {
//        printf("������Ч��PE��־��");
//        printf("%X\n",*sdpe);
//        free(PointBuffer);
//        return 0;
//    }
//	
//	unsigned char* choicepe=(unsigned char*)(sdpe+0x18);
//	*(unsigned int*)(choicepe+0x10)=0x1caa0;
//    printf("*********��ӡ��׼PE�ļ�ͷ*********\n");
//    printf("PE��־:				%04X\n",*(unsigned short*)sdpe);
//    printf("Machine:			%04X\n",*(unsigned short*)(sdpe+0x4));
//    printf("NumberOfSection:		%04X\n",*(unsigned short*)(sdpe+0x6));
//    printf("TimeDateStamp:			%08X\n",*(unsigned int*)(sdpe+0x8));
//    printf("PointerToSymbolTable:		%08X\n",*(unsigned int*)(sdpe+0xc));
//    printf("NumberOfSymbols:		%08X\n",*(unsigned int*)(sdpe+0x10));
//    printf("SizeOfOptionalHeader:		%04X\n",*(unsigned short*)(sdpe+0x14));
//    printf("Chrarcteristics:		%04X\n",*(unsigned short*)(sdpe+0x16));
	
//    printf("*********��ӡ��׼��ѡPEͷ*********\n");
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
