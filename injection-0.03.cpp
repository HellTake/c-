#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define debug 1
BYTE ShellCode[] =
{
    0x6A,0x00,0x6A,0x00,0x68,0x00,0x00,0x00,0x00,0x6A,0x00, //MessageBox push 0��Ӳ����
    0xE8,00,00,00,00,  // call���ָ��E8�ͺ��������Ӳ����
    0xE9,00,00,00,00,   // jmp���ָ��E9�ͺ��������Ӳ����
    0xC4,0xE3,0xBA,0xC3 
};
char name[] ="F:\\study\\pehead\\PETool 1.0.0.5.exe";
//char name[]="LORDPE.exe";

class File_Control
{
public:
    int getfunaddr(); // ��ȡMessageBoxA��ַ
    
};
//�෽������ 
int File_Control::getfunaddr()
{
        HMODULE Handle = GetModuleHandle("user32.dll");
        int Msgaddress = 0;
        if (Handle)
        {
            Msgaddress = (int)GetProcAddress(Handle, "MessageBoxA");
            if (!Msgaddress)
            {
                MessageBox(0, TEXT("�޷���ȡMessageBox��ַ"), 0, 0);
                exit(0);
                return 0; // ��������
            }
            return Msgaddress; // ��������
        }
        else
        {
            MessageBox(0, TEXT("�޷���ȡuser32���ַ"), 0, 0);
            exit(0);
            return 0; // ��������
        }
    }
//������ 
int main()
{
    // �ļ�����
    FILE *PointToFile = NULL; // �ļ�ָ��
    int FileSize = 0;         // ��¼�ļ���С
    int *StrBuffer = NULL;    // ��Ŷ�ȡ�ڴ��ַ
    File_Control file;
    // PEͷ����
    int stdpe = 0;               // ��׼PEͷƫ��
    int SizeOfOptionHeader = 0;  // ��ѡPEͷ��С
    int choicepe = 0;            // ��ѡPEͷƫ��
    int section = 0;             // �ڱ�ƫ��
    int VirtualAddress=0;		 //�����ڴ��еĴ�С 
    int PointerToRawData=0;		 //�����ļ��е�ƫ��
	int PointerToVirtual=0;		 //�����ڴ��е�ƫ�� 
    unsigned char *EmptyAddrEnd; // ��һ�������һ�ֽڵ�ַ
    
    unsigned int *OEP;           // OEP��ַ
    // ע�����
    int CodeStart = 0;            // ע������ļ���ƫ��
    int VirtualCodeStart=0;		  // ע������ڴ���ƫ�� 
    unsigned int jmp_to_home = 0; // ��jmp����ʹ�ã����ص��������
    int msgbox = 0;               // msgbox������ַ
    unsigned int call_msgbox = 0; // ��call����ʹ�ã�ʵ��call messagebox����
    unsigned int str_addr = 0;			//	�ַ�����ַ 
    int ShellcodeLength=sizeof(ShellCode);
    if ((PointToFile = fopen(name, "rb+")) == NULL)
    {
        MessageBox(0, TEXT("���ļ�ʧ��!"), 0, 0);
        exit(1);
    }
    if (debug)
        printf("���ļ��ɹ�!\n");

    // ��ȡ�ļ���С
    fseek(PointToFile, 0, 2);
    FileSize = ftell(PointToFile); // ��ȡ�ļ�ָ�뵱ǰλ��������ļ��׵�ƫ���ֽ���
    fseek(PointToFile, 0, 0);

    StrBuffer = (int *)(malloc(FileSize));
    fread(StrBuffer, FileSize, 1, PointToFile);
    
    // ��ȡPEͷ����
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
        printf("ע��������ļ��е�λ��:%x\n", CodeStart);
	
    // �������ע��ƫ��
    EmptyAddrEnd=(unsigned char *)((unsigned char *)StrBuffer + CodeStart);
    int i = 0;
    while (!*EmptyAddrEnd)
    {
        EmptyAddrEnd = (unsigned char *)((unsigned char *)StrBuffer + CodeStart + i);
        i++;
    }
    if (i==0){
    	MessageBox(0, TEXT("������ÿռ䲻��"), 0, 0);
        fclose(PointToFile);
        exit(0);
	}
    if (debug)
        printf("�հ׽ڿ��ô�С:%x\n", i-1);
	
	VirtualCodeStart=VirtualAddress+PointerToVirtual;
    if (*OEP == CodeStart)
    {
        MessageBox(0, TEXT("�����ѱ��޸�,�����ظ��޸�"), 0, 0);
        fclose(PointToFile);
        exit(0);
    }
	
    // ע��
    jmp_to_home = *OEP - VirtualCodeStart - ShellcodeLength + 4;
    msgbox = file.getfunaddr();
    call_msgbox = msgbox - 0x400000 - VirtualCodeStart - 16;
    str_addr=0x400000+VirtualCodeStart+21;

    memcpy((unsigned char *)StrBuffer + choicepe + 0x10,&VirtualCodeStart,4);
    memcpy((unsigned char *)StrBuffer + CodeStart,ShellCode,ShellcodeLength);
    memcpy((unsigned char *)StrBuffer + CodeStart + 5,&str_addr,4);
    memcpy((unsigned char *)StrBuffer + CodeStart + 12,&call_msgbox,4);
    memcpy((unsigned char *)StrBuffer + CodeStart + 17,&jmp_to_home,4);
    MessageBox(0, TEXT("ע����ɣ�"), TEXT("�ɹ�"), 0);
	fclose(PointToFile);
    PointToFile = fopen(name, "wb+");
    fwrite(StrBuffer, FileSize, 1, PointToFile);
	fclose(PointToFile);	
}
