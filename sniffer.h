#ifndef _COMMON_DEFINE_H_
#define _COMMON_DEFINE_H_
#include <stdlib.h> 
#include <stdio.h>
#include "stdafx.h"
#include "pcap.h"
//���ڴ���������ݰ���Ϣ
typedef struct
{
	char DestinationMac[100];//ԴMAC
	char SourceMac[100];//Ŀ��MAC
	char NetType[100];//Э������
	char SourceAddr[100];//ԴIP
	char DestinationAddr[100];//Ŀ��IP
	char SourcePort[100];//Դ�˿�
	char DestinationPort[100];//Ŀ��˿�
}PacketInformation;

//�����ڲ���������ݰ��ṹ����ԭʼ����
typedef struct
{
	pcap_pkthdr PktHeader;	//��ͷ����Ϣ�ṹָ��
	u_char* pPktData;		//������ָ��
	u_int ip_seq;   //�����ػ�İ�Ip���
	u_int tcpOrUdp_seq;//�����ػ�İ����
} RAW_PACKET;
int CapturePacket();
int DumpFileOperation();
#endif //_COMMON_DEFINE_H_