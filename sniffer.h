#ifndef _COMMON_DEFINE_H_
#define _COMMON_DEFINE_H_
#include <stdlib.h> 
#include <stdio.h>
#include "stdafx.h"
#include "pcap.h"
//用于存放网络数据包信息
typedef struct
{
	char DestinationMac[100];//源MAC
	char SourceMac[100];//目的MAC
	char NetType[100];//协议类型
	char SourceAddr[100];//源IP
	char DestinationAddr[100];//目的IP
	char SourcePort[100];//源端口
	char DestinationPort[100];//目标端口
}PacketInformation;

//程序内部保存的数据包结构，即原始数据
typedef struct
{
	pcap_pkthdr PktHeader;	//包头部信息结构指针
	u_char* pPktData;		//包数据指针
	u_int ip_seq;   //网络层截获的包Ip序号
	u_int tcpOrUdp_seq;//传输层截获的包序号
} RAW_PACKET;
int CapturePacket();
int DumpFileOperation();
#endif //_COMMON_DEFINE_H_