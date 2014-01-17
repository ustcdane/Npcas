#include "stdafx.h"
#include "ProtocolanalysisDlg.h"
#include <stdio.h>
#include <sys/types.h>
#include <windows.h>
#include "Protocol.h"
#include "sniffer.h"
#include "pcap.h"

extern HWND g_hWnd;//主窗口句柄
extern bool g_StopThread;//判断是否停止几截获数据包
EtherHeader g_DisplayEthernet;//链路层协议信息
PacketInformation g_packet;	//网络数据包信息
arpheader g_DisplayARP;//ARP协议信息
IcmpHeader g_DisplayIcmp;//ICMP协议信息
IpHeader g_DisplayIP;//IP协议信息
TcpHeader g_DisplayTCP;// TCP协议信息
UdpHeader g_DisplayUDP;//UDP协议信息

//注意字节序

// 解析捕获到的以太数据
int ParseEthernet(const unsigned char* packetdata,RAW_PACKET *pRawPacket)
{
	int NetType;
    MAC_HEADER* phMac;
	unsigned char *MAC;
	if (g_StopThread == TRUE)//全局变量判断,退出捕获线程
		AfxEndThread(1, 1);
	//清零
	sprintf(g_packet.SourceMac, "%s", "");
	sprintf(g_packet.DestinationMac, "%s", "");
	sprintf(g_packet.NetType, "%s", "");
	sprintf(g_packet.DestinationAddr, "%s", "");
	sprintf(g_packet.DestinationPort, "%s", "");
	sprintf(g_packet.SourceAddr, "%s", "");
	sprintf(g_packet.SourcePort, "%s", "");

	phMac = (MAC_HEADER *) packetdata;  
	NetType = ntohs(phMac->LengthOrType); //得到上层协议数据类型 
	MAC=phMac->SrcMacAddr ;
	//以太网源MAC地址
	sprintf(g_DisplayEthernet.SourceMac, "%02X:%02X:%02X:%02X:%02X:%02X",*MAC,*(MAC+1),*(MAC+2),*(MAC+3),*(MAC+4),*(MAC+5));
	strcpy(g_packet.SourceMac,g_DisplayEthernet.SourceMac);
	MAC=phMac->DesMacAddr;
	//以太网目的MAC地址
	sprintf(g_DisplayEthernet.DestinationMac, "%02X:%02X:%02X:%02X:%02X:%02X",*MAC,*(MAC+1),*(MAC+2),*(MAC+3),*(MAC+4),*(MAC+5));
	strcpy(g_packet.DestinationMac,g_DisplayEthernet.DestinationMac);
	packetdata = packetdata+sizeof(MAC_HEADER);/* 获得IP数据包头部的位置 */
	LPARAM  lp=(LPARAM)pRawPacket;//强制转化
	switch (NetType)
	{
	case 0x0800://ipv4
		sprintf(g_DisplayEthernet.NetType, "%s", "IPv4");
		//将捕获以太消息放入到与主界面线程相联系消息队列里,显示其协议信息
		::PostMessage(g_hWnd, WM_MY_MESSAGE_ETHERNET, 0, lp);
		//解析IP协议数据包
		ParseIp(packetdata,pRawPacket);
		::PostMessage(g_hWnd, WM_MY_MESSAGE_COMMON, 0, lp);
		return 0;
	case 0x0806://arp
	case 0x8035://rarp
		struct ARP *parp;
		parp=(struct ARP *)packetdata;
		if (ntohs(parp->OperationCode)<3 )//判断是否为ARP 
		{
			sprintf(g_DisplayEthernet.NetType, "%s", "ARP");
			sprintf(g_packet.NetType ,"%s","ARP");
		} 
		else//否则RARP
		{
			sprintf(g_DisplayEthernet.NetType, "%s", "RARP");
			sprintf(g_packet.NetType ,"%s","RARP");
		}
		::PostMessage(g_hWnd, WM_MY_MESSAGE_ETHERNET, 0, lp);
		//解析ARP/RARP协议信息
		ParseArp(packetdata,pRawPacket);
		::PostMessage(g_hWnd, WM_MY_MESSAGE_COMMON, 0, lp);
		return 0;
	case 0x8863: //PPPOE的发现阶段
	case 0x8864: //PPPOE的会话阶段
		sprintf(g_DisplayEthernet.NetType, "%s", "PPPoE");
		sprintf(g_packet.NetType, "%s", "PPPoE");
		::PostMessage(g_hWnd, WM_MY_MESSAGE_ETHERNET, 0,lp);
		::PostMessage(g_hWnd, WM_MY_MESSAGE_COMMON, 0, lp);
		return 0;
	case 0x86dd://IPV6
		sprintf(g_DisplayEthernet.NetType, "%s", "IPV6");
		sprintf(g_packet.NetType, "%s", "IPV6");
		::PostMessage(g_hWnd, WM_MY_MESSAGE_ETHERNET, 0, lp);
		::PostMessage(g_hWnd, WM_MY_MESSAGE_COMMON, 0, lp);
		return 0;
	default:
		sprintf(g_DisplayEthernet.NetType, "%s", "--");
		sprintf(g_packet.NetType, "%s", "--");
		::PostMessage(g_hWnd, WM_MY_MESSAGE_ETHERNET, 0, lp);
		::PostMessage(g_hWnd, WM_MY_MESSAGE_COMMON, 0, lp);
		return 0;
	}
	
	return 1;
}

// 解析捕获的ARP信息
void ParseArp(const unsigned char* packetdata,RAW_PACKET* pRawPacket)
{
	unsigned short Protocol;
	unsigned short Hardware;
	unsigned short Operation;
	struct ARP *Arp; 
	MAC_HEADER* pMacHdr = (MAC_HEADER*)pRawPacket->pPktData;
	struct ARP* pARPHdr = (struct ARP *)((BYTE*)pMacHdr+sizeof(MAC_HEADER));
	// 先对arp信息赋初值
	sprintf(g_DisplayARP.HardwareLength, "%s", "");
	sprintf(g_DisplayARP.Hardware, "%s", "");
	sprintf(g_DisplayARP.OperationCode, "%s", "");
	sprintf(g_DisplayARP.ProtocolLength, "%s", "");
	sprintf(g_DisplayARP.Protocol, "%s", "");
	sprintf(g_DisplayARP.OperationInformatin, "%s", "");
	sprintf(g_DisplayARP.SourceAddr, "%s", "");
	sprintf(g_DisplayARP.DestinationAddr, "%s", "");
	Arp = (struct ARP *) packetdata;		                   
	Hardware = ntohs(Arp->Hardware);
	Protocol = ntohs(Arp->Protocol);
	Operation = ntohs(Arp->OperationCode);
	sprintf(g_DisplayARP.HardwareLength, "%d", pARPHdr->HardwareLength);
	sprintf(g_DisplayARP.ProtocolLength, "%d", pARPHdr->ProtocolLength);
	sprintf(g_DisplayARP.Hardware, "%d", Hardware);
	sprintf(g_DisplayARP.Protocol, "%d", Protocol);
	sprintf(g_DisplayARP.OperationCode, "%d", Operation);  
	//ARP头部子节点：源IP地址
	in_addr ipAddr;
	memcpy(&ipAddr, pARPHdr->scrIpAddr, sizeof(in_addr));
	sprintf(g_DisplayARP.SourceAddr, "%s",inet_ntoa(ipAddr));
	//ARP头部子节点：目的IP地址
	memcpy(&ipAddr, pARPHdr->destIpAddr, sizeof(in_addr));
	sprintf(g_DisplayARP.DestinationAddr, "%s",inet_ntoa(ipAddr));
	LPARAM  lp=(LPARAM)pRawPacket;//强制转化
	switch (Operation)
	{
	case 1:
		sprintf(g_DisplayARP.OperationInformatin, "%s", "ARP请求");
		::PostMessage(g_hWnd, WM_MY_MESSAGE_ARP, 0, lp);
		break;
	case 2:
		sprintf(g_DisplayARP.OperationInformatin, "%s", "ARP应答");
		::PostMessage(g_hWnd, WM_MY_MESSAGE_ARP, 0, lp);
		break;
	case 3:
		sprintf(g_DisplayARP.OperationInformatin, "%s", "RARP请求");
		::PostMessage(g_hWnd, WM_MY_MESSAGE_ARP, 0, lp);
		break;
	case 4:
		sprintf(g_DisplayARP.OperationInformatin, "%s", "RARP应答");
		::PostMessage(g_hWnd, WM_MY_MESSAGE_ARP, 0, lp);
		break;
	default:
		sprintf(g_DisplayARP.OperationInformatin, "%s", "未知");
		::PostMessage(g_hWnd, WM_MY_MESSAGE_ARP, 0, lp);
		return ;
	}
}

// 解析捕获到的IP数据包
void ParseIp(const unsigned char* packetdata,RAW_PACKET* pRawPacket)
{
	struct IPV4* ip;
	unsigned int  HeaderLength;
	unsigned int 	Length;
	unsigned int 	off;
	unsigned char* pIP_data = NULL;
	unsigned int Off;
	unsigned char Tos;
	unsigned short Checksum;
	LPARAM  lp=(LPARAM)pRawPacket;//强制转化
	ip = (struct IPV4 *) packetdata;//强制转化为Ip结构的包
	/* 将网络字节序列转换成主机字节序列 */
	Length = ntohs(ip->Length);
	Checksum = ntohs(ip->Checksum);
	HeaderLength = ip->HeaderLength * 4;//首部长
	sprintf(g_DisplayIP.Version, "%d", ip->Version);
	sprintf(g_DisplayIP.HeaderLength, "%d", HeaderLength);
	Tos = ip->Tos;
	sprintf(g_DisplayIP.Tos, "%d", Tos);
	/* 将网络字节序列转换成主机字节序列 */
	sprintf(g_DisplayIP.Length, "%d", ntohs(ip->Length));
	sprintf(g_DisplayIP.Ident, "%d", ntohs(ip->Ident));
	/* 将网络字节序列转换成主机字节序列 */
	Off = ntohs(ip->Flags_Offset);
	sprintf(g_DisplayIP.Flags, "%d", (Off >>13) );
	sprintf(g_DisplayIP.Offset, "%d", (Off & 0x1fff) * 8);
	sprintf(g_DisplayIP.TTL, "%d", ip->TTL);
	sprintf(g_DisplayIP.Protocol, "%d", ip->Protocol);
	sprintf(g_DisplayIP.Checksum, "%d", Checksum);
	SOCKADDR_IN addr;
	addr.sin_addr.s_addr=ip->SourceAddr;
	sprintf(g_DisplayIP.SourceAddr, "%s", inet_ntoa(addr.sin_addr));
	addr.sin_addr.s_addr=ip->DestinationAddr;
	sprintf(g_DisplayIP.DestinationAddr, "%s", inet_ntoa(addr.sin_addr));
	strcpy(g_packet.SourceAddr ,g_DisplayIP.SourceAddr);
	strcpy(g_packet.DestinationAddr ,g_DisplayIP.DestinationAddr);	
	::PostMessage(g_hWnd, WM_MY_MESSAGE_IP, 0, lp);
	Length =Length-HeaderLength;
	off = ntohs(ip->Flags_Offset);
	if ((off & 0x1fff) == 0)
	{
		pIP_data = (unsigned char *) ip + HeaderLength;//ip数据部分,即网络层数据包
		switch (ip->Protocol)
		{
		case 6:
			sprintf(g_packet.NetType, "%s", "TCP");
			//解析TCP协议信息
			ParseTcp(pIP_data,pRawPacket);
			break;
		case 17:
			sprintf(g_packet.NetType, "%s", "UDP");
			//解析UDP协议信息
			ParseUdp(pIP_data,pRawPacket);
			break;
		case 1:
			sprintf(g_packet.NetType, "%s", "ICMP");
			//解析ICMP协议信息
			ParseIcmp(pIP_data,pRawPacket);
			break;
		case 2:
			sprintf(g_packet.NetType, "%s", "IGMP");
			break;
		default:
			sprintf(g_packet.NetType, "%s", "--");
			break;
		}
	}
}

//捕获到的ICMP数据包
void ParseIcmp(const unsigned char* packetdata,RAW_PACKET* pRawPacket)
{
	LPARAM  lp=(LPARAM)pRawPacket;//强制转化
	struct ICMP* Icmp;
	Icmp = (struct ICMP *) packetdata;
	sprintf(g_DisplayIcmp.type, "%d", Icmp->Type);
	switch (Icmp->Type)
	{
	case 0:
		sprintf(g_DisplayIcmp.information, "%s", "回显应答");
		break;
	case 8:
		sprintf(g_DisplayIcmp.information, "%s", "回显请求");
		break;
	case 13:
		sprintf(g_DisplayIcmp.information, "%s", "时间戳请求");
		break;
	case 14:
		sprintf(g_DisplayIcmp.information, "%s", "时间戳应答");
		break;
	case 17:
		sprintf(g_DisplayIcmp.information, "%s", "地址掩码请求");
		break;
	case 18:
		sprintf(g_DisplayIcmp.information, "%s", "地址掩码应答");
		break;
	default:
		sprintf(g_DisplayIcmp.information, "%s", "ICMP类型未知");
		break;
	}
	sprintf(g_DisplayIcmp.code, "%d", Icmp->Code);
	sprintf(g_DisplayIcmp.checksum, "%d", ntohs(Icmp->Checksum));
	//将捕获ICMP协议消息放入到与主界面线程相联系消息队列里,显示其协议信息
	::PostMessage(g_hWnd, WM_MY_MESSAGE_ICMP, 0, lp);
	return;
}
//解析捕获到的 TCP数据
int ParseTcp(const unsigned char* packetdata,RAW_PACKET* pRawPacket)
{
	LPARAM  lp=(LPARAM)pRawPacket;//强制转化
	struct TCP* ptcp;
	ptcp = (struct TCP *) packetdata;
	unsigned short SourcePort;
	SourcePort = ntohs(ptcp->SrcPort);
	unsigned short DestinationPort;
	DestinationPort = ntohs(ptcp->DstPort);
	int HeaderLength;
	// hdrlen_flags 4位首部长度 + 6位保留 + 6位标志
	HeaderLength = (ntohs(ptcp->hdrlen_flags)>>12)*4;//右移12位即得tcp首部长 6bit
	unsigned int  SequenceNum;
	SequenceNum = ntohl(ptcp->SequenceNum);
	unsigned int  Acknowledgment;
	Acknowledgment = ntohl(ptcp->Acknowledgment);
	unsigned short AdvertisedWindow;
	AdvertisedWindow = ntohs(ptcp->AdvertisedWindow);	
	unsigned short UrgPtr;
	UrgPtr = ntohs(ptcp->UrgPtr);
	unsigned char Flags;
	Flags = ntohs(ptcp->hdrlen_flags)&0x003f;//标志位 低6位
	sprintf(g_DisplayTCP.SrcPort, "%d", SourcePort);
	sprintf(g_DisplayTCP.DstPort, "%d", DestinationPort);
	strcpy(g_packet.DestinationPort ,g_DisplayTCP.DstPort);
	strcpy(g_packet.SourcePort ,g_DisplayTCP.SrcPort);
	sprintf(g_DisplayTCP.SequenceNum, "%u", SequenceNum);
	sprintf(g_DisplayTCP.Acknowledgment, "%u", Acknowledgment);
	sprintf(g_DisplayTCP.HdrLen, "%d", HeaderLength);
	//保留4位首部长度 + 6位保留 + 6位标志
	sprintf(g_DisplayTCP.Zero, "%d", (ntohs(ptcp->hdrlen_flags)>>6) & 0x003f );
	char myflags[1024];
	strcpy(myflags, "");
	if (Flags & 0x02)
	{
		strcat(myflags, "SYN ");
	}
	if (Flags & 0x01)
	{
		strcat(myflags, "FIN ");
	}
	if (Flags & 0x04)
	{
		strcat(myflags, "RST ");
	}
	if (Flags & 0x08)
	{
		strcat(myflags, "PSH ");
	}
	if (Flags & 0x10)
	{
		strcat(myflags, "ACK ");
	}
	if (Flags & 0x20)
	{
		strcat(myflags, "URG ");
	}
	sprintf(g_DisplayTCP.Flags, "%s", myflags);
	sprintf(g_DisplayTCP.AdvertisedWindow, "%d", AdvertisedWindow);
	sprintf(g_DisplayTCP.Checksum, "%d", ntohs(ptcp->Checksum));
	sprintf(g_DisplayTCP.UrgPtr, "%d", UrgPtr);
	//将捕获TCP消息放入到与主界面线程相联系消息队列里,显示其协议信息
	::PostMessage(g_hWnd, WM_MY_MESSAGE_TCP, 0, lp);
	//解析是含有HTTP协议
	ParseHttp(pRawPacket);
	return 0;
}
//解析是否捕获到 HTTP
void ParseHttp(RAW_PACKET* pRawPacket)
{
	LPARAM  lp=(LPARAM)pRawPacket;//强制转化
	int find_http = false;
	 /* 获得ip头 */
	struct IPV4 *ih = (struct IPV4 *)(pRawPacket->pPktData+sizeof(MAC_HEADER));
	/*将一个无符号短整形数从网络字节顺序转换为主机字节顺序,此处很重要*/
	int len = ntohs(ih->Length);//包含ip头和数据部分
	char *pip_data = (char *)(ih);
	int n = 0;
	for(;n<len; n++)
	{
		/* http get or post request */
		if(!find_http &&((n+3<len &&strncmp(pip_data+n,"GET",strlen("GET")) ==0 )
			|| (n+4<len && strncmp(pip_data+n,"POST",strlen("POST")) == 0)) )
			find_http = true;
		/* http response */
		if(!find_http && n+8<len && strncmp(pip_data+n,"HTTP/1.1",strlen("HTTP/1.1"))==0)
			find_http = true;
		if(find_http)//判断是否找到http
		{   
			//将捕获HTTP消息放入到与主界面线程相联系消息队列里,显示其协议信息
			::PostMessage(g_hWnd, WM_MY_MESSAGE_HTTP,(WPARAM)n,lp);//n相对ip偏移量的http开头
			break;
		}
	}
}
// 解析捕获到的UDP数据，并且解析看是否包含DNS协议的数据
int ParseUdp(const unsigned char* packetdata,RAW_PACKET* pRawPacket)
{
	
	LPARAM  lp=(LPARAM)pRawPacket;//强制转化
	struct UDP* udp;
	udp = (struct UDP *) packetdata;
	unsigned short SourcePort; 
	SourcePort = ntohs(udp->SrcPort);	
	unsigned short DestinationPort; 
	DestinationPort = ntohs(udp->DstPort); 
	unsigned short Length;
	Length = ntohs(udp->Length);
	sprintf(g_DisplayUDP.SrcPort, "%d", SourcePort);
	sprintf(g_DisplayUDP.DstPort, "%d", DestinationPort);
	strcpy(g_packet.DestinationPort ,g_DisplayUDP.DstPort);
	strcpy(g_packet.SourcePort ,g_DisplayUDP.SrcPort);
	sprintf(g_DisplayUDP.Length, "%d", Length);
	sprintf(g_DisplayUDP.Checksum, "%d", ntohs(udp->Checksum));
	::PostMessage(g_hWnd, WM_MY_MESSAGE_UDP, 0, lp);
	//是否含有DNS协议 通过判断端口号是否为 53
	if (SourcePort==53 || DestinationPort==53)
	{
		//将捕获UDP消息放入到与主界面线程相联系消息队列里,显示其协议信息
		::PostMessage(g_hWnd, WM_MY_MESSAGE_DNS, 0, lp);
	}
	return 0;
}
