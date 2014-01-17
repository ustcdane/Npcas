// 此头文件用于 定义网路协议的数据结构
#ifndef _PRO_DEFINE_H_
#define _PRO_DEFINE_H_
#include <pcap.h>
#include <Winsock2.h>
#define MAX 100
//ethernet
//MAC头部
typedef struct
{
	BYTE DesMacAddr[6];		//目的地址6个字节
	BYTE SrcMacAddr[6];		//源地址6个字节
	WORD LengthOrType;		//类型
} MAC_HEADER;
//存放以太网(链路层)头部信息
typedef struct 
{
	char DestinationMac[256];
	char SourceMac[256];
	char NetType[256];
}EtherHeader;

/* IPv4 首部 */
struct IPV4
{
	unsigned char HeaderLength : 4, Version : 4;// 版本 (4 bits) + 首部长度 (4 bits)
	unsigned char Tos;// 服务类型(Type of service) 
	unsigned short Length;// 总长(Total length)
	unsigned short Ident;// 标识(Identification)
	unsigned short Flags_Offset;// 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
	unsigned char TTL;// 存活时间(Time to live)
	unsigned char Protocol;// 协议(Protocol)
	unsigned short Checksum;// 首部校验和(Header checksum)
	unsigned int SourceAddr;// 源地址(Source address)
	unsigned int DestinationAddr;// 目的地址(Destination address)
};
typedef struct 
{
	char Version[MAX];
	char HeaderLength[MAX];
	char Tos[MAX];
	char Length[MAX];
	char Ident[MAX];
	char Flags[MAX];
	char Offset[MAX];
	char TTL[MAX];
	char Protocol[MAX];
	char Checksum[MAX];
	char SourceAddr[MAX];
	char DestinationAddr[MAX];
}IpHeader;
//IPv6包头结构体
struct IPV6 {
	u_char ver_tf: 4;/*4位的版本*/
	u_char traffic;/*8位的传输与分类*/
	unsigned int label:20;/*20位的流标识符*/
	u_char length[2];/*报头长度*/
	u_char next_header;/*下一个报头*/
	u_char limits;/*跨度限制,定义IP数据包所能经过的最大跳数，每跳一次将此值减1*/
	u_char Srcv6[16];/*IP数据包的源地址*/
	u_char Destv6[16];/*IP数据包的目的地址*/
};
//ARP报文
struct ARP
{
	unsigned short Hardware; //硬件地址类型 2个字节  	 
	unsigned short Protocol; //协议地址类型 2个字节
	unsigned char HardwareLength; //硬件地址长度 1个字节
	unsigned char ProtocolLength; //协议地址长度 1个字节
	unsigned short OperationCode; //操作类型 2个字节
	u_char srcMacAddr[6];		//源以太网地址
	u_char scrIpAddr[4];		//源IP地址
	u_char destMacAddr[6];	//目的以太网地址
	u_char destIpAddr[4];		//目的IP地址
};
//ARP 描述信息
typedef struct 
{
	char Hardware[MAX];
	char Protocol[MAX];
	char HardwareLength[MAX];
	char ProtocolLength[MAX];
	char OperationCode[MAX];
	char OperationInformatin[MAX];
	char SourceAddr[MAX];
	char DestinationAddr[MAX];
}arpheader;


//ICMP基本头部
struct ICMP
{
	unsigned char Type;//8位类型
	unsigned char  Code;//8位代码
	unsigned short  Checksum;//16位校验和
};
typedef struct 
{
	char type[MAX];
	char code[MAX];
	char checksum[MAX];
	char information[MAX];
}IcmpHeader;

//tcp
struct TCP
{
	unsigned short SrcPort;//16位源端口号 			
	unsigned short DstPort; //16位目的端口号			 
	unsigned int SequenceNum; //32位序列号  			 
	unsigned int Acknowledgment;//32位确认序号   			 
	u_short hdrlen_flags;	//4位首部长度 + 6位保留 + 6位标志
	unsigned short  AdvertisedWindow;//16位窗口大小   		
	unsigned short  Checksum; 	//16位校验和  			
	unsigned short  UrgPtr;   //16位紧急指针			  
};
typedef struct 
{
	char SrcPort[MAX];			  
	char DstPort[MAX];			  
	char SequenceNum[MAX];  		
	char Acknowledgment[MAX];  		
	char Zero[MAX];   			
	char HdrLen[MAX];  			  
	char Flags[MAX];
	char AdvertisedWindow[MAX];  		
	char Checksum[MAX];  			 
	char UrgPtr[MAX];  			  
}TcpHeader;

/* UDP 首部*/
struct UDP
{
	unsigned short SrcPort;// 源端口(Source port)
	unsigned short DstPort;// 目的端口(Destination port)
	unsigned short Length;// UDP数据包长度(Datagram length)
	unsigned short Checksum;// 校验和(Checksum)
};
typedef struct 
{
	char SrcPort[MAX];
	char DstPort[MAX];
	char Length[MAX];
	char Checksum[MAX];
}UdpHeader;
//DNS 头部 12字节
struct DNS 
{
	unsigned short  d_id;           //16 bit DNS 标识
	unsigned short  d_option;       //dns 标志
	unsigned short  d_qdcount;      //问题数
	unsigned short  d_ancount;      //资源记录数
	unsigned short  d_nscount;      //授权资源记录数
	unsigned short  d_arcount;      //额外资源记录数
};
// 以下为解析相应的协议信息
void ParseArp(const unsigned char* packetdata,RAW_PACKET* pRawPacket);
int ParseEthernet(const unsigned char* packetdata,RAW_PACKET* pRawPacket);
void ParseIcmp(const unsigned char* packetdata,RAW_PACKET* pRawPacket);
void ParseIp(const unsigned char* packetdata,RAW_PACKET* pRawPacket);
int ParseTcp(const unsigned char* packetdata,RAW_PACKET* pRawPacket);
int ParseUdp(const unsigned char* packetdata,RAW_PACKET* pRawPacket);
void ParseHttp(RAW_PACKET* pRawPacket);
#endif //PRO_DEFINE_H_