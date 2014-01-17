// ��ͷ�ļ����� ������·Э������ݽṹ
#ifndef _PRO_DEFINE_H_
#define _PRO_DEFINE_H_
#include <pcap.h>
#include <Winsock2.h>
#define MAX 100
//ethernet
//MACͷ��
typedef struct
{
	BYTE DesMacAddr[6];		//Ŀ�ĵ�ַ6���ֽ�
	BYTE SrcMacAddr[6];		//Դ��ַ6���ֽ�
	WORD LengthOrType;		//����
} MAC_HEADER;
//�����̫��(��·��)ͷ����Ϣ
typedef struct 
{
	char DestinationMac[256];
	char SourceMac[256];
	char NetType[256];
}EtherHeader;

/* IPv4 �ײ� */
struct IPV4
{
	unsigned char HeaderLength : 4, Version : 4;// �汾 (4 bits) + �ײ����� (4 bits)
	unsigned char Tos;// ��������(Type of service) 
	unsigned short Length;// �ܳ�(Total length)
	unsigned short Ident;// ��ʶ(Identification)
	unsigned short Flags_Offset;// ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)
	unsigned char TTL;// ���ʱ��(Time to live)
	unsigned char Protocol;// Э��(Protocol)
	unsigned short Checksum;// �ײ�У���(Header checksum)
	unsigned int SourceAddr;// Դ��ַ(Source address)
	unsigned int DestinationAddr;// Ŀ�ĵ�ַ(Destination address)
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
//IPv6��ͷ�ṹ��
struct IPV6 {
	u_char ver_tf: 4;/*4λ�İ汾*/
	u_char traffic;/*8λ�Ĵ��������*/
	unsigned int label:20;/*20λ������ʶ��*/
	u_char length[2];/*��ͷ����*/
	u_char next_header;/*��һ����ͷ*/
	u_char limits;/*�������,����IP���ݰ����ܾ��������������ÿ��һ�ν���ֵ��1*/
	u_char Srcv6[16];/*IP���ݰ���Դ��ַ*/
	u_char Destv6[16];/*IP���ݰ���Ŀ�ĵ�ַ*/
};
//ARP����
struct ARP
{
	unsigned short Hardware; //Ӳ����ַ���� 2���ֽ�  	 
	unsigned short Protocol; //Э���ַ���� 2���ֽ�
	unsigned char HardwareLength; //Ӳ����ַ���� 1���ֽ�
	unsigned char ProtocolLength; //Э���ַ���� 1���ֽ�
	unsigned short OperationCode; //�������� 2���ֽ�
	u_char srcMacAddr[6];		//Դ��̫����ַ
	u_char scrIpAddr[4];		//ԴIP��ַ
	u_char destMacAddr[6];	//Ŀ����̫����ַ
	u_char destIpAddr[4];		//Ŀ��IP��ַ
};
//ARP ������Ϣ
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


//ICMP����ͷ��
struct ICMP
{
	unsigned char Type;//8λ����
	unsigned char  Code;//8λ����
	unsigned short  Checksum;//16λУ���
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
	unsigned short SrcPort;//16λԴ�˿ں� 			
	unsigned short DstPort; //16λĿ�Ķ˿ں�			 
	unsigned int SequenceNum; //32λ���к�  			 
	unsigned int Acknowledgment;//32λȷ�����   			 
	u_short hdrlen_flags;	//4λ�ײ����� + 6λ���� + 6λ��־
	unsigned short  AdvertisedWindow;//16λ���ڴ�С   		
	unsigned short  Checksum; 	//16λУ���  			
	unsigned short  UrgPtr;   //16λ����ָ��			  
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

/* UDP �ײ�*/
struct UDP
{
	unsigned short SrcPort;// Դ�˿�(Source port)
	unsigned short DstPort;// Ŀ�Ķ˿�(Destination port)
	unsigned short Length;// UDP���ݰ�����(Datagram length)
	unsigned short Checksum;// У���(Checksum)
};
typedef struct 
{
	char SrcPort[MAX];
	char DstPort[MAX];
	char Length[MAX];
	char Checksum[MAX];
}UdpHeader;
//DNS ͷ�� 12�ֽ�
struct DNS 
{
	unsigned short  d_id;           //16 bit DNS ��ʶ
	unsigned short  d_option;       //dns ��־
	unsigned short  d_qdcount;      //������
	unsigned short  d_ancount;      //��Դ��¼��
	unsigned short  d_nscount;      //��Ȩ��Դ��¼��
	unsigned short  d_arcount;      //������Դ��¼��
};
// ����Ϊ������Ӧ��Э����Ϣ
void ParseArp(const unsigned char* packetdata,RAW_PACKET* pRawPacket);
int ParseEthernet(const unsigned char* packetdata,RAW_PACKET* pRawPacket);
void ParseIcmp(const unsigned char* packetdata,RAW_PACKET* pRawPacket);
void ParseIp(const unsigned char* packetdata,RAW_PACKET* pRawPacket);
int ParseTcp(const unsigned char* packetdata,RAW_PACKET* pRawPacket);
int ParseUdp(const unsigned char* packetdata,RAW_PACKET* pRawPacket);
void ParseHttp(RAW_PACKET* pRawPacket);
#endif //PRO_DEFINE_H_