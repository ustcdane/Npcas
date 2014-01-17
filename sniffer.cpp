#include "stdafx.h"
#include "ProtocolanalysisDlg.h"
#include "Protocol.h"
#include "devicedialog.h"
#include "sniffer.h"
CProtocolAnalysisDlg *g_pdlg;
int g_network_device;//选择要捕获的网卡号
char g_network_device_name[1024][1024];//存放网络接口名字
int g_network_device_number;
extern char g_PacketFilter[1024];//过滤语句
//定义回调函数类型
typedef void (*pcap_func_t)(unsigned char*, const struct pcap_pkthdr*, const u_char*);
/* 回调函数，当收到每一个数据包时会被libpcap所调用 */
void ProcessProtocolPacket(unsigned char* user, const struct pcap_pkthdr* h,
						   const unsigned char* packetdata)
						   //切忌此处的packetdata才为捕获的真正的网络数据包
						   //第二个参数h是捕获的网络数据包的简单信息
{	
	//把数据包保存到堆中
	RAW_PACKET* pRawPacket = new RAW_PACKET;
	pRawPacket->ip_seq =0;//包序号为初始为 0
	pRawPacket->tcpOrUdp_seq =0;
	memcpy(&pRawPacket->PktHeader, h, sizeof(pcap_pkthdr));
	u_char* pPktData = new u_char[h->caplen];
	memcpy(pPktData, packetdata, h->caplen);//注意此处为packetdata， 包数据
	pRawPacket->pPktData = pPktData;
	pcap_dump(user, h, packetdata);//实时保存截获到的数据
	ParseEthernet(packetdata,pRawPacket);//解析链路层 以太网信息
}

void ProcessProtocolPacketFromDumpFile(unsigned char* user, const struct pcap_pkthdr* h,
									   const unsigned char* packetdata)
{	
	//把数据包保存到堆中
	RAW_PACKET* pRawPacket = new RAW_PACKET;
	pRawPacket->ip_seq =0;//包序号为初始为 0
	pRawPacket->tcpOrUdp_seq =0;
	memcpy(&pRawPacket->PktHeader, h, sizeof(pcap_pkthdr));
	u_char* pPktData = new u_char[h->caplen];
	memcpy(pPktData,packetdata, h->caplen);
	pRawPacket->pPktData = pPktData;
	ParseEthernet(packetdata, pRawPacket);
}
int CapturePacket()
{
	pcap_if_t *NetworkDevice;
	pcap_if_t *DeviceIndex;
	int number = -1;  
	pcap_t* PcapHandle;
	u_int DeviceId;
	char Error[PCAP_ERRBUF_SIZE];
	char CaptureFilter[1024];
	pcap_handler Handler;
	bpf_u_int32 SubNet, NetMask;
	struct bpf_program FilterCode;	
	pcap_dumper_t *PcapFile;
	strcpy(CaptureFilter, g_PacketFilter);
	if (pcap_findalldevs(&NetworkDevice, Error) == -1)//获得主机网络设备列表
	{
		AfxMessageBox(Error);
		exit(1);
	}
	int i=0;
	g_network_device_number=0;
	for(DeviceIndex=NetworkDevice; DeviceIndex; DeviceIndex=DeviceIndex->next)
    {
		sprintf(g_network_device_name[i],"%s",DeviceIndex->name);
		++i;
		g_network_device_number++;
    }
	if (i == 0)
	{
		return -1;
	}
	CDeviceDialog dia;
	int result =dia.DoModal ();
	if(result!=IDOK)
	{
		return -1;
	}
	DeviceId = g_network_device;
	if (DeviceId <1 || DeviceId> i)
	{
		/* 释放设备列表 */
		pcap_freealldevs(NetworkDevice);
		return -1;
	}
	/* 跳转到选中的适配器 */
	for (DeviceIndex = NetworkDevice, i = 0; i < DeviceId - 1 ; DeviceIndex = DeviceIndex->next, i++)
		;
	/*打开网络设备准备捕获网络数据包*/
	if ((PcapHandle = pcap_open_live(DeviceIndex->name,// 设备名
						65536, // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
						1 ,// 混杂模式
						1000,// 读取超时时间
						Error// 错误缓冲池
						)) == NULL)
	{
		return -1;
	}
	char* Interface = NULL;
	CString strFilePath=g_pdlg->m_strFilePath; //路径
	strFilePath+=_T("\\temp.pcap");
	//打开网络数据包文件(打开堆文件) 
	PcapFile = pcap_dump_open(PcapHandle, strFilePath);
	if (CaptureFilter != NULL)
	{
		//获得子网掩码
		if (Interface != NULL)
		{    
			if (pcap_lookupnet(Interface, &SubNet, &NetMask, Error) < 0)
			{
				return 0;
			}
		}
		else
		{
			/* 如果这个接口没有地址，那么我们假设这个接口在C类网络中 */
			NetMask = 0xffffff;
		}
		//编译过滤规则
		if (pcap_compile(PcapHandle, &FilterCode, CaptureFilter, 1, NetMask) < 0)
		{
			/* 释放设备列表 */
			pcap_freealldevs(NetworkDevice);
			::MessageBox(g_pdlg->m_hWnd,_T("不能编译过滤规则!"),_T("错误"),MB_DEFBUTTON1);
			return -1;
		} 
		//设置过滤过则
		if (pcap_setfilter(PcapHandle, &FilterCode) < 0)
		{
			/* 释放设备列表 */
			pcap_freealldevs(NetworkDevice);
			::MessageBox(g_pdlg->m_hWnd,_T("过滤规则设置有误!"),_T("错误"),MB_DEFBUTTON1);
			return -1;
		}
	}
	/* 每次捕获到数据包时，libpcap都会自动调用这个回调函数 */
	Handler = (pcap_func_t)ProcessProtocolPacket;
	/* 开始捕获 */
	pcap_loop(PcapHandle, number, Handler, (unsigned char *)PcapFile);
	return 0;
}
//从堆文件中读取数据包,脱机文件中读取数据包
int DumpFileOperation()
{
	int number = -1;  
	pcap_t* PcapHandle;
	u_int i = 0;
	char Error[PCAP_ERRBUF_SIZE];
	char* Interface = NULL;
	char CapFilter[1024];
	strcpy(CapFilter, g_PacketFilter);
	pcap_handler Handler;
	bpf_u_int32 SubNet, NetMask;
	struct bpf_program FilterCode;
	CString pcap_file_name;
	LPCTSTR szTypes =_T("tcpdump Files (*.pcap)|*.pcap|")
		_T("libpcap Files (*.cap)|*.cap|")
		_T("All Files (*.*)|*.*||");
	CFileDialog *pdlg= new CFileDialog( TRUE, _T("pcap"), NULL, OFN_HIDEREADONLY, szTypes );
	int result=pdlg->DoModal();
	if(result==IDOK)
	{
		pcap_file_name=pdlg->GetFileName ();
	}
	else
	{
		return -1;
	}
	delete pdlg;
	PcapHandle=pcap_open_offline(pcap_file_name,Error);
	if(PcapHandle==NULL)
	{
		AfxMessageBox(Error);
		return -1;
	}
	if (CapFilter != NULL)
	{
		if (Interface != NULL)
		{
			if (pcap_lookupnet(Interface, &SubNet, &NetMask, Error) < 0)
			{
				return 0;
			}
		}
		else
			NetMask = 0xffffff;
		if (pcap_compile(PcapHandle, &FilterCode, CapFilter, 1, NetMask) < 0)
		{
			::MessageBox(g_pdlg->m_hWnd,_T("不能编译过滤规则!"),_T("错误"),MB_ICONWARNING);
			return -1;
		} 
		if (pcap_setfilter(PcapHandle, &FilterCode) < 0)
		{
			::MessageBox(g_pdlg->m_hWnd,_T("过滤规则设置有误!"),_T("错误"),MB_ICONWARNING);
			return -1;
		}
	}
	/* 回调函数，用来处理数据包 */
	Handler = (pcap_func_t)ProcessProtocolPacketFromDumpFile;
	// 读取并解析数据包，直到EOF为真
	pcap_loop(PcapHandle, number, Handler, NULL);
	return 0;
}
