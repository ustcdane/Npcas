#include "stdafx.h"
#include "ProtocolanalysisDlg.h"
#include "Protocol.h"
#include "devicedialog.h"
#include "sniffer.h"
CProtocolAnalysisDlg *g_pdlg;
int g_network_device;//ѡ��Ҫ�����������
char g_network_device_name[1024][1024];//�������ӿ�����
int g_network_device_number;
extern char g_PacketFilter[1024];//�������
//����ص���������
typedef void (*pcap_func_t)(unsigned char*, const struct pcap_pkthdr*, const u_char*);
/* �ص����������յ�ÿһ�����ݰ�ʱ�ᱻlibpcap������ */
void ProcessProtocolPacket(unsigned char* user, const struct pcap_pkthdr* h,
						   const unsigned char* packetdata)
						   //�мɴ˴���packetdata��Ϊ������������������ݰ�
						   //�ڶ�������h�ǲ�����������ݰ��ļ���Ϣ
{	
	//�����ݰ����浽����
	RAW_PACKET* pRawPacket = new RAW_PACKET;
	pRawPacket->ip_seq =0;//�����Ϊ��ʼΪ 0
	pRawPacket->tcpOrUdp_seq =0;
	memcpy(&pRawPacket->PktHeader, h, sizeof(pcap_pkthdr));
	u_char* pPktData = new u_char[h->caplen];
	memcpy(pPktData, packetdata, h->caplen);//ע��˴�Ϊpacketdata�� ������
	pRawPacket->pPktData = pPktData;
	pcap_dump(user, h, packetdata);//ʵʱ����ػ񵽵�����
	ParseEthernet(packetdata,pRawPacket);//������·�� ��̫����Ϣ
}

void ProcessProtocolPacketFromDumpFile(unsigned char* user, const struct pcap_pkthdr* h,
									   const unsigned char* packetdata)
{	
	//�����ݰ����浽����
	RAW_PACKET* pRawPacket = new RAW_PACKET;
	pRawPacket->ip_seq =0;//�����Ϊ��ʼΪ 0
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
	if (pcap_findalldevs(&NetworkDevice, Error) == -1)//������������豸�б�
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
		/* �ͷ��豸�б� */
		pcap_freealldevs(NetworkDevice);
		return -1;
	}
	/* ��ת��ѡ�е������� */
	for (DeviceIndex = NetworkDevice, i = 0; i < DeviceId - 1 ; DeviceIndex = DeviceIndex->next, i++)
		;
	/*�������豸׼�������������ݰ�*/
	if ((PcapHandle = pcap_open_live(DeviceIndex->name,// �豸��
						65536, // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
						1 ,// ����ģʽ
						1000,// ��ȡ��ʱʱ��
						Error// ���󻺳��
						)) == NULL)
	{
		return -1;
	}
	char* Interface = NULL;
	CString strFilePath=g_pdlg->m_strFilePath; //·��
	strFilePath+=_T("\\temp.pcap");
	//���������ݰ��ļ�(�򿪶��ļ�) 
	PcapFile = pcap_dump_open(PcapHandle, strFilePath);
	if (CaptureFilter != NULL)
	{
		//�����������
		if (Interface != NULL)
		{    
			if (pcap_lookupnet(Interface, &SubNet, &NetMask, Error) < 0)
			{
				return 0;
			}
		}
		else
		{
			/* �������ӿ�û�е�ַ����ô���Ǽ�������ӿ���C�������� */
			NetMask = 0xffffff;
		}
		//������˹���
		if (pcap_compile(PcapHandle, &FilterCode, CaptureFilter, 1, NetMask) < 0)
		{
			/* �ͷ��豸�б� */
			pcap_freealldevs(NetworkDevice);
			::MessageBox(g_pdlg->m_hWnd,_T("���ܱ�����˹���!"),_T("����"),MB_DEFBUTTON1);
			return -1;
		} 
		//���ù��˹���
		if (pcap_setfilter(PcapHandle, &FilterCode) < 0)
		{
			/* �ͷ��豸�б� */
			pcap_freealldevs(NetworkDevice);
			::MessageBox(g_pdlg->m_hWnd,_T("���˹�����������!"),_T("����"),MB_DEFBUTTON1);
			return -1;
		}
	}
	/* ÿ�β������ݰ�ʱ��libpcap�����Զ���������ص����� */
	Handler = (pcap_func_t)ProcessProtocolPacket;
	/* ��ʼ���� */
	pcap_loop(PcapHandle, number, Handler, (unsigned char *)PcapFile);
	return 0;
}
//�Ӷ��ļ��ж�ȡ���ݰ�,�ѻ��ļ��ж�ȡ���ݰ�
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
			::MessageBox(g_pdlg->m_hWnd,_T("���ܱ�����˹���!"),_T("����"),MB_ICONWARNING);
			return -1;
		} 
		if (pcap_setfilter(PcapHandle, &FilterCode) < 0)
		{
			::MessageBox(g_pdlg->m_hWnd,_T("���˹�����������!"),_T("����"),MB_ICONWARNING);
			return -1;
		}
	}
	/* �ص������������������ݰ� */
	Handler = (pcap_func_t)ProcessProtocolPacketFromDumpFile;
	// ��ȡ���������ݰ���ֱ��EOFΪ��
	pcap_loop(PcapHandle, number, Handler, NULL);
	return 0;
}
