#ifndef PROTOCOL_H
#define PROTOCOL_H
#define PROTO_ICMP 1
#define PROTO_TCP 6					
#define PROTO_UDP 17					 
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN    4321


//Mac֡ͷ ռ14���ֽ�
typedef struct ethhdr
{
	u_char dest[6];			//6���ֽ� Ŀ���ַ
	u_char src[6];				//6���ֽ� Դ��ַ
	u_short type;				//2���ֽ� ����0x0806 arp�� 0x0800 ipv4��0x86dd  ipv6

};

//ARPͷ 0x0806
typedef struct arphdr
{
	u_short ar_hrd;						//Ӳ�����ͣ�2���ֽ�
	u_short ar_pro;						//Э�����ͣ�2
	u_char ar_hln;						//Ӳ����ַ���ȣ�1
	u_char ar_pln;						//Э���ַ���ȣ�1
	u_short ar_op;						//�����룬1Ϊ���� 2Ϊ�ظ���2
	u_char ar_srcmac[6];			  //���ͷ�MAC��6
	u_char ar_srcip[4];				  //���ͷ�IP��4
	u_char ar_destmac[6];			  //���շ�MAC��6
	u_char ar_destip[4];				//���շ�IP��4
};

//����IPv4 ͷ0x0800 20�ֽ�
typedef struct iphdr
{
#if defined(LITTLE_ENDIAN)
	u_char ihl:4;            //�ײ�����
    u_char version:4;        //�汾
#elif defined(BIG_ENDIAN)
	u_char version:4;       //�汾  
	u_char  ihl:4;           //�ײ�����
#endif
	u_char tos;				//TOS �������� 8λ
	u_short tlen;			//���ܳ� u_shortռ�����ֽ� 16λ
	u_short id;				//��ʶ 3λ
	u_short frag_off;	//Ƭλ��  13λ
	u_char ttl;				//����ʱ�� 8λ
	u_char proto;		//�����Э��    8λ
	u_short check;		//У���  16λ
	u_int saddr;			//Դ��ַ  32λ
	u_int daddr;			//Ŀ�ĵ�ַ 32λ
	u_int	op_pad;		//ѡ���
};

//����TCPͷ 20�ֽ�
typedef struct tcphdr
{
	u_short sport;							//Դ�˿ڵ�ַ  16λ
	u_short dport;							//Ŀ�Ķ˿ڵ�ַ 16λ
	u_int seq;									//���к� 32λ
	u_int ack_seq;							//ȷ�����к� 
#if defined(LITTLE_ENDIAN)
	u_short res1:4,     //res1Ϊ����λ
				doff:4, //doffռ4λ����ʾ�ײ����ȣ����ĵ�λ�����ֽڣ�����32bit
				fin:1,  //������־λ���� fin: ���Ͷ���ɷ�������
				syn:1,  //syn: ͬ����ţ���������һ������
				rst:1,  //rst: �ؽ�����
				psh:1,  //psh: ���շ�Ӧ�þ��콫������Ķν���Ӧ�ò�
				ack:1,  //ack: ȷ�������Ч
				urg:1,  //urg: ����ָ����Ч
				ece:1,  //ӵ����־λ
				cwr:1;  //ӵ����־λ
#elif defined(BIG_ENDIAN)
	u_short doff:4,
				res1:4,
				cwr:1,
				ece:1,
				urg:1,
				ack:1,
				psh:1,
				rst:1,
				syn:1,
				fin:1;
#endif
	u_short window;					//���ڴ�С 16λ
	u_short check;						//У��� 16λ
	u_short urg_ptr;					//����ָ�� 16λ
	u_int opt;								//ѡ��
};

//����UDPͷ
typedef struct udphdr
{
	u_short sport;		//Դ�˿�  16λ
	u_short dport;		//Ŀ�Ķ˿� 16λ
	u_short len;			//���ݱ����� 16λ
	u_short check;		//У��� 16λ	
};

//����ICMP
typedef struct icmphdr
{
	u_char type;			//8λ ����
	u_char code;			//8λ ����
	u_char seq;			//���к� 8λ
	u_char chksum;		//8λУ���
};

//����IPv6
typedef struct iphdr6
{
	u_int version:4,				//�汾
			flowtype:8,			//������
			flowid:20;				//����ǩ
	u_short plen;					//��Ч�غɳ���
	u_char nh;						//��һ��ͷ����0x3a ��ʾ�ϲ���icmpv6��0x06 ��ʾ�ϲ���tcp��0x11 ��ʾ�ϲ���udp
	u_char hlim;					//������
	u_short saddr[8];			//Դ��ַ
	u_short daddr[8];			//Ŀ�ĵ�ַ
};

//����ICMPv6
typedef struct icmphdr6
{
	u_char type;			//8λ ����
	u_char code;			//8λ ����
	u_char seq;			//���к� 8λ
	u_char chksum;		//8λУ���
	u_char op_type;	//ѡ�����
	u_char op_len;		//ѡ�����
	u_char op_ethaddr[6];		//ѡ���·���ַ
};

//�Ը��ְ����м���
typedef struct pktcount
{
	int n_ip;
	int n_ip6;
	int n_arp;
	int n_tcp;
	int n_udp;
	int n_icmp;
	int n_icmp6;
	int n_http;
	int n_other;
	int n_sum;
};

//Ҫ��������ݽṹ
typedef struct datapkt
{	
	char  pktType[8];					//������
	int time[6];								//ʱ��
	int len;									//����

	struct ethhdr* ethh;				//��·���ͷ

	struct arphdr* arph;				//ARP��ͷ
	struct iphdr* iph;					//IP��ͷ
	struct iphdr6* iph6;				//IPV6

	struct icmphdr* icmph;		//ICMP��ͷ
	struct icmphdr6* icmph6;	//ICMPv6��ͷ
	struct udphdr* udph;			//UDP��ͷ
	struct tcphdr* tcph;				//TCP��ͷ

	void *apph;							//Ӧ�ò��ͷ
};
#endif