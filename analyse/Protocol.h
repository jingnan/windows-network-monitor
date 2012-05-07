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
	u_char dest[6];			    //6���ֽ� Ŀ���ַ
	u_char src[6];				//6���ֽ� Դ��ַ
	u_short type;				//2���ֽ� ����
};

//ARPͷ
typedef struct arphdr
{
	u_short ar_hrd;						//Ӳ������
	u_short ar_pro;						//Э������
	u_char ar_hln;						//Ӳ����ַ����
	u_char ar_pln;						//Э���ַ����
	u_short ar_op;					    //�����룬1Ϊ���� 2Ϊ�ظ�
	u_char ar_srcmac[6];			    //���ͷ�MAC
	u_char ar_srcip[4];				    //���ͷ�IP
	u_char ar_destmac[6];			    //���շ�MAC
	u_char ar_destip[4];			    //���շ�IP
};

//����IPͷ 
typedef struct iphdr
{
#if defined(LITTLE_ENDIAN)
	u_char ihl:4;
    u_char version:4;
#elif defined(BIG_ENDIAN)
	u_char version:4;
	u_char  ihl:4;
#endif
	u_char tos;				//TOS ��������
	u_short tlen;			//���ܳ� u_shortռ�����ֽ�
	u_short id;				//��ʶ
	u_short frag_off;	//Ƭλ��
	u_char ttl;				//����ʱ��
	u_char proto;		//Э��
	u_short check;		//У���
	u_int saddr;			//Դ��ַ
	u_int daddr;			//Ŀ�ĵ�ַ
	u_int	op_pad;		//ѡ���
};


//����TCPͷ
typedef struct tcphdr
{
	u_short sport;							//Դ�˿ڵ�ַ  16λ
	u_short dport;							//Ŀ�Ķ˿ڵ�ַ 16λ
	u_int seq;									//���к� 32λ
	u_int ack_seq;							//ȷ�����к� 
#if defined(LITTLE_ENDIAN)
	u_short res1:4,
				doff:4,
				fin:1,
				syn:1,
				rst:1,
				psh:1,
				ack:1,
				urg:1,
				ece:1,
				cwr:1;
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
	u_short window;					    //���ڴ�С 16λ
	u_short check;						//У��� 16λ
	u_short urg_ptr;					//����ָ�� 16λ
	u_int opt;						    //ѡ��
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
//#if defined(BIG_ENDIAN)
	u_int version:4,				//�汾
			flowtype:8,			//������
			flowid:20;				//����ǩ
/*#elif defined(LITTLE_ENDIAN)
u_int  flowid:20,				//����ǩ
			flowtype:8,			//������
			version:4;				//�汾
//#endif*/
	u_short plen;					//��Ч�غɳ���
	u_char nh;						//��һ��ͷ��
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

//////////////////////////////////////////////////////////////////////////
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