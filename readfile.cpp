int Cmcf6Dlg::lixsniff_readFile(CString path)
{
	int res,nItem,i ;
	struct tm *ltime;
	CString timestr,buf,srcMac,destMac;
	time_t local_tv_sec;
	struct pcap_pkthdr *header;									  //���ݰ�ͷ
	const u_char *pkt_data=NULL;     //�������յ����ֽ�������
	u_char *ppkt_data;

	Cmcf6Dlg *pthis =this;						//Щ���������lixsinff_CapThread��Ϊ��Լ���������ʱ���pthisָ��
	pcap_t *fp;

	//���ȴ���һ��·��������pcap_open_offline���ļ�ʱ��
	//·����Ҫ��char *���ͣ�������CStringǿ��ת�����char *
	int len = path.GetLength()+1;							/////////////////////////////////ע����һ��ϸ�ڣ�����Ҫ��1����������
	char* charpath = (char *)malloc(len);
	memset(charpath,0,len);
	if(NULL==charpath)
		return -1;

	for(i=0;i<len;i++)
		charpath[i] = (char)path.GetAt(i);

	//������ļ�
	if ((fp = pcap_open_offline( /*(char*)(LPCTSTR)path*/charpath, errbuf)) == NULL)
	{
		MessageBox(_T("���ļ�����")+CString(errbuf));
		return -1;
	}

	while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		struct datapkt *data = (struct datapkt*)malloc(sizeof(struct datapkt));
		memset(data,0,sizeof(struct datapkt));

		if(NULL == data)
		{
			MessageBox(_T("�ռ��������޷������µ����ݰ�"));
			return  -1;
		}

 	    //������������������ݰ����ڴ���Χ��
		if(analyze_frame(pkt_data,data,&(pthis->npacket))<0)
			 continue;

		//���¸������ݰ�����
		pthis->lixsniff_updateNPacket();

		//�����ػ��������װ��һ�������У��Ա����ʹ��
		ppkt_data = (u_char*)malloc(header->len);
		memcpy(ppkt_data,pkt_data,header->len);

		pthis->m_localDataList.AddTail(data);
		pthis->m_netDataList.AddTail(ppkt_data);

		/*Ԥ�������ʱ�䡢����*/
		data->len = header->len;								//��·���յ������ݳ���
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		data->time[0] = ltime->tm_year+1900;
		data->time[1] = ltime->tm_mon+1;
		data->time[2] = ltime->tm_mday;
		data->time[3] = ltime->tm_hour;
		data->time[4] = ltime->tm_min;
		data->time[5] = ltime->tm_sec;

		/*Ϊ�½��յ������ݰ���listControl���½�һ��item*/
		buf.Format(_T("%d"),pthis->npkt);
		nItem = pthis->m_listCtrl.InsertItem(pthis->npkt,buf);

		/*��ʾʱ���*/
		timestr.Format(_T("%d/%d/%d  %d:%d:%d"),data->time[0],
			data->time[1],data->time[2],data->time[3],data->time[4],data->time[5]);
		pthis->m_listCtrl.SetItemText(nItem,1,timestr);

		/*��ʾ����*/
		buf.Empty();
		buf.Format(_T("%d"),data->len);
		pthis->m_listCtrl.SetItemText(nItem,2,buf);

		/*��ʾԴMAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"),data->ethh->src[0],data->ethh->src[1],
							data->ethh->src[2],data->ethh->src[3],data->ethh->src[4],data->ethh->src[5]);
		pthis->m_listCtrl.SetItemText(nItem,3,buf);

		/*��ʾĿ��MAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"),data->ethh->dest[0],data->ethh->dest[1],
							data->ethh->dest[2],data->ethh->dest[3],data->ethh->dest[4],data->ethh->dest[5]);
		pthis->m_listCtrl.SetItemText(nItem,4,buf);

		/*���Э��*/
		pthis->m_listCtrl.SetItemText(nItem,5,CString(data->pktType));

		/*���ԴIP*/
		buf.Empty();
		if(0x0806== data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"),data->arph->ar_srcip[0],
				data->arph->ar_srcip[1],data->arph->ar_srcip[2],data->arph->ar_srcip[3]);
		}else  if(0x0800 == data->ethh->type){
			struct  in_addr in;
			in.S_un.S_addr = data->iph->saddr;
			buf = CString(inet_ntoa(in));
		}else if(0x86dd == data->ethh->type){
			int i;
			for(i=0;i<8;i++)
			{
				if(i<=6)
					buf.AppendFormat(_T("%02x-"),data->iph6->saddr[i]);
				else
					buf.AppendFormat(_T("%02x"),data->iph6->saddr[i]);
			}
		}
		pthis->m_listCtrl.SetItemText(nItem,6,buf);

		/*���Ŀ��IP*/
		buf.Empty();
		if(0x0806 == data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"),data->arph->ar_destip[0],
				data->arph->ar_destip[1],data->arph->ar_destip[2],data->arph->ar_destip[3]);
		}else if(0x0800 == data->ethh->type) {
			struct  in_addr in;
			in.S_un.S_addr = data->iph->daddr;
			buf = CString(inet_ntoa(in));
		}else if(0x86dd == data->ethh->type){
			int i;
			for(i=0;i<8;i++)
			{
				if(i<=6)

					buf.AppendFormat(_T("%02x-"),data->iph6->daddr[i]);
				else
					buf.AppendFormat(_T("%02x"),data->iph6->daddr[i]);
			}
		}
		pthis->m_listCtrl.SetItemText(nItem,7,buf);

		/*�԰�����*/
		pthis->npkt++;
	}

	pcap_close(fp);

	return 1;
}
