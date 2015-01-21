#include <pcap.h>
#include <stdio.h>
#define SIZE 200
int main()
{
	pcap_t *handle;
	char *dev;
	char  errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	char filter_app[]="port 8080";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet;

	//Defenimos el dispositivo
	dev=pcap_lookupdev(errbuf);

	pcap_lookupnet(dev,&net,&mask,errbuf);

	handle=pcap_open_live(dev,SIZE,1,20,errbuf);

	pcap_compile(handle,&filter,filter_app,0,net);
	pcap_setfilter(handle,&filter);

	packet=pcap_next(handle,&header);
	printf("SE TIENE UN PAQUETE CON LONGITUD %d \n",header.len );
	pcap_close(handle);
	return 0;
}