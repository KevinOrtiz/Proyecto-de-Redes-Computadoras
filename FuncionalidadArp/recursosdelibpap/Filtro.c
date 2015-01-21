#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#define SIZE 200
void callback(u_char *useless, const struct pcap_pkthdr* pkthdr,const u_char *packet)
{
	static int count=1;
	fprintf(stdout, "%d\n",count );
	fflush(stdout);
	count++;

}

int main(int argc, char **argv)
{
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	struct bpf_program fp;
	bpf_u_int32 maskp;
	bpf_u_int32 netp;

	 //Busca el dispositivo
	 dev=pcap_lookupdev(errbuf);
     if(dev==NULL)
     {
     	fprintf(stderr, "%s\n",errbuf );
     }
     else
     {
     	printf( "Abriendo %s en modo promiscuo\n",dev);
     }
    pcap_lookupnet(dev,&netp,&maskp,errbuf);
    descr=pcap_open_live(dev,SIZE,1,2000,errbuf);
    if(descr==NULL)
    {
    	printf("pcap_open_live():%s \n",errbuf);
    	exit(1);
    }
    if(pcap_compile(descr,&fp,argv[1],0,netp)==-1)
    {
    	fprintf(stderr, "Error al compilar el filtro \n");
    	exit(1);

    }
    if(pcap_setfilter(descr,&fp)==-1)
    {
    	fprintf(stderr, "Error al aplicar el filtro");
    	exit(1);
    }
    pcap_loop(descr,-1,callback,NULL);
    return;

}