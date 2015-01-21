#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/int.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/if_ethet.h>
#include <string.h>

struct arpstruct{
	u_char arp_mac[6];
	u_char arp_ip[4];

};

pcap_t *descriptor;

unsigned int x_hours=0;
unsigned int x_minutes=0;
unsigned int x_seconds=0;
unsigned int x_milliseconds=0;
unsigned int totaltime=0;
unsigned int countdown=0;
unsigned int tiempoperdido=0;
clock_t x_starttime;
clock_t x_counttime;
///definimos las funcionaes que vamos a usar
void arpspoofin();

void arpspoofin()
{

	char *netid;
	char *maskid;
	char *device;
	char errbuf[PCAP_ERRBUF_SIZE];
	const u_char *packete;
	struct pcap_pkthdr hdr;//cabezera o header
	struct ether_heather *eptr;
	struct bpf_program fp;

	bpf_u_int32 maskp;
	bpf_u_int32 netp;

	char filter_exp[]="udp dst port 8080";
	int filtro;
	int compiler;

	char nombreArchivo[40];
	char *extencion=".pcap";
	char  archivo[200] = "/home/kevin/Proyecto de Redes de Computadoras/Proyecto-de-Computadoras/"
    pcap_if_t *dispositivosdisponibles;
    pcap_if_t *dispositivo;
    pcap_t *handle;
    char errbufDispositivos[50];
    char devs[50];
    int count=1;
    int number;

    struct arpstruct datos[50];
    struct arp_struct frame;

    int i,j=0,y;
    char opciones[3];
     do
     {
     	printf("*************************************ARP SPOOFIN*******************\n");
     	printf("-i DEV,especifica la interface de red con la cual hacer sniff.\n ");
     	printf("-r FILE, lee el trafico de red de un archivo \n");
     	printf("Digite su opcion \t");
     	scanf("%s",opciones);
     	    if(strcmp(opciones,"-i")==0)
     	    {
     	    	//Esta condicion conjunta con la funcion es encontrar todos los dispositivos que se encuentran habilitados 
     	    	   if(pcap_findalldevs(&dispositivosdisponibles,errbuf))
     	    	   {
     	    	   	 printf("NO SE ENCONTRO NINGUN DISPOSITIVO %s",errbuf);
     	    	   	 exit(1);
     	    	   }

     	    	   for(dispositivos=dispositivosdisponibles;dispositivos !=NULL ;dispositivos=dispositivos->next)
     	    	   {
     	    	   	printf("%d->%s --->%s \n",count,dispositivos->name,dispositivos->description);
     	    	   	 if(dispositivos->name !=NULL)
     	    	   	 {
     	    	   	 	strcpy(devs[count],device->name);
     	    	   	 }
     	    	   	 count++;

     	    	   }

     	    	   printf("NUMERO DE DISPOSITIVO PARA HACER SNIFFING \n");
     	    	   scanf("%d",&number);
     	    	   printf("Tiempo de lapso maximo para hacer deteccion");
     	    	   scanf("%d",&countdown);
     	    	   dev=devs[number];
     	    	   
     	    }
     }



}
