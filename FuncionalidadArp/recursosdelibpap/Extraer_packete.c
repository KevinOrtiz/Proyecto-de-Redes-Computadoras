#include <pcap.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#define SIZE 200
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
static int count = 0; //inicializamos el contador
count ++;
printf("\n");
struct ether_header *eptr;
/* Apuntamos el puntero a la cabecera Ethernet al
comienzo del paquete
*/
eptr = (struct ether_header *) packet;

printf("Paquete numero: %d\n",count);

printf("MAC origen: %s\n",(char *) ether_ntoa(eptr->ether_shost) );

printf("MAC destino: %s\n", (char *)ether_ntoa(eptr->ether_dhost) );
//Comprobamos de que tipo es el paquete
if(ntohs(eptr->ether_type) == ETHERTYPE_IP)
{
	printf("Es de tipo IP, por ahora nos vale\n");
}
else if(ntohs(eptr->ether_type) == ETHERTYPE_ARP)
{
	printf("Es de tipo ARP, no nos vale\n"); 
	return;
}
else if(ntohs(eptr->ether_type) == ETHERTYPE_REVARP)
{
	printf("Es de tipo RARP, no nos vale\n"); 
	return;
}
else
{
	printf("Es de tipo desconocido, no nos vale\n");
}
/* Ahora extraemos la cabecera IP, por lo que tenemos
que desplazar el tama ̃
no de la cabecera Ethernet ya
procesada
*/
struct ip *ipc;
ipc = (struct ip*)(packet + sizeof(struct ether_header) );

printf("El ttl es %d\n",ipc->ip_ttl);
printf("IP origen: %s\n",inet_ntoa(ipc->ip_src));
printf("IP destino: %s\n",inet_ntoa(ipc->ip_dst));

const char* payload=(packet + sizeof(struct ether_header) + ipc->ip_len);
printf("Payload: \n %s\n",payload);
}



int main(int argc,char **argv)
{

char filtro[]="arp and port 80"; //solo el trafico web

char *dev;

char errbuf[PCAP_ERRBUF_SIZE];
pcap_t* descr;
const u_char *packet;
struct pcap_pkthdr hdr;
struct ether_header *eptr; // Ethernet
bpf_u_int32 maskp;
// mascara de subred
bpf_u_int32 netp;
// direccion de red
struct bpf_program fp; // El programa de filtrado compilado
dev = pcap_lookupdev(errbuf); //Buscamos un dispositivo del que comenzar la captura
if(dev == NULL)
{
	fprintf(stderr," %s\n",errbuf); 
	exit(1);
}
else
{
	printf("Abriendo %s en modo promiscuo\n",dev);
}
pcap_lookupnet(dev,&netp,&maskp,errbuf); //extraemos la direccion de red y la mascara
descr = pcap_open_live(dev,SIZE,1,20,errbuf); //comenzamos la captura en modo promiscuo
if(pcap_compile(descr,&fp,filtro,0,netp) == -1) //compilamos el programa
{
	fprintf(stderr,"Error compilando el filtro\n"); 
	exit(1);
}
if(pcap_setfilter(descr,&fp) == -1)
//aplicamos el filtro
{
	fprintf(stderr,"Error aplicando el filtro \n"); 
	exit(1);
}
if(descr == NULL)
{
	printf("pcap_open_live(): %s\n",errbuf); 
	exit(1);
	 }
pcap_loop(descr,10,my_callback,NULL); //entramos en el bucle (infinito)
return 0;
}




