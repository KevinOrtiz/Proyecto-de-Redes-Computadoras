#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
void antiscan();
void imprimirICMP(int count, const struct pcap_pkthdr* pkthdr,const u_char* packet);

pcap_t* descr;
int main()
{
	int opcion;
	do{
		system("clear");
		printf("\t\t\t\t\t MENÚ\n");
		printf("\t\t\t\t  1) ANTI SCAN\n");
		printf("\t\t\t\t  2) RESUMEN TEÓRICO\n");
		printf("\t\t\t\t  3) SALIR\n");	
		printf("\t\t\t\t  ELIJA UNA OPCIÓN :");
		scanf("%d",&opcion);
	}while(opcion>3);
	
	switch(opcion){
		case 1:{
			system("clear");		
			antiscan();
		}
			break;			
		default:
			return 0;
			break;
	}

	return 0;
}


void antiscan(){

	srand (time(NULL));
	struct bpf_program fp;
	int opcion;
	char option[10];
	char pingIP[100] = "ping -c 1 ";
	char targetIP[40];

	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];	
	pcap_if_t *alldevsp , *device;
	char devs[100][100];
	int count = 1;

	bpf_u_int32 maskp;// mascara de subred
	bpf_u_int32 netp;	// direccion de red
	int n;

	int compiler;
	int filter;
   /////////////////////////////////////////////////////////////////////////////////////
	printf("\n\t\tANTI-SCAN\n");
	do{
		system("clear");
		printf("\n\t\t\t\tANTISCAN\n");

		printf("\t\t-i DEV,     especifica la interface de red\n");
		printf("\t\t   con la cual hacer sniff.\n");
		printf("\n\tIngrese la opcion: ");
		scanf("%s",option);

		if(strcmp(option, "-i")==0){
			printf("\t\tINTERFACES DE LA RED\n");
		    if( pcap_findalldevs( &alldevsp , errbuf) ){
		        printf("Error al econtrar dispositivos : %s" , errbuf);
		        exit(1);
		    }
		    //Print the available devices
		    printf("\n  Dispositivos habilitados son: :\n");
		    for(device = alldevsp ; device != NULL ; device = device->next){
		    	printf("\t%d. %s - %s\n" , count , device->name , device->description);
		        if(device->name != NULL){
		            strcpy(devs[count] , device->name);
		        }
		        count++;
		    }

		    printf("\tIngrese el numero del dispositivo para hacer sniff:");
		    scanf("%d" , &n);
		    printf("\tEspecifique el target a simular:  " );
		    scanf("%s",targetIP );
		    
		    strcat(pingIP, targetIP);
  ///////////////////////////////////////////////////////////////////////////////////////
		    dev = devs[n]; // Device
		    pcap_lookupnet(dev,&netp,&maskp,errbuf); //Extraemos la direccion de red y la mascara

		    descr = pcap_open_live(dev,BUFSIZ,1,10,errbuf); //Comenzamos la captura en modo promiscuo

			if (descr == NULL){
				printf("pcap_open_live(): %s\n",errbuf); 
				exit(1); 
			}
			compiler = pcap_compile(descr,&fp,"icmp",0,netp);			
			if ( compiler < 0){ //Compilamos el programa
				fprintf(stderr,"Error compilando el filtro\n"); 
				exit(1);
			}

			filter = pcap_setfilter(descr,&fp);
			if ( filter < 0 ){ //aplicamos el filtro
				fprintf(stderr,"Error aplicando el filtro\n"); 
				exit(1);
			}
//////////////////////////////////////////////////////////////////////////////////////////////
			struct pcap_pkthdr *header;
			const u_char *data;
			u_int packetCount = 0;
			int returnValue;
			int repetir=0;

			
			int rango = 99-10+1;
			int n1=rand() % (rango), n2=rand() % (rango);
			int time1=rand() % (rango), time2=rand() % (rango);
			
			if(system(pingIP)){
				system("clear");
				system("clear");
				system("clear");
				printf("\n\n\t\tINTERFACES DE LA RED\n");
				printf("PING %s (%s) %i(%i) bytes of data.\n",targetIP,targetIP, n1,n2  );
				printf("64 bytes from %s: icmp_req=1 ttl=64 time=%i.%i\n",targetIP,time1,time2 );

				printf("\n--- %s ping statistics ---\n", targetIP );
				printf("1 packets transmitted, 1 received, 0%% packet loss, time 0ms\n" );
				printf("rtt min/avg/max/mdev = %i.%i0/%i.%i0/%i.%i0/0.000 ms\n",time1,time2, time1,time2, time1,time2 );
			}else{
				system("clear");
				system("clear");
				system("clear");
				printf("\n\n\t\tINTERFACES DE LA RED\n");
				system(pingIP);
			}
		}
	}while((strcmp(option,"-i")!=0));


	do{
		printf("\n\nDesea regresar al Menu Principal:\n1)SI\n2)NO");
		printf("\n  ELIJA UNA OPCIÓN :");
		scanf("%d",&opcion);
	}while(opcion>2);

	switch(opcion){
		case 1:{
			system("clear");
			main();
		}
			break;
	}
}




