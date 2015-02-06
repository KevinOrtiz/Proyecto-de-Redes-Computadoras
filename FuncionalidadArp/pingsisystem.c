
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <netinet/ip_icmp.h>
#include <string.h>


#define DEFAULT_INIT_PORT 1 /* puerto inicial del escaneo por defecto */
#define DEFAULT_END_PORT 1024 /* puerto final del escaneo por defecto  */
#define DEFAULT_ICMP_PORT 8765 /* puerto por defecto para mandar los paquetes ICMP */



int main(int argc, char *argv[])
{

	int sockfd,numbytes,flags,listen; //descriptor del socket, número de bytes enviados, flags y resultado del connect()
	int init_port, end_port; //variables de inicio y fin del escaneo
	int result,fromlen; //resultado del select, y tamaño del ICMP de respuesta
	struct hostent *he; //variable de tipo hostent donde se guardará información del Host a escanear
	struct sockaddr_in their_addr; // almacenarán la direccion IP del Host objetivo, y sus datos 
	static u_char paquete_salida[64]; //paquete de salida ICMP
	register struct icmp *cabecera_icmp = (struct icmp *) paquete_salida; //formato de paquete ICMP	
	fd_set fd_leer,fd_escribir; //descriptores a controlar por select
	struct timeval tv; //temporizador para el uso de select
	char recv_ICMP[512],shost[100];
	struct servent *bar; //guardará el nombre del servicio que corre en cada puerto
	int i,val,len=sizeof(val); //contador, resultado getsockopt


/* Chequeo de la correcta llamada al programa y de sus argumentos*/
	switch (argc)
	{
	case 2: init_port= DEFAULT_INIT_PORT;
	   end_port= DEFAULT_END_PORT;
	   break;

	case 3: init_port= atoi(argv[2]);
	   end_port= DEFAULT_END_PORT;
	   break; 

	case 4: if (atoi(argv[3])>atoi(argv[2]))
	   {
	         init_port= atoi(argv[2]);
	         end_port= atoi(argv[3]);
	   }
	   else
	   {

   	   	fprintf(stderr,"\n\nEl puerto final debe ser MAYOR que el inicial\n\n");
    	   	exit(1);
	   }
	   break;
	default:   fprintf(stderr,"\n\nuso: scaner_tcp host [puerto_inicial puerto_final]\n\n");
    	   	   exit(1); 
       }	

	/* convertimos el hostname a su direccion IP */
	if ((he= (void *) gethostbyname(argv[1])) == NULL)
	{
    error("gethostbyname");
    exit(1);
	}


/* Creamos el socket */
if ((sockfd = socket(AF_INET, SOCK_RAW,1)) == -1)
{

    perror("socket");
    exit(1);

}

/* configuramos la dirección a donde conectarnos */
their_addr.sin_family = AF_INET; // host byte order 
their_addr.sin_port = htons(DEFAULT_ICMP_PORT); /* network byte order */
their_addr.sin_addr = *((struct in_addr *)he->h_addr); // dirección IP
bzero(&(their_addr.sin_zero), 8);
sprintf(shost,"%d.%d.%d.%d",(unsigned char)he->h_addr_list[0][0],(unsigned char)he->h_addr_list[0][1],(unsigned char)he->h_addr_list[0][2],\
(unsigned char)he->h_addr_list[0][3]);

/* configuración cabecera mensaje ICMP */
cabecera_icmp->icmp_type = ICMP_ECHO; // Tipo de mensajes ICMP
cabecera_icmp->icmp_code = 0; // Código de mensaje ICMP
cabecera_icmp->icmp_cksum = 0; // Checksum del paquete ICMP
cabecera_icmp->icmp_seq =1; // Numero de secuencia
cabecera_icmp->icmp_id = 0x1111; // ID de paquete

/* Transmitimos el paquete ICMP */
if ((numbytes=sendto(sockfd, &paquete_salida, 64, 0, (struct sockaddr *)&their_addr, sizeof(struct sockaddr))) == -1)
{
    perror("sendto");
    exit(1);
}
else printf("\nPaquete ICMP enviado, número de bytes= %i\n\n",numbytes);

do {
   FD_ZERO(&fd_leer); // pone a 0 todos los bits de fd_var. 
   FD_SET(sockfd, &fd_leer); //activa en fd_leer el bit correspondiente al descriptor sockfd
   tv.tv_sec=2; // 2 segundos de tiempo de espera para recibir la respuesta al ICMP
   tv.tv_usec=0;
   result = select(sockfd +1, &fd_leer, NULL, NULL, &tv);
} while (result == -1 && errno == EINTR);


if (result > 0) {
   if (FD_ISSET(sockfd, &fd_leer)) {
      /* El socket tiene datos para leer */
      result = recvfrom(sockfd, recv_ICMP, sizeof recv_ICMP, 0, NULL, &fromlen);
      if (result == 0) {
         /* Conexión cerrada por el host */
	 printf("\nEl host ha cerrado la conexión.\n\n");
	 close(sockfd);
      }
      else {
         /* Se leyeron los datos de respuesta ICMP */
	 printf("\nEl host está activo,procederemos a chequear los servicios...\n");
	 close(sockfd);

	 printf("Escaneando %s - TCP ports %i al %i\n\n", shost, init_port, end_port);
             
	 
	 for (i=init_port;i<=end_port;i++)
         {
		/*
		Comprobamos puerto a puerto si tienen servicios corriendo o no, lo hacemos con la función connect(),
		pero antes hacemos que el socket no sea bloqueante mediante la función fcntl(). 
		Cuando se configura un socket como no bloqueante, y la conexión no se ha completado
		inmediatamente, la función connect () devuelve como código de retorno -1 y como código
		de error en al variable de sistema errno EINPROGRESS, indicando que la conexión todavía
		no se ha completado, pero se sigue intentando.
		Para detectar cuando se completa la conexión, se utiliza la función select ()
		*/		
	
		sockfd = socket (AF_INET, SOCK_STREAM, 0);
	 	flags = fcntl (sockfd, F_GETFL, 0);
	 	fcntl (sockfd, F_SETFL, O_NONBLOCK | flags);

		their_addr.sin_family = AF_INET; 
		their_addr.sin_port = htons(i); 
		their_addr.sin_addr = *((struct in_addr *)he->h_addr); 
		bzero(&(their_addr.sin_zero), 8);

		listen= connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr));

		
		if (listen<0) 
		{
		/*Si el connect no se conecta inmediatamente, controlamos con el SELECT()*/
			do {
   				FD_ZERO(&fd_escribir); 
   				FD_SET(sockfd, &fd_escribir); 
   				result = select(sockfd +1, NULL, &fd_escribir, NULL, NULL);
			} while (result == -1 && errno == EINTR);
			
                        if (result > 0)
			{
				 if (FD_ISSET(sockfd, &fd_escribir)){
				 /*Si se puede escribir en el descriptor comprobamos la salida de getsockopt()*/
					getsockopt(sockfd, SOL_SOCKET, SO_ERROR,&val, &len);

					if (val==0){
						/*EISCONN*/
						bar = getservbyport(htons(i),"tcp");
                        			printf("%d (%s) está corriendo.\n",i,( !bar ) ? "Desconocido" : bar->s_name);
					}
					/*ELSE ECONNREFUSED*/
				 }	
			}
			
                }
		else
		{
		/*El connect se conectó inmediatamente*/
                        bar = getservbyport(htons(i),"tcp");
                        printf("%d (%s) está corriendo.\n",i,( !bar ) ? "Desconocido" : bar->s_name);
		}
         	close(sockfd);
  	 }
    }	
}
else { 
	/* Expiró el temporizador */
        printf("\nEl host no parece estar activo.\n\n");
	close(sockfd);
        exit(1);

}

 printf("\nFin de escaneo.\n\n");
 exit(1);

}}//FIN_MAIN