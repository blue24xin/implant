/*----------------------------------------------------
 name: client.c
 bref: sent ctronl to implent 
 auther:xxxx
-----------------------------------------------------*/
#include<sys/types.h> 
#include<sys/socket.h> 
#include<unistd.h> 
#include<fcntl.h>
#include<netinet/in.h> 
#include<arpa/inet.h> 
#include<stdio.h> 
#include<stdlib.h> 
#include<errno.h> 
#include<netdb.h> 
#include<stdarg.h> 
#include<string.h> 
#include<getopt.h>
#include<time.h>

  
#define SERVER_PORT 1999 
#define BUFFER_SIZE 1024 
#define FILE_NAME_MAX_SIZE 512 
int readFile(char *path,char *buff,int len)
{
	int fd;
	fd = open(path,O_RDWR);
	if(fd<0)
	{
		
		return -1;
	}
	
	fd = open(path,O_RDWR);
	if(read(fd,buff,len)<=0)
	{
		
		return -1;
	}
	close(fd);
	
	return 0;	
}
get_time()
{
	time_t timep;
	time(&timep);
//	printf("%s\n",asctime(gmtime(&timep)));
	printf("%s",ctime(&timep));
}

void message()
{
	printf("List all available command:     'help'\n");
	printf("Interrupt a command:            Control-C\n");
	printf("Terminate this program:         'quit' or Control-D\n");
}

usage()
{

	printf("this is usage\n");	
}
  
int main(int argc,char **argv) 
{ 
	FILE * fd;
	int  rand_port;
	
	int c,opterr;
	char *l_opt_arg;  
	char *ipaddr=NULL;
	char *sport=NULL;
	char *filename=NULL;
	char tembuf[1024];
	char getinput[1200];
	srand(time(0));
	
	char* const short_options = "n:f:l:";  
	struct option long_options[] = {  
		{ "ipimplant",     0,   NULL,    'n'     },  
		{ "ipaddr",  0,   NULL,    'f'     },  
		{ "port",     1,   NULL,    'l'     },  
		{      0,     0,     0,     0},  
	};  
	
	opterr = 0;
	//while((c=getopt_long(argc,argv,short_options,long_options,NULL)) != -1)
	while(1)
	{
	 message();
	 get_time();
	 printf("\nBLUE>"); 
	 scanf("%s",getinput);
	 c=getopt_long(argc,argv,short_options,long_options,NULL);
	 switch(c){
		case 'n':
			ipaddr=optarg;
			 printf("ith \n");
			break;
		case 'f':
			filename=optarg;
			printf("this is test:%s\n",filename);	
			break;
		case 'l':
			sport=optarg;					
			printf("this is test:%s\n",sport);	
			break;
		case '?':
			printf("unrecognized opt:%s",optarg);
			opterr=1;
			break;
		}


	}
	if(opterr)
	{
	 usage();
	return -1;
	}	
	
	/*读取http ok */
	printf("read start ---\n");
	if(readFile(filename,tembuf,sizeof(tembuf))<0)
	{
		printf("read is fail\n");
		return -1;
	}
	rand_port=rand()%1000+8000;		
	printf("read end ---:rand_port:%d\n",rand_port);
#if 0
	if((fd=fopen(filename,"r"))==NULL)
	{
	 printf("open err\n");
	 return -1;
	}
	while(!feof(fd))
	{
	 fgets(tembuf,1024,fd);
	 printf("the file is :%s\n",tembuf);	
	 	
	}
	fclose(fd);	
		
#endif
	/* 服务端地址 */
	struct sockaddr_in server_addr; 
	bzero(&server_addr, sizeof(server_addr)); 
	server_addr.sin_family = AF_INET; 
	server_addr.sin_addr.s_addr = inet_addr(ipaddr); 
	server_addr.sin_port = htons(rand_port); 

	printf("the file is :%s\n",tembuf);	
	/* 创建socket */
	int client_socket_fd = socket(AF_INET, SOCK_DGRAM, 0); 
	if(client_socket_fd < 0) 
	{ 
		perror("Create Socket Failed:"); 
		exit(1); 
	} 
		
	char buffer[BUFFER_SIZE]; 
	bzero(buffer, BUFFER_SIZE); 
//	strncpy(buffer, filename, strlen(filename)>BUFFER_SIZE?BUFFER_SIZE:strlen(filename)); 
//	strcpy(buffer,tembuf);
	strncpy(buffer,tembuf,strlen(tembuf));
	printf("----\n");
	/* 发送 */
	if(sendto(client_socket_fd, buffer, strlen(buffer),0,(struct sockaddr*)&server_addr,sizeof(server_addr)) < 0) 
	{ 
		perror("Send File Name Failed:"); 
		exit(1); 
	}else{
	printf("sent ok ----\n");
	}
	close(client_socket_fd); 
	return 0; 
} 


