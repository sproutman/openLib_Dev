/*
 * TCP客户端和服务器交互的代码 客户端通过TCP 8000端口和open的Client进行交互
 * 不断改善中...
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>


#define ERROR -1

/* 宏定义： 端口号 */
#define MONITOR_TCP_PORT    8000

/* 定义socket */
int socketClient ;

/* 定义socket地址 */
struct sockaddr_in addrClient;

int reuse = 1;

//接受数据
char recvBuf[100];



int  initPcCLient()
{
	printf("create client socket\n");
	socketClient =  socket(AF_INET,SOCK_STREAM,0);  /*创建用于监听的套接字*/

	if (ERROR==socketClient)
	{
		printf("create client socket error\n");
	}

	/* 设置为可重用地址，如不设置此，则有可能间隔几分钟才能再绑定 */

	if(0 > setsockopt(socketClient,SOL_SOCKET,SO_REUSEADDR,(char*)&reuse,sizeof(int)))
	{
		close(socketClient);
		printf("set data socket option error\n");
	}
	/* 设置本地客户端动态IP地址 */
	addrClient.sin_family = AF_INET;
	addrClient.sin_addr.s_addr = inet_addr("127.0.0.1");
	addrClient.sin_port = htons(MONITOR_TCP_PORT);
	bzero((char*)&(addrClient.sin_zero),8);

	//向服务器发出连接请求
	//connect( socketClient, (struct SOCKADDR*)&addrClient, sizeof(addrClient));
	connect( socketClient, (void*)&addrClient, sizeof(addrClient));

	recv( socketClient, recvBuf, 100, 0 );
	printf( "%s\n", recvBuf );




	while(1)
	{
		char ucmd[4096] = {0};
		memset(ucmd, 0, sizeof(ucmd));
		printf("Please input your command :\n");
	 gets(ucmd);


//选择输入命令后的反应
		if (strcmp(ucmd, "help") == 0)
		{
			send(socketClient, "help\r\n", strlen( "help\r\n" )+1, 0 );
		}
	//	else if(strcmp(ucmd, "start") == 0)
		//{
	//		send(socketClient, "start\r\n", strlen( "start\r\n" )+1, 0 );
//		}
		else if(strcmp(ucmd, "stop") == 0)
		{
			send(socketClient, "signal SIGTERM\r\n", strlen( "signal SIGTERM\r\n" )+1, 0 );
		}
		else if(strcmp(ucmd, "restart") == 0)
		{
			send(socketClient, "signal SIGHUP\r\n", strlen( "signal SIGHUP\r\n" )+1, 0 );
		}
		else if(strcmp(ucmd, "state") == 0)
		{
			send(socketClient, "signal SIGHUP\r\n", strlen( "signal SIGHUP\r\n" )+1, 0 );
		}
		else
		{
				printf("Please choose your CMD from {help,start,stop,restart,state} !\n");
		}



		memset(ucmd, 0, sizeof(ucmd));
	 int cLen = recv(socketClient, ucmd, sizeof(ucmd),0);
	 if((cLen < 0)||(cLen == 0))
	    {
	        printf("recv() failure!\n");
	        return -1;
	    }
	    printf("recv() Data From Server: [%s]\n", ucmd);

	}
	//发送数据


	//关闭套接字
	close(socketClient);


	return 0;

}

//主函数
int main(void)
{
	printf("create \n");
	initPcCLient();
	return 0;

}
