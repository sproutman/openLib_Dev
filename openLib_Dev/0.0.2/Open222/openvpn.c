/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "syshead.h"

#include "init.h"
#include "forward.h"
#include "multi.h"
#include "win32.h"

#include "memdbg.h"

#include "forward-inline.h"

#define P2P_CHECK_SIG() EVENT_LOOP_CHECK_SIGNAL (c, process_signal_p2p, c);

static bool
process_signal_p2p (struct context *c)
{
  remap_signal (c);
  return process_signal (c);
}

static void
tunnel_point_to_point (struct context *c)
{
  context_clear_2 (c);

  /* set point-to-point mode */
  c->mode = CM_P2P;

  /* initialize tunnel instance */
  init_instance_handle_signals (c, c->es, CC_HARD_USR1_TO_HUP);
  if (IS_SIG (c))
    return;

  /* main event loop */
  while (true)
    {
      perf_push (PERF_EVENT_LOOP);

      /* process timers, TLS, etc. */
      pre_select (c);
      P2P_CHECK_SIG();

      /* set up and do the I/O wait */
      io_wait (c, p2p_iow_flags (c));
      P2P_CHECK_SIG();

      /* timeout? */
      if (c->c2.event_set_status == ES_TIMEOUT)
	{
	  perf_pop ();
	  continue;
	}

      /* process the I/O which triggered select */
      process_io (c);
      P2P_CHECK_SIG();

      perf_pop ();
    }

  uninit_management_callback ();

  /* tear down tunnel instance (unless --persist-tun) */
  close_instance (c);
}

#undef PROCESS_SIGNAL_P2P

int
old_main (int argc, char *argv[])
{
  struct context c;

#if PEDANTIC
  fprintf (stderr, "Sorry, I was built with --enable-pedantic and I am incapable of doing any real work!\n");
  return 1;
#endif

  CLEAR (c);

  /* signify first time for components which can
     only be initialized once per program instantiation. */
  c.first_time = true;

  /* initialize program-wide statics */
  if (init_static ())
    {
      /*
       * This loop is initially executed on startup and then
       * once per SIGHUP.
       */
      do
	{
	  /* enter pre-initialization mode with regard to signal handling */
	  pre_init_signal_catch ();

	  /* zero context struct but leave first_time member alone */
	  context_clear_all_except_first_time (&c);

	  /* static signal info object */
	  CLEAR (siginfo_static);
	  c.sig = &siginfo_static;

	  /* initialize garbage collector scoped to context object */
	  gc_init (&c.gc);

	  /* initialize environmental variable store */
	  c.es = env_set_create (NULL);
#ifdef WIN32
	  env_set_add_win32 (c.es);
#endif

#ifdef ENABLE_MANAGEMENT
	  /* initialize management subsystem */
	  init_management (&c);
#endif

	  /* initialize options to default state */
	  init_options (&c.options, true);

	  /* parse command line options, and read configuration file */
	  parse_argv (&c.options, argc, argv, M_USAGE, OPT_P_DEFAULT, NULL, c.es);

#ifdef ENABLE_PLUGIN
	  /* plugins may contribute options configuration */
	  init_verb_mute (&c, IVM_LEVEL_1);
	  init_plugins (&c);
	  open_plugins (&c, true, OPENVPN_PLUGIN_INIT_PRE_CONFIG_PARSE);
#endif

	  /* init verbosity and mute levels */
	  init_verb_mute (&c, IVM_LEVEL_1);

	  /* set dev options */
	  init_options_dev (&c.options);

	  /* openssl print info? */
	  if (print_openssl_info (&c.options))
	    break;

	  /* --genkey mode? */
	  if (do_genkey (&c.options))
	    break;

	  /* tun/tap persist command? */
	  if (do_persist_tuntap (&c.options))
	    break;

	  /* sanity check on options */
	  options_postprocess (&c.options);

	  /* show all option settings */
	  show_settings (&c.options);

	  /* print version number */
	  msg (M_INFO, "%s", title_string);

	  /* misc stuff */
	  pre_setup (&c.options);

	  /* test crypto? */
	  if (do_test_crypto (&c.options))
	    break;
	  
#ifdef ENABLE_MANAGEMENT
	  /* open management subsystem */
	  if (!open_management (&c))
	    break;
#endif

	  /* set certain options as environmental variables */
	  setenv_settings (c.es, &c.options);

	  /* finish context init */
	  context_init_1 (&c);

	  do
	    {
	      /* run tunnel depending on mode */
	      switch (c.options.mode)
		{
		case MODE_POINT_TO_POINT:
		  tunnel_point_to_point (&c);
		  break;
#if P2MP_SERVER
		case MODE_SERVER:
		  tunnel_server (&c);
		  break;
#endif
		default:
		  ASSERT (0);
		}

	      /* indicates first iteration -- has program-wide scope */
	      c.first_time = false;

	      /* any signals received? */
	      if (IS_SIG (&c))
		print_signal (c.sig, NULL, M_INFO);

	      /* pass restart status to management subsystem */
	      signal_restart_status (c.sig);
	    }
	  while (c.sig->signal_received == SIGUSR1);

	  uninit_options (&c.options);
	  gc_reset (&c.gc);
	}
      while (c.sig->signal_received == SIGHUP);
    }

  context_gc_free (&c);

  env_set_destroy (c.es);

#ifdef ENABLE_MANAGEMENT
  /* close management interface */
  close_management ();
#endif

  /* uninitialize program-wide statics */
  uninit_static ();

  openvpn_exit (OPENVPN_EXIT_STATUS_GOOD);  /* exit point */
  return 0;			            /* NOTREACHED */
}


int stopOpenvpn()
{
	//连接管理端口并向其发送stop(signal SIGTERM)指令
	printf("Enter into stopOpenvpn Function\n");

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



//int  initPcCLient()
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
	//addrClient.sin_port = htons(initPcCLient);
	addrClient.sin_port = htons(MONITOR_TCP_PORT);
	bzero((char*)&(addrClient.sin_zero),8);

	//向服务器发出连接请求
	//connect( socketClient, (struct SOCKADDR*)&addrClient, sizeof(addrClient));
	connect( socketClient, (void*)&addrClient, sizeof(addrClient));

	recv( socketClient, recvBuf, 100, 0 );
	printf( "%s\n", recvBuf );


	//Send CMD TO MI;
	char ucmd[4096] = {0};
	memset(ucmd, 0, sizeof(ucmd));
	send(socketClient, "signal SIGTERM\r\n", strlen( "signal SIGTERM\r\n" )+1, 0 );

	//receive Msg from MI
	memset(ucmd, 0, sizeof(ucmd));
	 int cLen = recv(socketClient, ucmd, sizeof(ucmd),0);
	 if((cLen < 0)||(cLen == 0))
	    {
	        printf("recv() failure!\n");
	        return -1;
	    }
	    printf("recv() Data From Server: [%s]\n", ucmd);

	return 0;


}

		return 0;

}



int restartVpn()
{

	//连接管理端口并向其发送stop(signal SIGTERM)指令
	printf("Enter into restartOpenvpn Function\n");

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

//int  initPcCLient()
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
//	addrClient.sin_port = htons(initPcCLient);
	addrClient.sin_port = htons(MONITOR_TCP_PORT);
	bzero((char*)&(addrClient.sin_zero),8);

	//向服务器发出连接请求
	//connect( socketClient, (struct SOCKADDR*)&addrClient, sizeof(addrClient));
	connect( socketClient, (void*)&addrClient, sizeof(addrClient));

	recv( socketClient, recvBuf, 100, 0 );
	printf( "%s\n", recvBuf );


	//Send CMD TO MI;
	char ucmd[4096] = {0};
	memset(ucmd, 0, sizeof(ucmd));
	send(socketClient, "signal SIGHUP\r\n", strlen( "signal SIGHUP\r\n" )+1, 0 );

	//receive Msg from MI
	memset(ucmd, 0, sizeof(ucmd));
	 int cLen = recv(socketClient, ucmd, sizeof(ucmd),0);
	 if((cLen < 0)||(cLen == 0))
	    {
	        printf("recv() failure!\n");
	        return -1;
	    }
	    printf("recv() Data From Server: [%s]\n", ucmd);

	return 0;


}

		return 0;
}


int getState()
{

	//连接管理端口并向其发送stop(signal SIGTERM)指令
	printf("Enter into getState Function\n");

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

//int  initPcCLient()
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
//	addrClient.sin_port = htons(initPcCLient);
	addrClient.sin_port = htons(MONITOR_TCP_PORT);
	bzero((char*)&(addrClient.sin_zero),8);

	//向服务器发出连接请求
	//connect( socketClient, (struct SOCKADDR*)&addrClient, sizeof(addrClient));
	connect( socketClient, (void*)&addrClient, sizeof(addrClient));

	recv( socketClient, recvBuf, 100, 0 );
	printf( "%s\n", recvBuf );


	//Send CMD TO MI;
	char ucmd[4096] = {0};
	memset(ucmd, 0, sizeof(ucmd));
	send(socketClient, "state\r\n", strlen( "state\r\n")+1, 0 );

	//receive Msg from MI
	memset(ucmd, 0, sizeof(ucmd));
	 int cLen = recv(socketClient, ucmd, sizeof(ucmd),0);
	 if((cLen < 0)||(cLen == 0))
	    {
	        printf("recv() failure!\n");
	        return -1;
	    }
	    printf("recv() Data From Server: [%s]\n", ucmd);

	return 0;


}

		return 0;
}



int
main (int argc, char *argv[])
{	

//使用指定参数启动openvpn
	char* arg[]={"openvpn","--config","/etc/openvpn/client.config"};
	
	old_main(3,arg);

	return 0;
}

