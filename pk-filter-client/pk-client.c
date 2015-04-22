#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/types.h>

#include <netlink/cache.h>
#include <netlink/route/link.h>
//#include <netlink/netlink-types.h>

#define NETLINK_PK_FILTER 31

typedef struct pkfilter_msg_config_cmd {
	u_int8_t	command;	/* pkfilter_msg_config_cmds */
} __attribute__ ((packed)) pkfilter_msg_config_cmd_t;

typedef enum pkfilter_cmd {
  PK_FILTER_CMD_START,
  PK_FILTER_CMD_STOP
} pkfilter_cmd_t;

static void print_usage(void)
{
  printf("Usage: pk-client <cmd>\n"
         " cmd := { start | stop } \n");
  exit(1);
}

/**
 * Command to start the packet filter.
 */
int pk_filter_send_start(struct nl_sock* sk)
{
  int err;
  struct nl_msg *msg;
  pkfilter_cmd_t cmd;
  pkfilter_msg_config_cmd_t config_cmd;
  
  msg = nlmsg_alloc_simple(NETLINK_PK_FILTER,0);
  if(!msg)
    return -1;

  config_cmd.command = PK_FILTER_CMD_START;

  nlmsg_append(msg, &config_cmd, sizeof(config_cmd), NLMSG_ALIGNTO);
  
  err = nl_send_auto_complete(sk, msg);
  nl_wait_for_ack(sk);  
 errout:
  nlmsg_free(msg);
  return err;  
}

int main(int argc, char* argv[])
{
  struct nl_sock* sk;
  char buffer[] = "Howdy, From Userspace";
  int err;
  
  if (argc < 2 || !strcmp(argv[1], "-h"))
    print_usage();
  
  if (!(sk = nl_socket_alloc())){
    // nl_cli_fatal(ENOBUFS, "Unable to allocate netlink socket");
    exit(-1);
  }

  if ((err = nl_connect(sk, NETLINK_PK_FILTER)) < 0){
    return err;
  }

  pk_filter_send_start(sk);  

  
  return 0;
}
