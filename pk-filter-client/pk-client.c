#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>

#define NETLINK_PK_FILTER 31

struct pkfilter_msg_config_cmd {
	u_int8_t	command;	/* pkfilter_msg_config_cmds */
} __attribute__ ((packed));

enum pkfilter_msg_cmd{
  PK_FILTER_CMD_START,
  PK_FILTER_CMD_STOP
};

static void print_usage(void)
{
  printf("Usage: pk-client <cmd>\n"
         " cmd := { start | stop| list | add | rm } \n");
  exit(1);
}

/**
 * Command to start the packet filter.
 */
int pk_filter_start_cmd()
{
  struct pkfilter_msg_cmd cmd;
  int err;
  struct nl_msg *msg;

  msg = nlmsg_alloc_simple(NETLINK_PK_FILTER,0);
  if(!msg)
    return -1;
  
  err = nl_send_auto_complete(sk, msg);
  
  //  nlmsg_append(msg, buf, size, NLMSG_ALIGNTO);
 errout:
  nlmsg_free(msg);
  return err;  
}

int main(int argc, char* argv[])
{
  struct nl_sock *nf_sock;
  char buffer[] = "Howdy, From Userspace";
  int err;
  
  if (argc < 2 || !strcmp(argv[1], "-h"))
    print_usage();
  
  if (!(nf_sock = nl_socket_alloc())){
    // nl_cli_fatal(ENOBUFS, "Unable to allocate netlink socket");
    exit(-1);
  }

  if ((err = nl_connect(nf_sock, NETLINK_PK_FILTER)) < 0){
    return err;
  }

  nl_send_simple(nf_sock, NETLINK_PK_FILTER, 0,buffer,sizeof(buffer));
    // nl_cli_fatal(err, "Unable to connect netlink socket: %s",
    //			     nl_geterror(err));
    //    return err;
    //  if (nl_cli_connect(nf_sock, NETLINK_PK_FILTER) < 0)
    //    return -1;
  
  return 0;
}
