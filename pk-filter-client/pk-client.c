#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/types.h>

#include <netlink/cache.h>
#include <netlink/route/link.h>

#include "pk-netlink.h"

#define NETLINK_PK_FILTER 31

static void print_usage(void)
{
  printf("Usage: pk-client <cmd>\n"
         " cmd := { start | stop | add } \n");
  exit(1);
}

int pk_filter_send_simple_cmd(pkfilter_cmd_t cmd_num, struct nl_sock* sk, pk_client_cmd_t* sub_cmd) {
  int err;
  struct nl_msg *msg;
  pkfilter_cmd_t cmd;
  pkfilter_msg_config_cmd_t* config_cmd;
  int cmd_size = sizeof(pkfilter_msg_config_cmd_t);
  
  if(sub_cmd!=NULL) {
    cmd_size += sub_cmd->size;
  }
  
  config_cmd = malloc(cmd_size);    
  
  msg = nlmsg_alloc_simple(NETLINK_PK_FILTER,0);
  if(!msg)
    return -1;
  
  config_cmd->command = cmd_num;

  if(sub_cmd!=NULL){
    config_cmd->len = sub_cmd->size;
    memcpy(&(config_cmd->data[0]),sub_cmd,sub_cmd->size);
  }
  
  nlmsg_append(msg, config_cmd, sizeof(config_cmd), NLMSG_ALIGNTO);
  
  err = nl_send_auto_complete(sk, msg);
  nl_wait_for_ack(sk);  
 errout:
  nlmsg_free(msg);
  return err;    
}

pk_client_cmd_t* parse_add_cmd(char* str_cmd){
  pk_client_cmd_t* cmd;
  
  char* ip = "10.0.0.112";
  int attr_size = sizeof(pk_client_attr_t)+sizeof(ip);
  int cmd_size = attr_size+sizeof(pk_client_cmd_t);
  
  cmd = malloc(cmd_size);
  cmd->type = PK_LOG_HDR;
  cmd->size = cmd_size;
  // Command Attributes
  cmd->nattr = 1;
  cmd->attrs[0].type = PK_AT_DST;
  cmd->attrs[0].nval = sizeof(ip);
  memcpy(cmd->attrs[0].val,ip, sizeof(ip));
  return cmd;
}


int main(int argc, char* argv[])
{
  struct nl_sock* sk;
  int err;
  char* subcmd = argv[1];
  
  if (argc < 2 || !strcmp(argv[1], "-h"))
    print_usage();
  
  if (!(sk = nl_socket_alloc())){
    exit(-1);
  }

  if ((err = nl_connect(sk, NETLINK_PK_FILTER)) < 0){
    fprintf(stderr,"No protocol handler for pk_filter installed \n");
    return err;
  }
  
  if(strcmp(subcmd,"start") == 0) {
    pk_filter_send_simple_cmd(PK_FILTER_CMD_START,sk,NULL);
  } else if (strcmp(subcmd,"stop") == 0) {
    pk_filter_send_simple_cmd(PK_FILTER_CMD_STOP,sk,NULL);
  } else if(strcmp(subcmd,"add") == 0) {    
    pk_filter_send_simple_cmd(PK_FILTER_CMD_ADD,sk,parse_add_cmd(subcmd));
  }
  
  return 0;
}
