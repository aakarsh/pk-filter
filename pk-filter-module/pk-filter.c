/*
 * Copyright (c)  Aakarsh Nair <aakarsh.nair@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#include <linux/ctype.h>
#include <linux/gfp.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/textsearch.h>
#include <linux/types.h>
#include <linux/udp.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_helper.h>

#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/ip.h>
#include <linux/filter.h>
#include <linux/netfilter/x_tables.h>

#include "pk-netlink.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aakarsh Nair");
MODULE_DESCRIPTION("A simple demonstration of using netfilter to track incoming packets");

#define NETLINK_PK_FILTER 31

typedef struct pk_attr {
  struct list_head list;
  int type;
  int len;
  void* val;
} pk_attr_t;

typedef struct pk_cmd {
  struct list_head list;
  int type;
  struct list_head attrs;
} pk_cmd_t;

static bool pk_nl_cmd_start(const struct sk_buff* skb, struct nlmsghdr* nlmsghdr,struct nlattr **attrs);
static bool pk_nl_cmd_add(const struct sk_buff* skb, struct nlmsghdr* nlmsghdr,struct nlattr **attrs);
static bool pk_nl_cmd_add_bpf(const struct sk_buff* skb, struct nlmsghdr* nlmsghdr,struct nlattr **attrs);
static bool pk_nl_cmd_stop(const struct sk_buff* skb,  struct nlmsghdr* nlmsghdr ,struct nlattr **attrs);

static bool (*pk_nl_cmd_handler_t[PK_NL_CMD_MAX+1])(const struct sk_buff* skb, struct nlmsghdr* nlmsghdr,struct nlattr **attrs) =
{
  [PK_FILTER_CMD_STOP]  = pk_nl_cmd_stop,
  [PK_FILTER_CMD_START] = pk_nl_cmd_start,
  [PK_FILTER_CMD_ADD] = pk_nl_cmd_add,
  [PK_FILTER_CMD_ADD_BPF] = pk_nl_cmd_add_bpf,
  [PK_NL_CMD_MAX] = 0
};


/**
 * We process the netlink message by looking at the nlmsghdr along
 * with the socket buffer contents.
 */
static int pf_filter_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
  pkfilter_msg_config_cmd_t *msg;
  int type = nlh->nlmsg_type;
  printk(KERN_INFO "pf_filter_rcv_msg : Got a netlink message type : %d \n", type);
  msg = nlmsg_data(nlh);


  printk(KERN_INFO "Got Command : %d \n", msg->command);
  if(msg->command >= PK_NL_CMD_MAX || msg->command < 0) {
    printk(KERN_INFO "pk_filter_rcv_msg: Invalid command type : %d",msg->command);
    return -1;
  }
  // Dispatch command
  printk(KERN_INFO "Calling dispatch on command %d  \n",msg->command);
  pk_nl_cmd_handler_t[msg->command](skb,nlh,NULL);

  return 0;
}


/**
 * Main handler for dealing with netlink messages.
 */
static void pf_filter_rcv(struct sk_buff *skb)
{
  struct nlmsghdr *nlh = nlmsg_hdr(skb);

  printk(KERN_INFO "pf_filter_rcv : Got netlink message \n");

  if (nlh->nlmsg_len < NLMSG_HDRLEN || skb->len < nlh->nlmsg_len) {
    printk(KERN_INFO "pf_filter_rcv: Rejecting message header length %d is less than NLMSG_HDRLEN %d \n",nlh->nlmsg_len , NLMSG_HDRLEN);
    return;
  }

  if (!netlink_net_capable(skb, CAP_NET_ADMIN)) {
    printk(KERN_INFO "pf_filter_rcv: Rejecting message, insufficent permission ");
    netlink_ack(skb, nlh, -EPERM);
    return;
  }
  
  netlink_rcv_skb(skb, &pf_filter_rcv_msg);
}

/**
 * Initializes pf filter networking.
 * Set the input method for handling netlink sockets to pf_filter_rcv.
 */
static int __net_init pk_filter_net_init(struct net *net)
{
  struct sock *nfnl;
  struct netlink_kernel_cfg cfg = {
    .input	= pf_filter_rcv,
  };
  
  nfnl = netlink_kernel_create(net, NETLINK_PK_FILTER, &cfg);
  net->nfnl_stash = nfnl;
  rcu_assign_pointer(net->nfnl, nfnl);

  return 0;
}

static void __net_exit pk_filter_net_exit_batch(struct list_head *net_exit_list)  
{
  struct net *net;
  list_for_each_entry(net, net_exit_list, exit_list)
    netlink_kernel_release(net->nfnl_stash);
}

static struct pernet_operations pk_filter_net_ops = {
	.init		= pk_filter_net_init,
	.exit_batch	= pk_filter_net_exit_batch,
};



// List of packet filtering commands
static LIST_HEAD(pk_cmds);

// Configure cmd & attributes
static void pk_cmd_add_attribute(pk_cmd_t* cmd , int type,const char* value);

// Matchers
static bool pk_dst_match(const void* addr,int sz, struct iphdr* hdr,struct sk_buff * skb);
static bool pk_src_match(const void* addr,int sz, struct iphdr* hdr,struct sk_buff * skb);
static bool pk_proto_match(const void* proto,int sz, struct iphdr* hdr,struct sk_buff * skb);
static bool pk_bpf_match(const void* bpf_prog,int sz, struct iphdr* hdr,struct sk_buff * skb);

//statec bool pk_bpf_match(const char* bpf_code, struct 
static bool pk_cmd_match(pk_cmd_t* cmd,struct iphdr* hdr,struct sk_buff * skb);

static bool (*pk_ip_attr_matchers_t[PK_AT_MAX+1])(const void* val, int sz,struct iphdr* hdr,struct sk_buff * skb) =
{
  [PK_AT_SRC]  = pk_src_match,
  [PK_AT_DST] = pk_dst_match,
  [PK_AT_PROTO] = pk_proto_match,
  [PK_AT_BPF] = pk_bpf_match,
  [PK_AT_MAX] = 0
};

// Proc configuration  airo.c
struct proc_data {
	int release_buffer;
	int readlen;
	char *rbuffer;
	int writelen;
	int maxwritelen;
	char *wbuffer;
	void (*on_close) (struct inode *, struct file *);
};

static ssize_t proc_read( struct file *file,char __user *buffer,size_t len,loff_t *offset);
static ssize_t proc_write( struct file *file,const char __user *buffer,size_t len,loff_t *offset );
static int proc_close( struct inode *inode, struct file *file );
static int proc_pk_filter_open( struct inode *inode, struct file *file );
static void proc_pk_filter_close( struct inode *inode, struct file *file );

static const struct file_operations proc_pk_filter_ops = {
	.owner		= THIS_MODULE,
	.read		= proc_read,
        .write          = proc_write,
	.open		= proc_pk_filter_open,
	.release	= proc_close,
	.llseek		= default_llseek,
};

// better way needed 
static unsigned int atou(const char *s);

static unsigned int
pk_filter_in(const struct nf_hook_ops *ops, struct sk_buff *skb,
	     const struct net_device *in, const struct net_device *out,
	     int (*okfn)(struct sk_buff *));


static struct nf_hook_ops pk_filter_ops[] __read_mostly = {
	{
		.hook		= pk_filter_in,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_NAT_SRC - 2,
	}
};

typedef enum pk_hook_status {
  PK_HOOK_ENABLED,
  PK_HOOK_DISABLED,
} pk_hook_status_t;

static pk_hook_status_t hook_status = PK_HOOK_DISABLED;

static bool pk_nl_cmd_start(const struct sk_buff* skb, struct nlmsghdr* nlmsghdr,struct nlattr **attrs){
  printk(KERN_INFO "pk_nl_cmd_start called, registering hooks \n");
  if(hook_status == PK_HOOK_DISABLED) {
    nf_register_hooks(pk_filter_ops, ARRAY_SIZE(pk_filter_ops));
    hook_status = PK_HOOK_ENABLED;
  }
  return 1;
}

static bool pk_nl_cmd_stop(const struct sk_buff* skb, struct nlmsghdr* nlmsghdr,struct nlattr **attrs){
  printk(KERN_INFO "pk_nl_cmd_stop called, unregistering hooks \n");
  if(hook_status == PK_HOOK_ENABLED) {
    nf_unregister_hooks(pk_filter_ops, ARRAY_SIZE(pk_filter_ops));
    hook_status = PK_HOOK_DISABLED;
  }
  return 1;
}

struct sock_filter tcp_filter [] = {
  { 0x28, 0, 0, 0x0000000c },//     (000) ldh      [12]                             
  { 0x15, 0, 5, 0x000086dd },//     (001) jeq      #0x86dd          jt 2    jf 7    
  { 0x30, 0, 0, 0x00000014 },//     (002) ldb      [20]                             
  { 0x15, 6, 0, 0x00000006 },//     (003) jeq      #0x6             jt 10   jf 4    
  { 0x15, 0, 6, 0x0000002c },//     (004) jeq      #0x2c            jt 5    jf 11   
  { 0x30, 0, 0, 0x00000036 },//     (005) ldb      [54]                             
  { 0x15, 3, 4, 0x00000006 },//     (006) jeq      #0x6             jt 10   jf 11   
  { 0x15, 0, 3, 0x00000800 },//     (007) jeq      #0x800           jt 8    jf 11   
  { 0x30, 0, 0, 0x00000017 },//     (008) ldb      [23]                             
  { 0x15, 0, 1, 0x00000006 },//     (009) jeq      #0x6             jt 10   jf 11   
  { 0x6, 0, 0, 0x00040000 }, //     (010) ret      #262144                          
  { 0x6, 0, 0, 0x00000000 }, //     (011) ret      #0                               
  /**
  { 0x28, 0, 0, 0x0000000c },
  { 0x15, 27, 0, 0x000086dd },
  { 0x15, 0, 26, 0x00000800 },
  { 0x30, 0, 0, 0x00000017 },
  { 0x15, 0, 24, 0x00000006 },
  { 0x28, 0, 0, 0x00000014 },
  { 0x45, 22, 0, 0x00001fff },
  { 0xb1, 0, 0, 0x0000000e },
  { 0x48, 0, 0, 0x0000000e },
  { 0x15, 2, 0, 0x00000050 },
  { 0x48, 0, 0, 0x00000010 },
  { 0x15, 0, 17, 0x00000050 },
  { 0x28, 0, 0, 0x00000010 },
  { 0x2, 0, 0, 0x00000001 },
  { 0x30, 0, 0, 0x0000000e },
  { 0x54, 0, 0, 0x0000000f },
  { 0x64, 0, 0, 0x00000002 },
  { 0x7, 0, 0, 0x00000005 },
  { 0x60, 0, 0, 0x00000001 },
  { 0x1c, 0, 0, 0x00000000 },
  { 0x2, 0, 0, 0x00000005 },
  { 0xb1, 0, 0, 0x0000000e },
  { 0x50, 0, 0, 0x0000001a },
  { 0x54, 0, 0, 0x000000f0 },
  { 0x74, 0, 0, 0x00000002 },
  { 0x7, 0, 0, 0x00000009 },
  { 0x60, 0, 0, 0x00000005 },
  { 0x1d, 1, 0, 0x00000000 },
  { 0x6, 0, 0, 0x00040000 },
  { 0x6, 0, 0, 0x00000000 },
  */
};

static bool pk_nl_cmd_add_bpf(const struct sk_buff* skb, struct nlmsghdr* nlmsghdr,struct nlattr **attrs){
  
  pkfilter_msg_add_bpf_filter_cmd_t *msg;
  pk_cmd_t * pk_cmd;
  pk_attr_t* attr;
  struct bpf_prog *prog;
  struct sock_fprog_kern fprog;
  
  int err = 0;
  
  msg = nlmsg_data(nlmsghdr);
  if(msg->len >= 1024){
    printk(KERN_INFO "Program size exceeded limit(1024):%d \n ",
           msg->len);
    return 0;
  }

  printk(KERN_INFO "pk_nl_cmd_add_bpf : command %d  len %d \n",
         msg->command, msg->len);
  
  fprog.len =sizeof(tcp_filter)/sizeof(struct sock_filter); // msg->len;
  fprog.filter = tcp_filter; // msg->data;
  
  if((err = bpf_prog_create(&prog,&fprog))) {
    printk(KERN_INFO "Failed to create bpf program %d \n", err);
    return -EINVAL;
  }
  
  pk_cmd = (pk_cmd_t*) kmalloc(sizeof(pk_cmd_t), GFP_KERNEL);
  INIT_LIST_HEAD(&pk_cmd->list);
  INIT_LIST_HEAD(&pk_cmd->attrs);
  pk_cmd->type = msg->command;

  attr = (pk_attr_t*) kmalloc(sizeof(pk_attr_t),GFP_KERNEL);
  INIT_LIST_HEAD(&attr->list);
  attr->type = PK_AT_BPF;
  attr->len = prog->len;
  attr->val = prog;
  
  // add to command
  list_add(&pk_cmd->attrs,&attr->list);
  list_add(&pk_cmds,&pk_cmd->list);
  
  printk(KERN_INFO "Added pk_client bpf \n");
  return 1;
}

static bool pk_nl_cmd_add(const struct sk_buff* skb, struct nlmsghdr* nlmsghdr,struct nlattr **attrs){
  pkfilter_msg_config_cmd_t *msg;
  pk_client_cmd_t *cmd;
  pk_cmd_t * pk_cmd;
  int i;
  
  printk(KERN_INFO "pk_nl_cmd_add called\n");
  msg = nlmsg_data(nlmsghdr);
  cmd = &(msg->data[0]);
  
  printk(KERN_INFO " Adding rule type %d nattr %d size %d \n",
         cmd->type,cmd->nattr,cmd->size);
  
  pk_cmd = (pk_cmd_t*) kmalloc(sizeof(pk_cmd_t),GFP_KERNEL);
  INIT_LIST_HEAD(&pk_cmd->list);
  INIT_LIST_HEAD(&pk_cmd->attrs);
  pk_cmd->type = cmd->type;
  

  for(i = 0; i < cmd->nattr; i++) {
    printk(KERN_INFO "Attribute Type [%d] [%s] \n" ,
           cmd->attrs[i].type,
           cmd->attrs[i].val);    
    pk_cmd_add_attribute(pk_cmd, cmd->attrs[i].type,cmd->attrs[i].val);    
  }
  
  list_add(&pk_cmds,&pk_cmd->list);
  
  return 1;
}

static bool pk_cmd_match(pk_cmd_t* cmd,struct iphdr* hdr,struct sk_buff * skb)
{
  struct list_head* _a;
  pk_attr_t* a;
  bool match_attrs = true;

  if(cmd == NULL)
    return true;
  
  // Iterate through command attributes and make sure we match all attributes.
  // TODO We could have or matching too (and (or src="foo" dst="kkk"))  
  list_for_each(_a,&cmd->attrs) {
    a = list_entry(_a,pk_attr_t,list);
    match_attrs = match_attrs && pk_ip_attr_matchers_t[a->type](a->val,a->len,hdr,skb);
  }  
  return match_attrs;
}


static unsigned int
pk_filter_in(const struct nf_hook_ops *ops, struct sk_buff *skb,
	     const struct net_device *in, const struct net_device *out,
	     int (*okfn)(struct sk_buff *))
{
  struct list_head* _c;
  pk_cmd_t* c;
  struct iphdr* hdr = ip_hdr(skb);

  list_for_each(_c,&pk_cmds) {
    c = list_entry(_c,pk_cmd_t,list);
    if(pk_cmd_match(c,hdr,skb)) {
      switch (c->type){
      case PK_ACCEPT:
        return NF_ACCEPT;
      case PK_DROP:
        printk(KERN_INFO "Dropping pkt : src=%pI4 dst=%pI4 proto=%d len=%d \n",
               &(hdr->saddr),&(hdr->daddr),hdr->protocol,hdr->tot_len);
        return NF_DROP;
      case PK_LOG_HDR:
        printk(KERN_INFO "Logging header pkt : id=%d src=%pI4 dst=%pI4 proto=%d len=%d check=%d ttl=%d  frag_off=%d\n",
               hdr->id,
               &(hdr->saddr),&(hdr->daddr),hdr->protocol,hdr->tot_len,hdr->check,hdr->ttl,hdr->frag_off);
        return NF_ACCEPT;
      }
    }
  }
  return NF_ACCEPT;
}

static int __init pk_filter_init(void)
{
  struct proc_dir_entry *entry;
  //  pk_cmd_t * cmd;  
  printk(KERN_INFO "pkfilter:Hi pk-filter\n");

  /* Setup the pk-filter list */
  entry = proc_create_data("pk_filter_list", (S_IRUGO | S_IWUGO),
                           NULL, &proc_pk_filter_ops, NULL);

  /**
  cmd = (pk_cmd_t*) kmalloc(sizeof(pk_cmd_t),GFP_KERNEL);
  INIT_LIST_HEAD(&cmd->list);
  INIT_LIST_HEAD(&cmd->attrs);

  cmd->type = PK_LOG_HDR;
  pk_cmd_add_attribute(cmd,PK_AT_DST, "10.0.0.112");

  // Add command to command list
  list_add(&pk_cmds,&cmd->list);
  */
  
  return register_pernet_subsys(&pk_filter_net_ops);
}

static void pk_cmd_add_attribute(pk_cmd_t* cmd , int type,const char* value) {
  int attr_len = strlen(value);
  pk_attr_t* attr = (pk_attr_t*) kmalloc(sizeof(pk_attr_t),GFP_KERNEL);
  INIT_LIST_HEAD(&attr->list);
  attr->type = type;
  attr->val = kzalloc(1024,GFP_KERNEL);
  attr->len = min(attr_len,1024);
  strncpy(attr->val,value,1024);
  list_add(&cmd->attrs,&attr->list);
}

static void __exit pk_filter_cleanup(void)
{
  //  struct list_head *_c,*_a;
  //  pk_cmd_t* c = NULL;
  //  pk_attr_t* a = NULL;  
  remove_proc_entry("pk_filter_list",NULL);
  // TODO Need to free the command list
  /**
  list_for_each(_c,&pk_cmds) {
    c = list_entry(_c,pk_cmd_t,list);
    list_del(&c->list);
    kfree(c);
      
    list_for_each(_a,&c->attrs) {
      a = list_entry(_a,pk_attr_t,list);
    }
    kfree(c);
      
  }
  kfree(&pk_cmds);
 */
  unregister_pernet_subsys(&pk_filter_net_ops);
  printk(KERN_INFO "pkfilter: Goodbye pk-filter.\n");
}

static int proc_pk_filter_open( struct inode *inode, struct file *file )
{

  struct proc_data *data;
  if ((file->private_data = kzalloc(sizeof(struct proc_data ), GFP_KERNEL)) == NULL)
    return -ENOMEM;

  data = file->private_data;
  if ((data->rbuffer = kzalloc( 180, GFP_KERNEL )) == NULL) {
    kfree (file->private_data);
    return -ENOMEM;
  }

  data->writelen = 0;
  #define BUF_LEN 4096
  data->maxwritelen = BUF_LEN;

  if ((data->wbuffer = kzalloc( BUF_LEN, GFP_KERNEL )) == NULL) {
    kfree (data->rbuffer);
    kfree (file->private_data);
    return -ENOMEM;
  }

  data->on_close = proc_pk_filter_close;
  return 0;
}

static void proc_pk_filter_close( struct inode *inode, struct file *file )
{
  struct proc_data *data;
  char* line;
  int k = 0;

  data = file->private_data;

  
  if ( !data->writelen ) return;

  while((line = strsep(&(data->wbuffer),"\n")) !=NULL){
    printk(KERN_INFO "%d. %s",k++,line);
  }  
  // free buffers
}


// Genereic Proc Methods After This Point
/*
 *  What we want from the proc_fs is to be able to efficiently read
 *  and write the configuration.  To do this, we want to read the
 *  configuration when the file is opened and write it when the file is
 *  closed.  So basically we allocate a read buffer at open and fill it
 *  with data, and allocate a write buffer and read it at close.
 */

/*
 *  The read routine is generic, it relies on the preallocated rbuffer
 *  to supply the data.
 */
static ssize_t proc_read( struct file *file,
			  char __user *buffer,
			  size_t len,
			  loff_t *offset )
{
	struct proc_data *priv = file->private_data;

	if (!priv->rbuffer)
		return -EINVAL;

	return simple_read_from_buffer(buffer, len, offset, priv->rbuffer,
					priv->readlen);
}

/*
 *  The write routine is generic, it fills in a preallocated rbuffer
 *  to supply the data.
 */
static ssize_t proc_write( struct file *file,
			   const char __user *buffer,
			   size_t len,
			   loff_t *offset )
{
	ssize_t ret;
	struct proc_data *priv = file->private_data;

	if (!priv->wbuffer)
		return -EINVAL;

	ret = simple_write_to_buffer(priv->wbuffer, priv->maxwritelen, offset,
					buffer, len);
	if (ret > 0)
		priv->writelen = max_t(int, priv->writelen, *offset);

	return ret;
}


static int proc_close( struct inode *inode, struct file *file )
{
	struct proc_data *data = file->private_data;

	if (data->on_close != NULL)
		data->on_close(inode, file);
	kfree(data->rbuffer);
	kfree(data->wbuffer);
	kfree(data);
	return 0;
}


static bool pk_dst_match(const void* addr, int sz,struct iphdr* hdr,struct sk_buff * skb){
  char pkt_dst[20];
  sprintf(pkt_dst,"%pI4",&(hdr->daddr));
  return (strcmp(pkt_dst,addr) == 0);  
}

static bool pk_src_match(const void* addr, int sz,struct iphdr* hdr,struct sk_buff * skb){
  char pkt_src[20];
  sprintf(pkt_src,"%pI4",&(hdr->saddr));
  return (strcmp(pkt_src,addr) == 0);  
}

static bool pk_proto_match(const void* proto, int sz,struct iphdr* hdr,struct sk_buff * skb){
  unsigned int p = atou(proto);
  return (p == hdr->protocol);
}

//TODO need to work more to figure out why bpf filter is not working
static bool pk_bpf_match(const void* arg, int sz,struct iphdr* hdr,struct sk_buff * skb){ 

  unsigned int pkt_len;
  struct bpf_prog *prog = (struct bpf_prog*) arg;
  
  unsigned int header_len = skb->data - skb_network_header(skb);  
  skb_push(skb, header_len);
  
  pkt_len = BPF_PROG_RUN(prog,skb);

  skb_pull(skb, header_len);
  
  if(pkt_len!=0) {    
    printk(KERN_INFO "pk-filter: bpf didnt match %d \n",pkt_len);      
  } else{
    printk(KERN_INFO "Found a matching packet %d \n",pkt_len);      
  }
  return pkt_len!=0;
}

// from boot.h
unsigned int atou(const char *s)
{
	unsigned int i = 0;
	while (isdigit(*s))
		i = i * 10 + (*s++ - '0');
	return i;
}

module_init(pk_filter_init);
module_exit(pk_filter_cleanup);
