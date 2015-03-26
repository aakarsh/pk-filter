/*
 * Copyright (c)  Aakarsh Nair <aakarsh.nair@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

// TODO insert jokes about Greenspun's tenth rule here
//http://en.wikipedia.org/wiki/Greenspun%27s_tenth_rule

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
#include <linux/netfilter/x_tables.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aakarsh Nair");
MODULE_DESCRIPTION("A simple demonstration of using netfilter to track incoming packets");


// Configuration Rules
enum pk_rule_type {
  PK_ACCEPT,
  PK_DROP,
  PK_LOG,
  PK_LOG_HDR
};

enum pk_attr_type {
  PK_AT_SRC  = 0,
  PK_AT_DST = 1,
  PK_AT_PROTO = 2,
  PK_AT_MAX = 3
};

typedef struct pk_attr {
  struct list_head list;
  int type;
  char* val;
} pk_attr_t;

typedef struct pk_cmd {
  struct list_head list;
  int type;
  struct list_head attrs;
} pk_cmd_t;

// List of packet filtering commands
static LIST_HEAD(pk_cmds);

// Configure cmd & attributes
static void pk_cmd_add_attribute(pk_cmd_t* cmd , int type,const char* value);

// Matchers
static bool pk_dst_match(const char* addr, struct iphdr* hdr);
static bool pk_src_match(const char* addr, struct iphdr* hdr);
static bool pk_proto_match(const char* proto, struct iphdr* hdr);
static bool pk_cmd_match(pk_cmd_t* cmd,struct iphdr* hdr);

static bool (*pk_ip_attr_matchers_t[PK_AT_MAX+1])(const char* val, struct iphdr* hdr) =
{
  [PK_AT_SRC]  = pk_src_match,
  [PK_AT_DST] = pk_dst_match,
  [PK_AT_PROTO] = pk_proto_match,
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


static bool pk_cmd_match(pk_cmd_t* cmd,struct iphdr* hdr)
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
    match_attrs = match_attrs && pk_ip_attr_matchers_t[a->type](a->val,hdr);
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

  /**
     We must iterate through each cmd rule performing the action of
     the first matching rule.

     foreach cmd  in cmds
        if all_attributes match packet <-- can use hash function here.
           apply rule action
           return
     else 
        return accept
   */  
  list_for_each(_c,&pk_cmds) {
    c = list_entry(_c,pk_cmd_t,list);
    if(pk_cmd_match(c,hdr)) {
      switch (c->type){
      case PK_ACCEPT:
        return NF_ACCEPT;
      case PK_DROP:
        printk(KERN_INFO "dropping pkt : src=%pI4 dst=%pI4 proto=%d len=%d \n",
               &(hdr->saddr),&(hdr->daddr),hdr->protocol,hdr->tot_len);
        return NF_DROP;
      case PK_LOG_HDR:
        printk(KERN_INFO "logging header pkt : id=%d src=%pI4 dst=%pI4 proto=%d len=%d check=%d ttl=%d  frag_off=%d\n",
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
  pk_cmd_t * cmd;
  
  printk(KERN_INFO "pkfilter:Hi pk-filter\n");
  nf_register_hooks(pk_filter_ops, ARRAY_SIZE(pk_filter_ops));

  /* Setup the pk-filter list */
  entry = proc_create_data("pk_filter_list", (S_IRUGO | S_IWUGO),
                           NULL, &proc_pk_filter_ops, NULL);

  cmd = (pk_cmd_t*) kmalloc(sizeof(pk_cmd_t),GFP_KERNEL);
  INIT_LIST_HEAD(&cmd->list);
  INIT_LIST_HEAD(&cmd->attrs);

  cmd->type = PK_LOG_HDR;
  pk_cmd_add_attribute(cmd,PK_AT_DST, "10.0.0.243");
  pk_cmd_add_attribute(cmd,PK_AT_PROTO, "17");  

  // Add command to command list
  list_add(&pk_cmds,&cmd->list);
  
  return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void pk_cmd_add_attribute(pk_cmd_t* cmd , int type,const char* value) {
  pk_attr_t* attr = (pk_attr_t*) kmalloc(sizeof(pk_attr_t),GFP_KERNEL);
  INIT_LIST_HEAD(&attr->list);
  attr->type = type;
  attr->val = kzalloc(1024,GFP_KERNEL);
  strncpy(attr->val,value,1024);
  list_add(&cmd->attrs,&attr->list);
}

static void __exit pk_filter_cleanup(void)
{
  //  struct list_head *_c,*_a;
  //  pk_cmd_t* c = NULL;
  //  pk_attr_t* a = NULL;
  nf_unregister_hooks(pk_filter_ops,ARRAY_SIZE(pk_filter_ops));
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


static bool pk_dst_match(const char* addr, struct iphdr* hdr){
  char pkt_dst[20];
  sprintf(pkt_dst,"%pI4",&(hdr->daddr));
  return (strcmp(pkt_dst,addr) == 0);  
}

static bool pk_src_match(const char* addr, struct iphdr* hdr){
  char pkt_src[20];
  sprintf(pkt_src,"%pI4",&(hdr->saddr));
  return (strcmp(pkt_src,addr) == 0);  
}

static bool pk_proto_match(const char* proto, struct iphdr* hdr){
  unsigned int p = atou(proto);
  return (p == hdr->protocol);
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
