#ifndef __CONFIG_H__
#define __CONFIG_H__

#define MAX_NAME_LEN 20
#define MAX_IFNAME_LEN 16
#define IPADDR_SIZE 20
#define MACADDR_SIZE 18

struct node_data {
    char name[MAX_NAME_LEN];
    char ifname[MAX_IFNAME_LEN];
    int id;
    char ip[IPADDR_SIZE];
    char mac[MACADDR_SIZE];
};

int add_node_param(struct node_data *node, char *key, const char *val);
int get_node_cnt(char *conf_file);
struct node_data *create_node_list(char *conf_file, int node_cnt);
void dump_node_list(struct node_data *node_list, int node_cnt);

#endif // __CONFIG_H__
