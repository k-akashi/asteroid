#include <json-c/json.h>

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "config.hpp"

int add_node_param(struct node_data *node, char *key, const char *val)
{
    //"node0" : { "interface": "mesh0", "id": 0, "ipaddr": "172.16.0.1/32", "macaddr": "00:00:00:00:00:01" }

    if (strncmp(key, "node", sizeof ("nod")) == 0) {
        strncpy(node->name, key, MAX_NAME_LEN);
    }
    else if (strncmp(key, "interface", sizeof ("interface")) == 0) {
        strncpy(node->ifname, val, MAX_IFNAME_LEN);
    }
    else if (strncmp(key, "id", sizeof ("id")) == 0) {
        node->id = atoi(val);
    }
    else if (strncmp(key, "ipaddr", sizeof ("ipaddr")) == 0) {
        strncpy(node->ip, val, IPADDR_SIZE);
    }
    else if (strncmp(key, "macaddr", sizeof ("macaddr")) == 0) {
        strncpy(node->mac, val, MACADDR_SIZE);
    }

    return 0;
}

int get_node_cnt(char *conf_file)
{
    int node_cnt = 0;
    struct json_object *fjson = json_object_from_file(conf_file);

    json_object_object_foreach(fjson, key, val) {
        node_cnt++;
        //if (!strncmp(key, "node", sizeof ("node"))) {
        //    node_cnt++;
        //}
    }

    return node_cnt;
}

struct node_data *create_node_list(char *conf_file, int node_cnt)
{
    struct json_object *fjson = json_object_from_file(conf_file);

    struct node_data *node_list, *node_ptr;
    struct node_data *node;
    node_ptr = node_list = (struct node_data *)malloc(sizeof (struct node_data) * node_cnt);
    node = (struct node_data *)malloc(sizeof (struct node_data));

    json_object_object_foreach(fjson, key, val) {
        if (strncmp(key, "node", 4) == 0) {
            memset(node, 0, sizeof (struct node_data));
            add_node_param(node_ptr, key, json_object_to_json_string(val));
            json_object_object_foreach(val, node_key, node_val) {
                add_node_param(node_ptr, node_key, json_object_get_string(node_val));
            }
        }
        
        node_ptr++;
    }

    return node_list;
}

void dump_node_list(struct node_data *node_list, int node_cnt)
{
    int i;
    struct node_data *node_ptr = node_list;

    for (i = 0; i < node_cnt; i++) {
        printf("node info:\n");
        printf("\tnode name:           %s\n", node_ptr->name);
        printf("\tnode interface name: %s\n", node_ptr->ifname);
        printf("\tnode id:             %d\n", node_ptr->id);
        printf("\tnode IP address:     %s\n", node_ptr->ip);
        printf("\tnode MAC address:    %s\n", node_ptr->mac);

        node_ptr++;
    }
    //"node0" : { "interface": "mesh0", "id": 0, "ipaddr": "172.16.0.1/32", "macaddr": "00:00:00:00:00:01" }
}

#if DEBUG
int
main(int argc, char **argv)
{
    int cnt;
    struct node_data *nlist;
    Config conf;

    cnt = conf.get_node_cnt(argv[1]);
    printf("%d\n", cnt);
    nlist = conf.create_node_list(argv[1], cnt);
    conf.dump_node_list(nlist, cnt);

    return 0;
}
#endif
