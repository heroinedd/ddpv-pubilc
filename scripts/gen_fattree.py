import os.path
import os
import socket
import struct

import networkx as nx
import argparse

from functools import reduce

import math


def generate_fattree_topology(k):
    topology = []
    total_edges = 0
    num_core = int((k / 2) ** 2)

    # core-agg 连接数字大的agg
    for i in range(num_core):
        core_switch = f"corei{i}"
        agg_index = int(math.floor(i / (k / 2)))
        for j in range(k):
            aggregation_switch = f"aggri{j}i{agg_index}"
            total_edges += 1
            topology.append((core_switch, f"{core_switch}->{aggregation_switch}", aggregation_switch,
                             f"{aggregation_switch}->{core_switch}"))

    # agg-edge
    for pod_index in range(k):
        for j in range(int(k / 2)):
            aggregation_switch1 = f"aggri{pod_index}i{j}"
            for m in range(int(k / 2)):
                aggregation_switch2 = f"edgei{pod_index}i{m}"
                total_edges += 1
                topology.append((aggregation_switch1, f"{aggregation_switch1}->{aggregation_switch2}",
                                 aggregation_switch2, f"{aggregation_switch2}->{aggregation_switch1}"))

    # edge-host 不加host！！！
    # for pod_index in range(k):
    #     for j in range(int(k/2)):
    #         agg_index = j
    #         aggregation_switch = f"aggr_{pod_index}_{agg_index}"
    #         for m in range(int(k/2)):
    #             host_index = int(m + j*k/2)
    #             host_switch = f"host_{pod_index}_{host_index}"
    #             topology.append((host_switch, f"{host_switch}->{aggregation_switch}", aggregation_switch, f"{aggregation_switch}->{host_switch}"))
    #             total_edges += 1

    return topology, total_edges


def save_topology_to_file(topology, filename):
    with open(filename, 'w') as file:
        for edge in topology:
            file.write(" ".join(edge) + "\n")


class IpGenerator():
    def __init__(self, prefix=24, base=167772160):
        self.prefix = prefix
        self.network = 0
        self.m = 1
        self.n = 1
        self.o = 1
        self.base = base

    def gen(self):
        ip = self.base + (self.network << (32 - self.prefix))
        self.network += 1
        return ip


def write_space(nodeToPrefix, prefix, output):
    with open(os.path.join(output, "packet_space"), 'w') as f:
        for node, ips in nodeToPrefix.items():
            for ip in ips:
                f.write('%s %s %s\n' % (node, ip, prefix))


def gen_fib(input, output, nprefix, prefix):
    FIBs = {}
    nodeToPrefix = {}
    ipGen = IpGenerator(prefix)
    G = nx.Graph()
    res = []
    for line in open(input):
        if '?' in line or 'None' in line:
            continue
        arr = line.split()
        latency = 0
        if len(arr) > 4:
            latency = int(arr[4])

        G.add_edge(arr[0], arr[2], portmap={arr[0]: arr[1], arr[2]: arr[3]}, latency=latency)

    for node in G.nodes:
        FIBs[node] = []
        nodeToPrefix[node] = []
        for i in range(nprefix):
            nodeToPrefix[node].append(ipGen.gen())
        # res[node] = dict()
        # res[node]["ip"] = nodeToPrefix[node]

    write_space(nodeToPrefix, prefix, output)

    for n in G.nodes:
        lengths, paths = nx.single_source_dijkstra(G, n, weight='latency')
        for (dst, path) in paths.items():
            if dst == n:
                continue
            for p in nodeToPrefix[dst]:
                FIBs[n].append('%s %s %s' % (p, prefix, G[n][path[1]]['portmap'][n]))
    path = os.path.join(output, "rule")
    if not os.path.exists(path):
        os.mkdir(path)
    for (sw, rules) in FIBs.items():
        res.append({"name": sw, "ip": [ch1(i) + "/" + str(prefix) for i in nodeToPrefix[sw]], "rule_num": len(rules)})
        with open(os.path.join(path, sw), 'w') as f:
            for rule in rules:
                f.write('fw %s\n' % rule)

    print('#nodes: %d' % len(G.nodes))
    print('#edges: %d' % len(G.edges))
    print('FIB generate to %s with %d entries' % (output, len(G.nodes) * (len(G.nodes) - 1) * nprefix))

    return res


def ch1(num):
    return socket.inet_ntoa(struct.pack("!I", num))


def read_fib(path, device):
    res = []
    with open(os.path.join(path, device), mode="r") as f:
        while True:
            line = f.readline()
            if not line:
                break
            line = line.strip()
            token = line.split(" ")
            if token[0] == "fw":
                index = len(res)
                match = ch1(int(token[1])) + "/" + token[2]
                action = "fwd(ALL, {%s})" % token[3]
                res.append({
                    "index": index,
                    "match": match,
                    "action": action}
                )
    return res


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="The output format is: node ip prefix outport, read as \"a node has a rule ip/prefix that forward to outport\"")
    # parser.add_argument("input", help="the input topology file")
    # parser.add_argument("output", help="the output FIB file")
    parser.add_argument("-nprefix", type=int, default=1, help="the number of prefixes on each node, default=1")
    parser.add_argument("-prefix", type=int, default=24, help="the prefix for each address, default=24")
    parser.add_argument("-kvalue", type=int, default=4, help="fattree size")
    args = parser.parse_args()

    # Example usage
    k_value = args.kvalue  # You can adjust this based on your desired Fattree size
    fattree_topology, total_edges = generate_fattree_topology(k_value)
    save_topology_to_file(fattree_topology, '../config/fattree' + str(k_value) + '/topology')

    k = k_value
    total_nodes = 5 * k * k / 4
    print(f"Total nodes in Fattree topology: {total_nodes}")
    print(f"Total edges in Fattree topology: {total_edges}")

    inputFile = '../config/fattree' + str(k_value) + '/topology'
    onputFile = '../config/fattree' + str(k_value)
    gen_fib(inputFile, onputFile, args.nprefix, args.prefix)
