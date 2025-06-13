import os.path
import os
import socket
import struct
import time

import networkx as nx
import argparse

from functools import reduce
from Planner.planner import Planner

import math

config_dir = "../config/"


def generate_fattree_topology(k):
    topology = []
    total_edges = 0
    num_core = int((k / 2) ** 2)

    # core-agg
    for i in range(num_core):
        core_switch = f"core_{i}"
        agg_index = int(math.floor(i / (k / 2)))
        for j in range(k):
            aggregation_switch = f"aggr_{j}_{agg_index}"
            total_edges += 1
            topology.append((core_switch, f"{core_switch}->{aggregation_switch}", aggregation_switch,
                             f"{aggregation_switch}->{core_switch}"))

    # agg-edge
    for pod_index in range(k):
        for j in range(int(k / 2)):
            aggregation_switch1 = f"aggr_{pod_index}_{j}"
            for m in range(int(k / 2)):
                aggregation_switch2 = f"edge_{pod_index}_{m}"
                total_edges += 1
                topology.append((aggregation_switch1, f"{aggregation_switch1}->{aggregation_switch2}",
                                 aggregation_switch2, f"{aggregation_switch2}->{aggregation_switch1}"))

    return topology, total_edges


def save_topology_to_file(topology, filename):
    with open(filename, 'w') as file:
        for edge in topology:
            file.write(" ".join(edge) + "\n")


class IpGenerator:
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


def write_space(node_to_prefix, prefix, output):
    with open(os.path.join(output, "packet_space"), 'w') as f:
        for node, ips in node_to_prefix.items():
            for ip in ips:
                f.write('%s %s %s\n' % (node, ip, prefix))


def gen_fib(input_file, output_file, n_prefix, prefix):
    FIBs = {}
    node_to_prefix = {}
    ip_generator = IpGenerator(prefix)
    G = nx.Graph()
    res = []
    for line in open(input_file):
        if '?' in line or 'None' in line:
            continue
        arr = line.split()
        latency = 0
        if len(arr) > 4:
            latency = int(arr[4])

        G.add_edge(arr[0], arr[2], portmap={arr[0]: arr[1], arr[2]: arr[3]}, latency=latency)

    for node in G.nodes:
        FIBs[node] = []
        node_to_prefix[node] = []
        for i in range(n_prefix):
            node_to_prefix[node].append(ip_generator.gen())
        # res[node] = dict()
        # res[node]["ip"] = nodeToPrefix[node]

    write_space(node_to_prefix, prefix, output_file)

    for n in G.nodes:
        lengths, paths = nx.single_source_dijkstra(G, n, weight='latency')
        for (dst, path) in paths.items():
            if dst == n:
                continue
            for p in node_to_prefix[dst]:
                FIBs[n].append('%s %s %s' % (p, prefix, G[n][path[1]]['portmap'][n]))
    path = os.path.join(output_file, "rule")
    if not os.path.exists(path):
        os.mkdir(path)
    for (sw, rules) in FIBs.items():
        res.append({"name": sw, "ip": [ch1(i) + "/" + str(prefix) for i in node_to_prefix[sw]], "rule_num": len(rules)})
        with open(os.path.join(path, sw), 'w') as f:
            for rule in rules:
                f.write('fw %s\n' % rule)

    print('#nodes: %d' % len(G.nodes))
    print('#edges: %d' % len(G.edges))
    print('FIBs generated to %s with %d entries' % (output_file, len(G.nodes) * (len(G.nodes) - 1) * n_prefix))

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


def gen_dpvnet(k):
    planner = Planner()
    planner.read_topology_from_file(f"{config_dir}fattree{k}/topology")

    total_states = []
    # build DPVNet for two edge routers in the same pod
    device1 = 'edge_0_0'
    device2 = f'edge_0_{(k // 2) - 1}'
    states = planner.gen(None, device2, [device1], r"(exist >= 1, (`%s`.*`%s` , (<= shortest)))" % (device1, device2))
    if states:
        total_states.append((device2, [device1], "exists >= 1", "%s.*%s" % (device1, device2), states))
        print(f"generated DPVNet for {device1} -> {device2}")
    # build DPVNet for two edge routers in different pods
    start = time.time()
    device1 = 'edge_0_0'
    device2 = f'edge_{k - 1}_{(k // 2) - 1}'
    states = planner.gen(None, device2, [device1], r"(exist >= 1, (`%s`.*`%s` , (<= shortest)))" % (device1, device2))
    if states:
        total_states.append((device2, [device1], "exists >= 1", "%s.*%s" % (device1, device2), states))
        print(f"generated DPVNet for {device1} -> {device2}")
    print(time.time() - start)
    planner.output_puml(total_states, f"{config_dir}fattree{k}/DPVNet.puml", True)
    print('DPVNet generated to %s' % f"{config_dir}fattree{k}/DPVNet.puml")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="The output format is: node ip prefix outport, read as \"a node has a rule ip/prefix that forward to outport\"")
    parser.add_argument("-nprefix", type=int, default=1, help="the number of prefixes on each node, default=1")
    parser.add_argument("-prefix", type=int, default=24, help="the prefix for each address, default=24")
    parser.add_argument("-kvalue", type=int, default=4, help="fattree size")
    args = parser.parse_args()

    # k = args.kvalue  # You can adjust this based on your desired Fattree size
    k = 48

    # 1. generate topology
    # fattree_topology, total_edges = generate_fattree_topology(k)
    # save_topology_to_file(fattree_topology, f"{config_dir}fattree{k}/topology")
    # total_nodes = 5 * k * k / 4
    # print(f"Total nodes in Fattree topology: {total_nodes}")
    # print(f"Total edges in Fattree topology: {total_edges}")

    # 2. generate FIBs
    # input_f = f"{config_dir}fattree{k}/topology"
    # output_f = f"{config_dir}fattree{k}"
    # gen_fib(input_f, output_f, args.nprefix, args.prefix)

    # 3. generate DPVNet
    gen_dpvnet(k)
