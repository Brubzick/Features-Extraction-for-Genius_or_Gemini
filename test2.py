import networkx as nx

cfg = nx.DiGraph()
cfg.add_node(3)
cfg.add_node(5)
cfg.add_edge(3,5)

print(len(cfg))