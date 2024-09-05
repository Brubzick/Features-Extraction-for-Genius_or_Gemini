import networkx as nx
import os

a = "sda/das/asda/abc"
b = 'cdf'
d = os.path.dirname(a)
print(os.path.join(d,b))
