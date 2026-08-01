import matplotlib.pyplot as plt
import networkx as nx

def generate_network_graph(target, ports):
    G = nx.Graph()
    G.add_node(f"Target: {target}")
    for p in ports:
        node_name = f"Port {p}"
        G.add_node(node_name)
        G.add_edge(f"Target: {target}", node_name)
    
    plt.figure(figsize=(8, 6))
    nx.draw(G, with_labels=True, node_color="#5844FF", node_size=2000, font_color="white")
    plt.show()
