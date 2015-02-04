import networkx as nx
from .codeblocks import get_nx_graph, get_block_start, codeblock, flowchart

COLOR_REACHABLE = 0x66EE11
COLOR_UNREACHABLE = 0x6611EE
COLOR_REACHING = 0x11EE66
COLOR_NOT_REACHING = 0x1166EE
COLOR_SOURCE = 0xEE6611
COLOR_NONE = 0xFFFFFFFF


def clear_func(ea):
    for block in flowchart(ea):
        block.color = COLOR_NONE


def mark_not_reaching_nodes(ea, source_color=COLOR_SOURCE, other_color=COLOR_NOT_REACHING):
    graph = get_nx_graph(ea)
    graph = graph.reverse()
    block_ea = get_block_start(ea)
    reaching = nx.descendants(graph, block_ea)
    for node_ea in graph.nodes_iter():
        if node_ea not in reaching:
            codeblock(node_ea).color = other_color

    codeblock(ea).color = source_color


def mark_reaching_nodes(ea, source_color=COLOR_SOURCE, other_color=COLOR_REACHING):
    graph = get_nx_graph(ea)
    graph = graph.reverse()
    block_ea = get_block_start(ea)
    for descendant in nx.descendants(graph, block_ea):
        codeblock(descendant).color = other_color

    codeblock(ea).color = source_color


def mark_unreachable_nodes(ea, source_color=COLOR_SOURCE, other_color=COLOR_UNREACHABLE):
    graph = get_nx_graph(ea)
    block_ea = get_block_start(ea)
    descendants = nx.descendants(graph, block_ea)
    for block in flowchart(ea):
        if block.startEA not in descendants:
            block.color = other_color

    codeblock(ea).color = source_color


def mark_reachable_nodes(ea, source_color=COLOR_SOURCE, other_color=COLOR_REACHABLE):
    graph = get_nx_graph(ea)
    block_ea = get_block_start(ea)
    for descendant in nx.descendants(graph, block_ea):
        codeblock(descendant).color = other_color

    codeblock(ea).color = source_color