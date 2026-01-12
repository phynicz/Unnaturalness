import os
import sh
import re
import sys
import argparse
import pandas as pd
import numpy as np
import networkx as nx
from pathlib import Path
from tree_sitter import Language, Parser



QUERY = """(method_invocation 
    object: (identifier)
    name: (identifier) 
    arguments: (argument_list)) @ciphergetinstance"""
CRYPTO = "Cipher.getInstance"
EXT = ".java"


def instantiate_language(name, url):
    try:
        sh.git.clone(url, name)
    except sh.ErrorReturnCode as e:
        print("Clone error:", e.stderr.decode())
    Language.build_library(f"{name}.so", [name])
    return Language(f"{name}.so", name)

JAVA_LANGUAGE = instantiate_language("java", "https://github.com/tree-sitter/tree-sitter-java")
parser = Parser()
parser.set_language(JAVA_LANGUAGE)
query = JAVA_LANGUAGE.query(QUERY)

def text(node):
    return node.text.decode()

def traverse_tree(root, with_anon=False):
    G = nx.DiGraph()
    todo = [root]
    while todo:
        node = todo.pop()
        if with_anon or node.is_named:
            G.add_node(node.id, type=node.type)
        for child in node.children:
            if with_anon or child.is_named:
                G.add_edge(node.id, child.id)
            todo.append(child)
    return G

def extract_cipher_calls(source_code, tree):
    root = tree.root_node
    captures = query.captures(root)
    lines = []
    for capture, _ in captures:
        src_line = text(capture)
        if CRYPTO in src_line:
            lines.append((capture, src_line))
    return lines

def score_arguments(graph):
    labels = nx.get_node_attributes(graph, 'type')
    args = list(labels.values())[1:]
    value_count = dict(zip(*np.unique(args, return_counts=True)))
    value_count.pop('string_fragment', None)
    arg_count = sum(value_count.values())
    score = np.tanh(np.log10(arg_count)) if arg_count else 0
    return value_count, arg_count, float(score)

def process_java_file(app_id, class_path, filename):
    try:
        with open(class_path, 'rb') as f:
            source_code = f.read()
    except Exception as e:
        print(f"Read error: {e}")
        return []

    tree = parser.parse(source_code)
    calls = extract_cipher_calls(source_code, tree)
    rows = []

    for capture, line in calls:
        try:
            graph = traverse_tree(capture.child_by_field_name("arguments"))
            if graph is None or graph.number_of_nodes() == 0:
                metrics = ({}, 0, "-")
            else:
                metrics = score_arguments(graph)

            rows.append([
                app_id, class_path, filename, line,
                metrics[0], metrics[1], metrics[2]
            ])
        except Exception as e:
            print(f"Capture error: {e}")
            continue
    return rows

def collect_data(path):
    all_rows = []
    base_path = Path(path)
    if not base_path.exists():
        print(f"Path {path} not found.")
        return []

    for app_folder in base_path.iterdir():
        if app_folder.is_dir():
            app_id = app_folder.name
            for file_path in app_folder.rglob(f"*{EXT}"):
                rows = process_java_file(app_id, str(file_path), file_path.name)
                all_rows.extend(rows)
    return all_rows


if __name__ == "__main__":
    parser_cli = argparse.ArgumentParser(description="Extract Cipher.getInstance calls from Java projects.")
    parser_cli.add_argument("cipher_dir", help="Directory containing Java files/apps to analyze")
    parser_cli.add_argument("output_csv", help="Path to save the output CSV")
    args = parser_cli.parse_args()

    data = collect_data(args.cipher_dir)
    df = pd.DataFrame(data, columns=[
        'app_id', 'class_path', 'class_name', 
        'invocation', 'argument_list', 
        'number_of_arguments', 'complexity_score'
    ])
    df.to_csv(args.output_csv, index=False)
    print(f"Saved to {args.output_csv}")
