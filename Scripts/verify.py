import argparse
from tree_sitter import Language, Parser
import networkx as nx
import matplotlib.pyplot as plt
import sh
from pathlib import Path
import re
import os
import pandas as pd
import numpy as np
import csv



QUERY= """(method_declaration  
name: (identifier) @verify
parameters: (formal_parameters)) """
method = "verify"
ext = ".java"
app = []
current_app = []

def instantiate_language(name, url):
    try:
        sh.git.clone(url, name)
    except sh.ErrorReturnCode as e:
        print(e.stderr.decode())
    Language.build_library(f"{name}.so", [name])
    return Language(f"{name}.so", name)


JAVA_LANGUAGE = instantiate_language("java", "https://github.com/tree-sitter/tree-sitter-java")

parser = Parser()
parser.set_language(JAVA_LANGUAGE)
query = JAVA_LANGUAGE.query(QUERY)

columns = ['app_id','class_path', 'class_name', 'method', 'invocation', 'method_body', 'argument_list', 'number_of_arguments', 'complexity_score']

df = pd.DataFrame(columns=columns)

def get_app_id(path):
    for dir in os.listdir(path):
        app_cipher = os.path.join(path, dir)
        for root, dirs, files in os.walk(app_cipher, topdown=True, onerror=None, followlinks=True):
            app_id = os.path.basename(app_cipher)
            for filename in files:
                if ext in filename:
                    class_path = os.path.join(app_cipher, filename)
                    class_name = filename
                    app.clear()
                    with open(class_path, 'rb')  as file:
                        source_code = file.read()
                        tree = parser.parse((source_code))
                        root = tree.root_node
                        captures = query.captures(root)
                        app.append(app_id)
                        app.append(class_path)
                        app.append(class_name)
                        print_captures_cipher(captures, app)
    

def print_captures_cipher(captures, app):
    for capture, tag in captures:
        name = text(capture) 
        for line in name.splitlines():
            if method == line:
                app_name = app[0]
                class_dir = app[1]
                class_n = app[2]
                cipher_obj = line
                current_app.append(app_name)
                current_app.append(class_dir)
                current_app.append(class_n)
                current_app.append(cipher_obj)
                current_app.append(capture.parent.text.decode())

                try:
                    tree_to_graph(capture.parent.child_by_field_name('body'))
                    if tree_to_graph(capture.parent.child_by_field_name('body')) is None:
                        current_app.append("-")
                        current_app.append("-")
                        current_app.append("-")
                        current_app.append("-")
                        df.loc[len(df)] = current_app
                        current_app.clear()
                        continue
                    else:
                        current_app.append(capture.parent.child_by_field_name('body').text.decode())
                        metric_score(tree_to_graph(capture.parent.child_by_field_name('body')), "type")
                except None as e:
                    continue
            else:
                continue


def metric_score(G, label=None):            
    labels = nx.get_node_attributes(G, "type")
    args = list(labels.values())
    args.pop(0)
    values, counts = np.unique(args, return_counts=True) 
    value_count = dict(zip(values, counts))
    x = sum(counts)                               
    try:
        z = np.log10(x)
        weird_score = np.tanh(z)
        current_app.append(value_count)
        current_app.append(x)
        current_app.append(float(weird_score))
        print(current_app)
        print("\n")
        df.loc[len(df)] = current_app
        current_app.clear()
    except ZeroDivisionError as e:
        current_app.append(value_count)
        current_app.append(x)
        current_app.append(0)
        print(current_app)
        print("\n")
        df.loc[len(df)] = current_app
        current_app.clear()


def tree_to_graph(root, with_anon=False):
    G = nx.DiGraph()
    todo = [root]
    while todo:
        try:
            node = todo.pop()
            if node.is_named:
                G.add_node(node.id, type=node.type)
            for child in node.children:
                if child.is_named:
                    G.add_edge(node.id, child.id)
                todo.append(child)
        except AttributeError as e:
            return None 
    return G


def text(node):
    return node.text.decode()

if __name__ == "__main__":
    parser_cli = argparse.ArgumentParser(description="Extract Cipher.getInstance calls from Java projects.")
    parser_cli.add_argument("cipher_dir", help="Directory containing Java files/apps to analyze")
    parser_cli.add_argument("output_csv", help="Path to save the output CSV")
    args = parser_cli.parse_args()
    path = os.path.join(os.getcwd(), args.cipher_dir)
    get_app_id(path)
    df.to_csv(args.output_csv, index=False)
    print(f"Saved to {args.output_csv}")

