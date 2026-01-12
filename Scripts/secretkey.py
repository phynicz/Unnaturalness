import argparse
from tree_sitter import Language, Parser
import sh
import os
import pandas as pd
import networkx as nx
import numpy as np


#  RUN with: python secretkey.py <class_files_dir> <output.csv>

QUERY= """(object_creation_expression 
type: (type_identifier)
arguments: (argument_list) @args ) @create"""
crypto = "SecretKeySpec("
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

columns = ['app_id','class_path', 'class_name', 'invocation', 'argument_list', 'number_of_arguments', 'complexity_score']

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
            if crypto in line:
                app_name = app[0]
                class_dir = app[1]
                class_n = app[2]
                cipher_obj = line
                current_app.append(app_name)
                current_app.append(class_dir)
                current_app.append(class_n)
                current_app.append(cipher_obj)
                try:
                    tree_to_graph(capture.child_by_field_name('arguments'))
                    if tree_to_graph(capture.child_by_field_name('arguments')) is None:
                        current_app.append("-")
                        current_app.append("-")
                        current_app.append("-")
                        df.loc[len(df)] = current_app
                        current_app.clear()
                        continue
                    else:
                        metric_score(tree_to_graph(capture.child_by_field_name('arguments')), "type")
                except None as e:
                    continue
            else:
                continue


def metric_score(G, label=None):           
        labels = nx.get_node_attributes(G, label)
        args = list(labels.values())
        args.pop(0)
        values, counts = np.unique(args, return_counts=True)
        value_count = dict(zip(values, counts))
        if 'string_fragment' in value_count:
            del value_count['string_fragment']
        x = sum(value_count.values())
        try:
            shift = np.log10(x)
            weird_score = np.tanh(shift)
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
            if with_anon or node.is_named:
                G.add_node(node.id, type=node.type)
            for child in node.children:
                if with_anon or child.is_named:
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
