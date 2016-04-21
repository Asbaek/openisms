#usr/bin/env python
# -*- coding: utf-8 -*-
from flask import Flask, request, render_template, jsonify, redirect, url_for
import json
import codecs
import os
import re

DATA = "assessments/data.json"
SCHEMA = "assessments/schema.json"

app = Flask(__name__)

# general functions


def import_jsondata(selected_file):
    """
    Returns dictionary loaded from specified json file
    Argument:
        selected_file: String such as "assessments/data.json"
    """
    f = codecs.open(selected_file, mode='r', encoding='utf-8')
    data = json.load(f)
    f.close()
    return data


def write_file(filename, contents, charset='utf-8'):
    """
    Returns nothing, but writes unicode text to specified file
    Arguments:
        filename: String, such as "assessments/data.json"
        contents: String, such as output form json.dumps()
        charset: Must be utf-8 to allow special characters
    """
    with open(filename, 'w') as f:
        f.write(contents.encode(charset))

@app.route("/", methods=['GET'])
def index():
    """
    Displays Welcome page 
    """
    return render_template('index.html')

@app.route("/about", methods=['GET'])
def about():
    """
    Displays About/FAQ page
    """
    return render_template('about.html')

@app.route("/assessments", methods=['GET'])
def assessments():
    """
    Displays list of processes to analyse or delete 
    """
    # create process_table
    data=import_jsondata(DATA)
    process_table=data['processes']
    return render_template('assessments.html',process_table=process_table)

@app.route("/show_json", methods=['GET'])
def show_json():
    data = import_jsondata(DATA)
    return jsonify(data)


if __name__ == '__main__':
    # Try and get SERVER_NAME env variable, defaults to 127.0.0.1
    host = os.getenv('HOSTNAME', '127.0.0.1')

    app.run(host=host)
