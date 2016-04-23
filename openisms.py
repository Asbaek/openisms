#sr/bin/env python
# -*- coding: utf-8 -*-

#########################
# External dependencies #
#########################
from flask import Flask, request, render_template, jsonify, redirect, url_for
import json
import codecs
import os
import re

DATA = "assessments/data.json"
SCHEMA = "assessments/schema.json"
CONTROL_LIBRARY = "assessments/control_library.json"
app = Flask(__name__)

###########################
# Multi purpose functions #
###########################
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

##################
# Risk functions #
##################
def get_table(aspect_ids):
    """
    get_details returns a list of dictionaries where each
    list row is a dictionary with details about  aspect_ids.
    Arguments:
    - aspect_ids must be a list with strings. The aspects 
      must be of the same kind.
    """
    #Check and collect input
    assert(type(aspect_ids) is list),"Function get_table only accepts lists"
    data=import_jsondata(DATA)
    control_library=import_jsondata(CONTROL_LIBRARY)
    #Prepare output
    if "process" in aspect_ids[0]:
        aspect_type="process"
        aspect_data = data["processes"]
    elif "asset" in aspect_ids[0]:
        aspect_type="asset"
        aspect_data = data["assets"]
    elif "threat" in aspect_ids[0]:
        aspect_type="threat"
        aspect_data = data["threats"]
    elif "container" in aspect_ids[0]:
        aspect_type="container"
        aspect_data = data["containers"] 
    else:
        aspect_type="control"
        aspect_data = control_library["control_library"]
    
    result=[]
    for aspect_id in aspect_ids:
       result_row = {}
       id_identifier = aspect_type + "_id"
       for item in aspect_data:
           row_id = item.get(id_identifier, None)
           if row_id and (row_id in aspect_id):
               result.append(item) 
    if not result:
        print "get_table returned an empty list"
    #Output validation
    assert(type(result) is list)
    return result


##########################
# Web Application Output #
##########################
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

@app.route("/analyse_process", methods=['GET'])
def analyse_process():
    """
    Displays forms to analyse processes 
    """
    #get input data
    process_ids = []
    process_ids.append(request.args['process_id'])
    process_table = get_table(process_ids)

    #process_table = get_table("process",process_id,data)
    #asset_table   = get_table("asset",process_id,data)
    #threat_table  = get_table("threat",process_id,data)
    return render_template('analyse_process.html', process_table=process_table)

@app.route("/show_json", methods=['GET'])
def show_json():
    data = import_jsondata(DATA)
    return jsonify(data)

#############
# Main code #
#############
if __name__ == '__main__':
    # Try and get SERVER_NAME env variable, defaults to 127.0.0.1
    host = os.getenv('HOSTNAME', '127.0.0.1')
    app.run(host=host)
