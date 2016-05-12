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
    list row is a dictionary with details about aspect_ids.
    Arguments:
    - aspect_ids must be a list with strings. The aspects 
      must be of the same kind.
    """
    #Check and collect input
    assert(type(aspect_ids) is list),"Function get_table only accepts lists"
    data=import_jsondata(DATA)
    aspect_ids = [x for x in aspect_ids if x is not None]
    aspect_ids = sorted(set(aspect_ids))
    control_library=import_jsondata(CONTROL_LIBRARY)
    if len(aspect_ids)>0:
        aspect_id_sample = aspect_ids[0]
    else:
        return []
    #Prepare output
    if "process" in aspect_id_sample:
        aspect_type="process"
        aspect_data = data["processes"]
    elif "asset" in aspect_id_sample:
        aspect_type="asset"
        aspect_data = data["assets"]
    elif "threat" in aspect_id_sample:
        aspect_type="threat"
        aspect_data = data["threats"]
    elif "container" in aspect_id_sample:
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
           if (row_id and aspect_id):
               if (row_id==aspect_id):
                   result.append(item) 
    #Output validation
    assert(type(result) is list)
    return result

def get_process_assets(process_ids):
    """
    get_process_assets returns a list of asset ids for assets with a given process name
    Arguments:
    - process_id. A string like "process0000001"
    """
    assert(type(process_ids) is list), "get_process_assets got wrong input. Must be list"
    process_ids = sorted(set(process_ids))
    data=import_jsondata(DATA)
    result = []
    for risk in data["risktable"]:
        temp_process_id = risk.get("process_id", None) 
        temp_asset_id   = risk.get("asset_id", None)
        if temp_process_id in process_ids:
            result.append(temp_asset_id)
    result = sorted(set(result))
    assert(type(result) is list), "get_process_assets encountered an error in result variable"
    return result

def get_asset_threats(asset_ids):
    """
    Returns a list of threat dictionaries. Each dictionary contains needed information to describe the threat, affected containers and security controls. 
    Arguments:
    - asset_ids: A list of strings in the format "asset" followed by a unique integer number.
    """
    assert(type(asset_ids) is list), "get_asset_threats got wrong input. Must be list"
    asset_ids = sorted(set(asset_ids))
    data=import_jsondata(DATA)
    result = []
    for risk in data["risktable"]:
        temp_asset_id = risk.get("asset_id",None)
        temp_threat_id = risk.get("threat_id",None)
        if temp_asset_id and (temp_asset_id in asset_ids):
            result.append(temp_threat_id)
    result = sorted(set(result))
    assert(type(result) is list), "get_asset_threats encountered an error in result variable"
    return result

def get_control_dict(search_control_id):
    """
    Returns a dict with control_id and control_name if searc_control_id is found in control_library.json 
    Returns an empty dict if nothing is found.
    Arguments:
    - search_control_id: string with a control_id
    """
    assert(type(search_control_id) is str)
    control_library=import_jsondata(CONTROL_LIBRARY)
    result = {}
    for index, control in enumerate(control_library["control_library"]):
        control_id = control.get("control_id", None)
        if search_control_id in control_id:
            control_name = control.get("control_name", None)
            result.update({"control_id":control_id,"control_name":control_name})
    assert(type(result) is dict)
    return result

def get_container_dict(search_container_id):
    """
    Returns a dict with container_id and container_name from the table containers in data.json
    Returns an empty dict if nothgin is found.
    Arguments:
    - search_container_id: string with container_id
    """
    assert(type(search_container_id) is str)
    data=import_jsondata(DATA)
    result={}
    for index, container in enumerate(data["containers"]):
        container_id = container.get("container_id", None)
        if search_container_id in container_id:
            container_name = container.get("container_name", None)
            result.update({"container_id":container_id, "container_name":container_name})
    assert(type(result) is dict)
    return result

def get_risk_score(threat_dict):
    """
    Returns a risk score as a string with 2 decimals. 
    Returns "No risk score" string if an error is encountered 
    The method is based on octave allegro.
    Arguments:
    - threat_dict: A dict loaded from threats in data.json 
    """
    data=import_jsondata(DATA)
    global_impact_details=data.get("global_impact_details", None)
    risk_score = -1.0 
    impact_scores = threat_dict.get("impact_scores",None)
    try:
        for global_impact in global_impact_details: 
            for impact_score in impact_scores:
                global_impact_type = global_impact.get("type", None)
	        impact_score_type = impact_score.get("type", None)
                if global_impact_type in impact_score_type:
                    # note that priority 1 is weighted 5 and 
                    # priority 5 is weigted 1.
		    # the weight is therefore weight=6-priority
		    priority = global_impact.get("priority", None)
		    weight = 6.0-float(priority)
		    score = float(impact_score.get("score", None))
                    risk_score += weight*score
    except KeyError,e:
	print "get_risk_score error: "+str(e)

    risk_score=risk_score*10.0/45.0      
    if risk_score>0.0:
    	result = str('{0:.2f}'.format(risk_score))
    else:
	result = "No risk calculated"
    assert(type(result) is str)
    return result


def inject_risk_scores(threat_table):
    """
    Returns an a threat table with a new or updated row named "risk score"
    Arguments:
    - threat_table: A list of threat dicts. 
    """
    assert(type(threat_table) is list)
    for index,threat_dict in enumerate(threat_table):
        risk_score=get_risk_score(threat_dict)
	threat_table[index].update({"risk_score":risk_score})
    assert(type(threat_table) is list)
    return threat_table  

def inject_containers_and_controls(threat_table):
    """
    Returns an extended threat_table (list of threat dicts). Each threat dict gets container element injected:
    "containers":[
     {"container_id":"",
     "container_name":"",
     "container_controls":[{"control_id":"","control_name"}]
     }]
    Arguments:
    - threat_table: is a list of threat dicts.
    """
    control_library = import_jsondata(CONTROL_LIBRARY)
    data=import_jsondata(DATA)
    for index,threat_dict in enumerate(threat_table):
        containers=[]
        threat_table_id = threat_dict.get("threat_id",None)
        for risk in data["risktable"]:
            temp_threat_id = risk.get("threat_id", None)
            if temp_threat_id and (temp_threat_id in threat_table_id):
                temp_container_id=risk.get("container_id", None)
                temp_control_id  =risk.get("control_id", None)
                new_data = {}
                new_data["container_controls"]=[]
                if temp_container_id:
                    container_dict ={}
                    container_dict=get_container_dict(str(temp_container_id))
		    new_data.update(container_dict)
                    if temp_control_id:
                        control_dict = {}
                        control_dict = get_control_dict(str(temp_control_id))
                        new_data["container_controls"].append(control_dict)
                containers.append(new_data)
    	threat_table[index]["containers"]=containers
    return threat_table        

def apply_to_risktable(risk_dict):
    """
    update_risktable updates the risktable element in data.json to contain a specified reference.
    Arguments:
    - risk_dict contains a dictionary of the format used in risktable.
      Example: 
      X is a unique 6 digit number
      {
          "asset_id": "assetX", 
          "container_id": "containerX", 
          "control_id": "AC-02", 
          "deliverable_id": "deliverableX", 
          "process_id": "processX", 
          "threat_id": "threatX"
      }
    """
    assert(type(risk_dict) is dict)
    assert(len(risk_dict)>0) # Min. 1 keys
    assert(len(risk_dict)<3) # Max. 2 keys
    data=import_jsondata(DATA)
    risk_dict_already_exists=False
    for var_dict in data["risktable"]:
        if cmp(var_dict, risk_dict)==0:
            risk_dict_already_exists=True
    if risk_dict_already_exists:
        pass
    else:   
        data["risktable"].append(risk_dict)
        output = json.dumps(data)
        write_file(DATA, output, charset='utf-8')
    return jsonify(risk_dict)

def apply_to_aspect(aspect, new_aspect_detail):
    """
    update_aspect_details():
    Arguments:
    - aspect to update. 
    - details to update. Must be in a compliant dict format.
    """
    assert(type(aspect) is str)
    assert(type(new_aspect_detail) is dict)
    data=import_jsondata(DATA)
    if aspect in "asset":
        asset_id_new= new_aspect_detail.get("asset_id", None)
        if asset_id_new:
            asset_found=False
            for index,asset in enumerate(data['assets']):
                asset_id_existing=asset.get("asset_id", None)
                if asset_id_new in asset_id_existing:
                    data["assets"][index].update(new_aspect_detail)  
                    asset_found=True
            if not asset_found:
                data["assets"].append(new_aspect_detail)
        else:
            return False
    elif aspect in "process":
        process_id_new = new_aspect_detail.get("process_id", None)
        if process_id_new:
            process_found=False
            for index, process in enumerate(data['processes']):
	        process_id_existing = process.get("process_id", None)
                if process_id_new in process_id_existing:
                    data["processes"][index].update(new_aspect_detail)
                    process_found = True
            if not process_found:
                data["processes"].append(new_aspect_detail)
        else:
            return False
    outputdata = json.dumps(data)
    write_file(DATA, outputdata, charset='utf-8')
    return jsonify(new_aspect_detail)

    
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

    asset_ids = get_process_assets(process_ids)
    asset_table = get_table(asset_ids)
    data = import_jsondata(DATA)
    rxo_values = data["rxo_values"]
    global_impact_details = data["global_impact_details"]

    threat_ids = get_asset_threats(asset_ids)
    threat_table = get_table(threat_ids)
    threat_table = inject_containers_and_controls(threat_table)
    threat_table = inject_risk_scores(threat_table)
    
    control_library = import_jsondata(CONTROL_LIBRARY)
    container_library = data.get("container_library", None)
    return render_template('analyse_process.html', process_table=process_table,
						   asset_table=asset_table,
						   rxo_values=rxo_values,
						   global_impact_details=global_impact_details,
						   threat_table=threat_table,
						   control_library=control_library,
						   container_library=container_library)
def get_next_id(aspect_id_type):
    """
    get_next_id returns next unique available ID number, depending on aspect_name.
    The function will search data dict for any occurences. 
    If none is found, the first number in the sequence is returned.
    Arguments:
    - aspect_id_type is one of the keys defined in schema["risktable"].
    """
    schema=import_jsondata(SCHEMA)
    risktable_template = schema.get("risktable",None)
    aspect_id_types = list(risktable_template[0].keys())
    data = import_jsondata(DATA)
    if aspect_id_type is "asset_id":
        assets=data.get("assets",None)
        asset_ids = []
        for asset in assets:
            asset_id = asset.get("asset_id", None)
            if asset_id: 
                asset_ids.append(asset_id)    
        risktable=data.get("risktable", None)
        for risk in risktable:
            asset_id = risk.get("asset_id", None)
            if asset_id:
                asset_ids.append(asset_id)
        if not asset_ids:
            asset_ids.append("asset000000")
        int_ids = [int(a[5:]) for a in asset_ids]
        return "asset" + str(max(int_ids)+1).zfill(6)   


@app.route("/add_asset", methods=['POST'])
def add_asset():
    schema=import_jsondata(SCHEMA)
    asset_template = schema['assets'][0]
    asset_id = get_next_id("asset_id")
    asset_template.update({"asset_id":asset_id}) 

    formdata = {}
    f = request.form
    for key in f.keys():
        for value in f.getlist(key):
            formdata[key] = value.strip() 
    process_id = formdata.get("process_id",None)
    apply_to_aspect("asset", asset_template)
    risk_ids = {'process_id':process_id,'asset_id':asset_id}
    apply_to_risktable(risk_ids)
    return jsonify(asset_template)    



@app.route("/update_process", methods=['POST'])
def update_process():
    formdata = {}
    f = request.form
    new_process_data = {}
    for key in f.keys():
        for value in f.getlist(key):
            new_process_data[key] = value.strip() 
    process_id = new_process_data.get("process_id",None)
    new_process_data.pop("action", None)
    apply_to_aspect("process", new_process_data)
    risk_ids = {'process_id':process_id}
    apply_to_risktable(risk_ids)
    return jsonify(new_process_data)

@app.route("/update_asset", methods=['POST'])
def update_asset():
    #extract form data
    formdata = {}
    f = request.form
    new_asset_data = {}
    for key in f.keys():
        for value in f.getlist(key):
            new_asset_data[key] = value.strip() 
    process_id = new_asset_data.get("process_id",None)
    asset_id = new_asset_data.get("asset_id",None)
    #clean data before storage
    new_asset_data.pop("process_id",None)
    new_asset_data.pop("action",None)
    apply_to_aspect("asset", new_asset_data)
    #store id comination
    risk_ids = {'process_id':process_id,'asset_id':asset_id}
    apply_to_risktable(risk_ids)
    return jsonify(new_asset_data)

@app.route("/update_threat", methods=['POST'])
def update_threat():
    formdata = {}
    f = request.form
    output = {}
    for key in f.keys():
        for value in f.getlist(key):
            output[key] = value.strip() 
    return jsonify(output)

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
    app.run(debug=True)
    app.run(host=host)
