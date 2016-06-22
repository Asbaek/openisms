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
DELIVERABLES = "assessments/deliverables.json"
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

def fix_json_dict(reference_dict, target_dict):
    """
    fix_json_dict 
    """
    assert(type(reference_dict) is dict)
    assert(type(target_dict) is dict)
    result = {}
    result.update(target_dict) 
    for rkey, rvalue in reference_dict.iteritems():
        tkey_found=False
        for tkey, tvalue in target_dict.iteritems():
            if (rkey in tkey):
                tkey_found=True
        if not tkey_found:
            result.update({rkey:rvalue})
    return result 

def get_impact_type_list(data):
    """
    get_impact_type_list returns a list of impact types extracted from data.json 'global_impact_scores' list.
    Variable:
    - data strcuture loaded form data.json
    """
    result=[]
    global_impact_details=data.get("global_impact_details",None)
    for global_impact_detail in global_impact_details:
        impact_type = global_impact_detail.get("type",None)
        if impact_type:
            result.append(impact_type)
    assert(type(result) is list)
    return result

def fix_data_structure():
    data   = import_jsondata(DATA)
    schema = import_jsondata(SCHEMA)

    for index, process in enumerate(data['processes']):
        fixed_process = fix_json_dict(schema['processes'][0],process)
        data['processes'][index]=fixed_process
    for index, asset in enumerate(data['assets']):
        fixed_asset = fix_json_dict(schema['assets'][0],asset)
        data['assets'][index]=fixed_asset
    for index, threat in enumerate(data['threats']):
        fixed_threat = fix_json_dict(schema['threats'][0],threat)
        impact_details = threat.get("impact_scores",None)
        impact_types = []
        for impact_detail in impact_details:
            impact_type = impact_detail.get("type",None)
     	    if impact_type:
                impact_types.append(impact_type)
        global_impact_types = get_impact_type_list(data)
        for global_impact_type in global_impact_types:
            if not global_impact_type in impact_types: 
                new_score = {"type":global_impact_type, "score":"0"}
                fixed_threat['impact_scores'].append(new_score)
        data['threats'][index]=fixed_threat
    output = json.dumps(data, indent=4)
    write_file(DATA, output, charset='utf-8')


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


def get_threat_process(threat_id, data):
    assert(type(threat_id) is str)
    process_id = None 
    asset_id = None
    for risk in data['risktable']:
        var_threat_id = risk.get("threat_id", None)
        var_asset_id = risk.get("asset_id",None)
        if var_threat_id and var_asset_id:
            if var_threat_id == threat_id:
                asset_id = var_asset_id
    for risk in data['risktable']:
        var_process_id = risk.get("process_id",None)
        var_asset_id = risk.get("asset_id", None)
        if var_process_id and var_asset_id:
            if var_asset_id == asset_id:
                process_id = var_process_id            
    return process_id

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
            container_name = container.get("container_name", "No name")
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
    risk_score = 0.0
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
    	result = str('{:04.1f}'.format(risk_score))
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
        containers_reported = []
        asset_id = ""
        threat_table_id = threat_dict.get("threat_id",None)
        for risk in data["risktable"]:
            temp_threat_id = risk.get("threat_id", None)
            if temp_threat_id and (temp_threat_id in threat_table_id):
                temp_container_id=risk.get("container_id", None)
                asset_id = risk.get("asset_id", None) or asset_id
                new_data = {}
                new_data["container_controls"]=[]
                temp_control_ids=[]
                if temp_container_id and not (temp_container_id in containers_reported):
                    container_dict ={}
                    container_dict=get_container_dict(str(temp_container_id))
		    new_data.update(container_dict)
		    containers_reported.append(str(temp_container_id))
		    # loop through all risks with temp_container_id  and get container_id
                    for id_dict in data["risktable"]:
                        current_container_id = id_dict.get("container_id", None)
                        if (current_container_id == temp_container_id):
                            current_control_id  =id_dict.get("control_id", None)
                            if current_control_id:
                                control_dict = {}
                                control_dict = get_control_dict(str(current_control_id))
                                new_data["container_controls"].append(control_dict)
                if new_data.get("container_name",None):
                    containers.append(new_data)
    	threat_table[index]["containers"]=containers
        threat_table[index]["asset_id"]=asset_id
        asset_name=""
        asset_owner=""
        for asset in data['assets']:
            var_asset_id = asset.get("asset_id", None)
            if var_asset_id == asset_id:
                asset_name=asset.get("asset_name",None)
                asset_owner=asset.get("asset_owner",None)
        threat_table[index]["asset_name"]=asset_name
        threat_table[index]["asset_owner"]=asset_owner
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
    assert(len(risk_dict)<4) # Max. 3 keys
    data=import_jsondata(DATA)
    risk_dict_already_exists=False
    for var_dict in data["risktable"]:
        if cmp(var_dict, risk_dict)==0:
            risk_dict_already_exists=True
    if risk_dict_already_exists:
        pass
    else:   
        data["risktable"].append(risk_dict)
        output = json.dumps(data, indent=4)
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
    elif aspect in "threat":
        threat_id_new = new_aspect_detail.get("threat_id", None)
        if threat_id_new:
            threat_found=False
            for index, threat in enumerate(data['threats']):
	        threat_id_existing = threat.get("threat_id", None)
                if threat_id_new in threat_id_existing:
                    threat_found=True
                    threat_index=index
            if threat_found:
	        new_impact_scores = new_aspect_detail.get("impact_scores",None)
                if new_impact_scores:
                     threat_details=data['threats'][threat_index]['impact_scores']
                     for index, old_impact_score in enumerate(threat_details):
                         for new_impact_score in new_impact_scores:
                             new_impact_type = new_impact_score.get("type",None)
			     old_impact_type = old_impact_score.get('type',None)
                             if new_impact_type in old_impact_type:
                                  data['threats'][threat_index]['impact_scores'][index].update(new_impact_score)
                data["threats"][threat_index].update(new_aspect_detail)
            if not threat_found:
                data["threats"].append(new_aspect_detail)
        else:
            return False
    elif aspect in "container":
        container_id_new = new_aspect_detail.get("container_id", None)
        if container_id_new:
            container_found=False
            for index, container in enumerate(data['containers']):
	        container_id_existing = container.get("container_id", None)
                if container_id_new in container_id_existing:
                    data["containers"][index].update(new_aspect_detail)
                    container_found = True
            if not container_found:
                data["containers"].append(new_aspect_detail)
        else:
            return False
    outputdata = json.dumps(data, indent=4)
    write_file(DATA, outputdata, charset='utf-8')
    return True

    
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

@app.route("/alignment", methods=['GET'])
def alignment():
    data=import_jsondata(DATA)
    global_impact_details=data["global_impact_details"]
    return render_template("alignment.html", global_impact_details=global_impact_details)

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
    action=request.args['action']
    process_ids = []
    process_ids.append(request.args['process_id'])
    process_table = get_table(process_ids)
    if action=="Delete":
        process_id = str(process_ids[0])
        if process_id:
            depending_ids=delete_cascading_ids(process_id)
            for aspect_id in depending_ids:
                delete_aspect(str(aspect_id))
        return assessments()
    if action=="Analyse":
        asset_ids = get_process_assets(process_ids)
        asset_table = get_table(asset_ids)
        data = import_jsondata(DATA)
        rxo_values = data["rxo_values"]
        global_impact_details = data["global_impact_details"]

        threat_ids = get_asset_threats(asset_ids)
        threat_table = get_table(threat_ids)
        threat_table = inject_containers_and_controls(threat_table)
        threat_table = inject_risk_scores(threat_table)
        threat_library = data.get("threat_library")
        control_library = import_jsondata(CONTROL_LIBRARY)
        container_library = data.get("container_library", None)
        return render_template('analyse_process.html', process_table=process_table,
						       asset_table=asset_table,
						       rxo_values=rxo_values,
 						       threat_library = threat_library,
						       global_impact_details=global_impact_details,
						       threat_table=threat_table,
						       control_library=control_library,
						       container_library=container_library)
    if action=="Report":
        asset_ids = get_process_assets(process_ids)
        asset_table = get_table(asset_ids)
        data = import_jsondata(DATA)
        rxo_values = data["rxo_values"]
        global_impact_details = data["global_impact_details"]

        threat_ids = get_asset_threats(asset_ids)
        threat_table = get_table(threat_ids)
        threat_table = inject_containers_and_controls(threat_table)
        threat_table = inject_risk_scores(threat_table)
        threat_library = data.get("threat_library")
        control_library = import_jsondata(CONTROL_LIBRARY)
        container_library = data.get("container_library", None)
        return render_template('report_process.html', process_table=process_table,
						       asset_table=asset_table,
						       rxo_values=rxo_values,
 						       threat_library = threat_library,
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
    risktable=data.get("risktable", None)
    if aspect_id_type is "process_id":
        processes=data.get("processes",None)
        process_ids=[]
        for process in processes:
            process_id = process.get("process_id",None)
            if process_id:
                process_ids.append(process_id)
        for risk in risktable:
            process_id = risk.get("process_id",None)
            if process_id:
                process_ids.append(process_id)
        if not process_ids:
            process_ids.append("process000000")
        int_ids = [int(a[7:]) for a in process_ids]
        return "process" + str(max(int_ids)+1).zfill(6)
    if aspect_id_type is "asset_id":
        assets=data.get("assets",None)
        asset_ids = []
        for asset in assets:
            asset_id = asset.get("asset_id", None)
            if asset_id: 
                asset_ids.append(asset_id)    
        for risk in risktable:
            asset_id = risk.get("asset_id", None)
            if asset_id:
                asset_ids.append(asset_id)
        if not asset_ids:
            asset_ids.append("asset000000")
        int_ids = [int(a[5:]) for a in asset_ids]
        return "asset" + str(max(int_ids)+1).zfill(6)   
    elif aspect_id_type is "threat_id":
        threats=data.get("threats",None)
        threat_ids = []
        for threat in threats:
            threat_id = threat.get("threat_id", None)
            if threat_id: 
                threat_ids.append(threat_id)    
        for risk in risktable:
            threat_id = risk.get("threat_id", None)
            if threat_id:
                threat_ids.append(threat_id)
        if not threat_ids:
            threat_ids.append("threat000000")
        int_ids = [int(a[6:]) for a in threat_ids]
        return "threat" + str(max(int_ids)+1).zfill(6)   
    elif aspect_id_type is "container_id":
        containers=data.get("containers",None)
        container_ids = []
        for container in containers:
            container_id = container.get("container_id", None)
            if container_id: 
                container_ids.append(container_id)    
        for risk in risktable:
            container_id = risk.get("container_id", None)
            if container_id:
                container_ids.append(container_id)
        if not container_ids:
            container_ids.append("container000000")
        int_ids = [int(a[9:]) for a in container_ids]
        return "container" + str(max(int_ids)+1).zfill(6)   

@app.route("/add_process", methods=['POST','GET'])
def add_process():
    schema=import_jsondata(SCHEMA)

    process_template = schema['processes'][0]
    process_id = get_next_id("process_id")
    process_template.update({"process_id":process_id})

    apply_to_aspect("process", process_template)
    risk_ids = {'process_id':process_id}
    apply_to_risktable(risk_ids)
    return assessments()    


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
    return redirect(url_for('analyse_process',process_id=process_id,action='Analyse'))

@app.route("/add_threat", methods=['POST'])
def add_threat():
    schema=import_jsondata(SCHEMA)
    threat_template = schema['threats'][0]
    threat_id = get_next_id("threat_id")
    threat_template.update({"threat_id":threat_id}) 

    formdata = {}
    f = request.form
    for key in f.keys():
        for value in f.getlist(key):
            formdata[key] = value.strip() 
    asset_id = formdata.get("asset_id",None)
    process_id = formdata.get("process_id",None)
    threat_template['threat_name'] = formdata.get("threat_name","")

    apply_to_aspect("threat", threat_template)
    risk_ids = {'asset_id':asset_id,'threat_id':threat_id}
    apply_to_risktable(risk_ids)
    return redirect(url_for('analyse_process',process_id=process_id,action='Analyse'))

@app.route("/add_container", methods=['POST'])
def add_container():
    formdata = {}
    f = request.form
    for key in f.keys():
        for value in f.getlist(key):
            formdata[key] = value.strip() 
    threat_id = formdata.get("threat_id",None)
    container_id = get_next_id("container_id")
    process_id = formdata.get("process_id",None)
    formdata.pop("process_id",None)
    schema=import_jsondata(SCHEMA)
    container_template = schema['containers'][0]
    container_template.update(formdata) 
    container_template.update({'container_id':container_id})
    container_name = container_template.get("container_name",None)
    if container_name:
        apply_to_aspect("container", container_template)
        risk_ids = {'threat_id':threat_id,'container_id':container_id}
        apply_to_risktable(risk_ids)
        return redirect(url_for('analyse_process',process_id=process_id,action='Analyse'))
    else:
        return "Select a name"

@app.route("/add_control", methods=['POST'])
def add_control():
    formdata = {}
    f = request.form
    for key in f.keys():
        for value in f.getlist(key):
            formdata[key] = value.strip() 
    formdata.pop("action",None)
    process_id = formdata.get("process_id",None)
    formdata.pop("process_id",None)
    apply_to_risktable(formdata)
    return redirect(url_for('analyse_process',process_id=process_id,action='Analyse'))

@app.route("/update_process", methods=['POST'])
def update_process():
    formdata = {}
    f = request.form
    new_process_data = {}
    for key in f.keys():
        for value in f.getlist(key):
            new_process_data[key] = value.strip() 
    process_id = new_process_data.get("process_id",None)
    action = new_process_data.get("action",None)
    new_process_data.pop("action", None)
    apply_to_aspect("process", new_process_data)
    risk_ids = {'process_id':process_id}
    apply_to_risktable(risk_ids)
    return redirect(url_for('analyse_process',process_id=process_id,action='Analyse'))

@app.route("/update_asset", methods=['POST'])
def update_asset():
    #extract form data
    formdata = {}
    f = request.form
    new_asset_data = {}
    for key in f.keys():
        for value in f.getlist(key):
            new_asset_data[key] = value.strip() 
    action = new_asset_data.get("action",None)
    process_id = new_asset_data.get("process_id",None)
    asset_id = new_asset_data.get("asset_id",None)
    if action == "Delete asset":
        if asset_id:
            depending_ids=[]
            depending_ids=delete_cascading_ids(str(asset_id))
            for aspect_id in depending_ids:
                delete_aspect(str(aspect_id))
    if action == "Apply asset changes":
        #clean data before storage
        new_asset_data.pop("process_id",None)
        new_asset_data.pop("action",None)
        apply_to_aspect("asset", new_asset_data)
        #store id comination
        risk_ids = {'process_id':process_id,'asset_id':asset_id}
        apply_to_risktable(risk_ids)
    return redirect(url_for('analyse_process',process_id=process_id,action='Analyse'))

@app.route("/update_threat", methods=['POST'])
def update_threat():
    # Get formdata
    formdata = {}
    f = request.form
    for key in f.keys():
        for value in f.getlist(key):
            formdata[key] = value.strip() 
    action = formdata.get('action',None)
    # Update risktable
    process_id = formdata.get('process_id',None)
    threat_id = formdata.get('threat_id',None)
    asset_id = formdata.get("asset_id",None)
    if action == "Delete threat":
        if threat_id:
            depending_ids=[]
            depending_ids=delete_cascading_ids(str(threat_id))
            for aspect_id in depending_ids:
                delete_aspect(str(aspect_id))
    if action == "Apply threat changes":
        risk_ids = {"threat_id":threat_id, "asset_id":asset_id}
        apply_to_risktable(risk_ids)
        # Clean formdata
        formdata.pop("action",None)
        formdata.pop("asset_id",None)
        # Get list of impact_score_types from data.json  
        impact_score_types=[]
        data=import_jsondata(DATA)
        global_impact_details=data.get("global_impact_details",None)
        for global_impact_detail in global_impact_details:
            impact_score_types.append(global_impact_detail.get("type",None))
        # Create datastructure for impact_scores and update formdata.
        impact_scores=[]
        for impact_score_type in impact_score_types:
            formdata_variable = formdata.get(impact_score_type, None)
            if formdata_variable in ["0","1","2","3"]:
                impact_score={}
                impact_score['score']=str(formdata_variable)
                impact_score['type']=impact_score_type
                impact_scores.append(impact_score)
                formdata.pop(impact_score_type,None)
        formdata['impact_scores']=impact_scores        
        # Store data
        apply_to_aspect("threat", formdata)
    return redirect(url_for('analyse_process',process_id=process_id,action='Analyse'))

def delete_id_set(id_1, id_2):
    """
    delete_id deletes all lines from risktable in data.json, containing both ids.
    Arguments:
    - id_1: first id, e.g. "container_000001"
    - id_2: second id, e.g. "control000001"
    """
    assert(type(id_1) is str)
    assert(type(id_2) is str)
    data=import_jsondata(DATA)
    old_risktable = data.get("risktable",None)
    new_risktable = []
    for risk in old_risktable:
        id_1_found=False
        id_2_found=False
        for key,value in risk.iteritems():
            if value==id_1: id_1_found=True
            if value==id_2: id_2_found=True
        if not (id_1_found and id_2_found):
            new_risktable.append(risk)
    data['risktable']=new_risktable
    output = json.dumps(data, indent=4)
    write_file(DATA, output, charset='utf-8')
    return True

def delete_cascading_ids(aspect_id):
    assert(type(aspect_id) is str)
    prefix = aspect_id[0:5]
    assert(prefix in ["proce","asset","threa"])
    data=import_jsondata(DATA)
    old_risktable = data.get("risktable",None)
    id_order = ["process_id","asset_id","threat_id"]
    remove_list=[]
    remove_list.append(aspect_id)
    for risk in old_risktable:
        remove_risk = False
        for id_type in id_order:
            for id_key, id_value in risk.iteritems():
                if id_type == id_key:
                    if id_value in remove_list:
                        remove_risk=True
                        break
            if remove_risk:
                for id_key, id_value in risk.iteritems():
                    if id_type==id_key:
                        remove_list.append(id_value)
    new_risktable = []
    for risk in old_risktable:
        keep_risk=True
        for id_key, id_value in risk.iteritems():
            if id_value in remove_list:
                keep_risk=False
        if keep_risk:
            new_risktable.append(risk)
    data['risktable']=new_risktable
    output = json.dumps(data, indent=4)
    write_file(DATA, output, charset='utf-8')
    return list(set(remove_list))

def delete_aspect(aspect_id):
    assert(type(aspect_id) is str)
    ref = ""
    key = ""
    if aspect_id[0:7]=="process":
        ref="processes"
        key="process_id"
    elif aspect_id[0:5]=="asset":
        ref="assets"
        key="asset_id"
    elif aspect_id[0:6]=="threat":
        ref="threats"
        key="threat_id"
    if ref:
        data=import_jsondata(DATA)
        for index,aspect in enumerate(data[ref]):
            row_id = aspect.get(key,None)
            if row_id == aspect_id:
                data[ref].pop(index)
                break  
        output = json.dumps(data, indent=4)
        write_file(DATA, output, charset='utf-8')
    return True

@app.route("/delete_control",methods=['POST','GET'])
def delete_control():
    formdata = {}
    f = request.form
    for key in f.keys():
        for value in f.getlist(key):
            formdata[key] = value.strip() 
    process_id = formdata.get('process_id',None)
    control_id = formdata.get("control_id",None)
    container_id = formdata.get("container_id",None)
    if control_id and container_id:
        delete_id_set(str(control_id),str(container_id))
    return redirect(url_for('analyse_process',process_id=process_id,action='Analyse'))

@app.route("/delete_container",methods=['POST','GET'])
def delete_container():
    formdata = {}
    f = request.form
    for key in f.keys():
        for value in f.getlist(key):
            formdata[key] = value.strip() 
    process_id = formdata.get('process_id',None)
    threat_id = formdata.get("threat_id",None)
    container_id = formdata.get("container_id",None)
    if container_id and threat_id:
        delete_id_set(str(threat_id),str(container_id))
    return redirect(url_for('analyse_process',process_id=process_id,action='Analyse'))


@app.route("/show_json", methods=['GET'])
def show_json():
    data = import_jsondata(DATA)
    return jsonify(data)

@app.route("/reports", methods=['GET'])
def reports():
    return render_template("reports.html") 

@app.route("/risk_acceptance", methods=['GET'])
def risk_acceptance():
    return render_template("risk_acceptance.html") 

@app.route("/controls_soa", methods=['GET'])
def controls_soa():
    data = import_jsondata(DATA)
    control_library=import_jsondata(CONTROL_LIBRARY)
    control_table = control_library['control_library']
    for index,control in enumerate(control_table):
        control_id = control.get("control_id",None)
        control_counter=0
        control_containers=[]
        if control_id:
            #find control_containers+control_counter
            for risk in data['risktable']:
                risktable_control_id=risk.get("control_id",None)
                if control_id==risktable_control_id:
                    control_counter+=1
                    container_id = risk.get("container_id",None) 
                    if container_id:
                        container_dict=get_container_dict(str(container_id))
                        container_name=container_dict.get("container_name", "None")
                        control_containers.append(container_name)
            #find control_assets
            related_ids = []
            for risk in data['risktable']:
                risktable_control_id = risk.get("control_id", None)
                risktable_container_id = risk.get("container_id", None)
                if control_id == risktable_control_id:
                    if risktable_control_id and risktable_container_id:
                        related_ids.append(risktable_container_id)
            for risk in data['risktable']:
                risktable_container_id = risk.get("container_id", None)
                risktable_threat_id = risk.get("threat_id",None)
                if risktable_container_id in related_ids:
                    related_ids.append(risktable_threat_id)
            control_asset_ids =[]
            for risk in data['risktable']:
                risktable_threat_id = risk.get("threat_id",None)
                risktable_asset_id = risk.get("asset_id", None)
                if risktable_threat_id in related_ids:
                    control_asset_ids.append(risktable_asset_id)
            control_assets=[]
            for asset in data['assets']:
                asset_id=asset.get("asset_id",None)
                if asset_id in control_asset_ids:
                    asset_name = asset.get("asset_name",None)
                    control_assets.append(asset_name)
        control_table[index]["control_containers"]=set(control_containers)
        control_table[index]["control_assets"]=set(control_assets)  
        control_table[index]["control_count"]=control_counter   
        
        deliverables = import_jsondata(DELIVERABLES)
        deliverable_names=[]
        for deliverable in deliverables["deliverables"]:
            deliverable_control_references = deliverable.get("controls",None)
            if deliverable_control_references:
                for dcontrol_id in deliverable_control_references:
                    if dcontrol_id == control_id:
                        deliverable_name = deliverable.get("name", None)
                        if deliverable_name:
                            deliverable_names.append(deliverable_name)
        control_table[index]["deliverable_names"]=set(deliverable_names)      
    return render_template("controls_soa.html",control_table=control_table) 

@app.route("/deliverables", methods=['GET'])
def deliverables():
    data = import_jsondata(DATA)
    deliverables_import = import_jsondata(DELIVERABLES)
    deliverables_table = deliverables_import['deliverables']
    # Count the number of times the deliverable was relevant in the SOA
    control_library=import_jsondata(CONTROL_LIBRARY)
    control_table = control_library['control_library']
    for index,control in enumerate(control_table):
        control_id = control.get("control_id",None)
        control_counter=0
        if control_id:
            for risk in data['risktable']:
                risktable_control_id=risk.get("control_id",None)
                if control_id==risktable_control_id:
                    control_counter+=1
            index_to_change = None
            for index2,deliverable in enumerate(deliverables_table):
                deliverable_control_references = deliverable.get("controls",None)
                for dcontrol_id in deliverable_control_references:
                    if dcontrol_id == control_id:
                        index_to_change = index2
            if index_to_change: 
                deliverables_table[index_to_change]["count"]=control_counter 
    deliverable_maturity = deliverables_import.get("deliverable_maturity",None)
    return render_template("deliverables.html", deliverables_table=deliverables_table, deliverable_maturity=deliverable_maturity)

@app.route("/update_deliverables", methods=['POST'])
def update_deliverables():
    deliverables_import = import_jsondata(DELIVERABLES)
    formdata = {}
    f = request.form
    for key in f.keys():
        for value in f.getlist(key):
            formdata[key] = value.strip() 
    maturity_current = formdata.get('maturity_current',None)
    maturity_planned = formdata.get('maturity_planned',None)
    name = formdata.get('name', None)
    if name:
        delivery_index = None
        for index, deliverable in enumerate(deliverables_import["deliverables"]):
            var_name = deliverable.get("name", None)
            if var_name == name:
                delivery_index = index
	        break
        if delivery_index != None:
            deliverables_import["deliverables"][delivery_index].update(formdata)   
    output = json.dumps(deliverables_import, indent=4)
    write_file(DELIVERABLES, output, charset='utf-8')
    return deliverables()    

@app.route("/risk_report", methods=['POST','GET'])
def risk_report():
    data = import_jsondata(DATA)
    threat_ids=[]
    for risk in data['risktable']:
        threat_id = risk.get('threat_id',None) 
        if threat_id:
            threat_ids.append(threat_id)
    threat_table = get_table(threat_ids)
    threat_table = inject_containers_and_controls(threat_table)
    threat_table = inject_risk_scores(threat_table)
    for index,threat in enumerate(threat_table):
        process_name = ""
        threat_id = threat.get("threat_id", None)
        process_id = get_threat_process(str(threat_id), data)   
        for process in data['processes']:
            var_process_id = process.get("process_id", None)
            if var_process_id:
                if process_id == var_process_id:
                    process_name = process.get("process_name", "")
        threat_table[index]['process_name']=process_name
    return render_template("risk_report.html",threat_table=threat_table) 

#############
# Main code #
#############
if __name__ == '__main__':
    fix_data_structure()
    # Try and get HOSTNAME env variable, defaults to 127.0.0.1
    host = os.getenv('HOSTNAME', '127.0.0.1')
    app.run(host=host)
    # Will debug if DEBUG is set to anything, otherwise false
    debug = not not (os.getenv('DEBUG', False))
    app.run(host=host,debug=debug)
