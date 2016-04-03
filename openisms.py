#/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import Flask, request, render_template, jsonify
import json
import codecs


DATAFILE = "assessments/data.json"
SCHEMADATA = "assessments/schema.json"

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
    Populates and returns the index.html page to browser
    Arguments:
    	None
    """
    query = {'action': 'load_list', 'aspect': 'process',
             'processid': None, 'aspectid': None, 'inputdata': None}
    process_list = storage_processor(query)
    return render_template('index.html', process_list=process_list)


@app.route("/load_process_form", methods=['GET'])
def change_service(datafile=DATAFILE):
    """
    Populates and returns an editable view of all threat information
    Arguments
    	datafile: String, such as "assessments/data.json"
    """
    data = import_jsondata(datafile)
    # collect data
    process_id = request.args.get('process_id')
    action = request.args.get("action")
    if action == "Delete process":
        query = {'action': 'delete', 'aspect': 'process',
                 'processid': process_id, 'aspectid': None, 'inputdata': None}
        process_data = storage_processor(query)
        return "Process " + \
            str(process_id) + \
            " was deleted"
    if action == "New process":
        data = import_jsondata(datafile)
        schema = import_jsondata(SCHEMADATA)
        input_data = schema['processes'][0]
        process_ids = []
        for process in data['processes']:
            try:
                process_ids.append(int(process.get('_id', '10000')))
            except ValueError as ve:
                return "Error occured in add function: " + str(ve)
        input_data['_id'] = max(process_ids) + 1
        data["processes"].append(input_data)
        output = json.dumps(data, indent=4)
        write_file(datafile, output)
        return "New process added."
    if action == "Update process":
        try:
            query = {'action': 'load_item', 'aspect': 'process',
                     'processid': process_id, 'aspectid': None, 'inputdata': None}
            process_data = storage_processor(query)

            query = {'action': 'load_list', 'aspect': 'containerlib'}
            containerlib = storage_processor(query)

            query = {'action': 'load_list', 'aspect': 'controllib'}
            controllib = storage_processor(query)

            query = {'action': 'load_list', 'aspect': 'threatlib'}
            threatlib = storage_processor(query)

            query = {'action': 'load_item', 'aspect': 'impact_description'}
            impact_description = storage_processor(query)

        except Exception as e:
            print "Error code recieved: " + str(e)
        return render_template('edit_process_form.html', process_data=process_data, process_id=process_id,
                               containerlib=containerlib, controllib=controllib, threatlib=threatlib,
			       impact_description=impact_description)


def storage_processor(query, filename=DATAFILE):
    """
    """
    # load all data from file
    try:
        f = codecs.open(filename, mode='r', encoding='utf-8')
        data = json.load(f)
        f.close()

        # extract standard variables
        aspect = query.get('aspect', 'error')
        inputdata = query.get('inputdata', 'error')
        processid = query.get('processid', 'error')
        aspectid = query.get('aspectid', 'error')

        # Calculate
        process_index = None
        if processid not in ['error', None]:
            for index, element in enumerate(data['processes']):
                if str(element['_id']) == str(processid):
                    process_index = index

        aspect_index = None
        if aspect in ['threats', 'assets']:
            for index, element in enumerate(
                    data['processes'][process_index][aspect]):
                if str(element['_id']) == str(aspectid):
                    aspect_index = index
        elif aspect in ['containerlib']:
            for index, element in enumerate(data['containerlib']):
                if str(element['_id']) == str(aspectid):
                    aspect_index = index
        elif aspect in ['threat_control', 'threat_container', 'threat_details']:
            for index, element in enumerate(
                    data['processes'][process_index]['threats']):
                if str(element['_id']) == str(aspectid):
                    aspect_index = index

        DEBUG = False
        if DEBUG:
            print "storage_processor DEBUG message"
            print "-------------------------------"
            print "aspect id: 		" + str(aspectid)
            print "aspect: 		" + str(aspect)
            print "aspect type: 	" + str(type(aspect))
            print "aspect_index: 	" + str(aspect_index)
            print "process_index: 	" + str(process_index)
            print "inputdata: 		" + str(inputdata)
            print "query 		" + str(query)
            print "-------------------------------"

        # Call relevant functions
        action_mapper = {"add": add, "load_list": load_list, "delete": delete,
                         "load_item": load_item, "report_all": report_all, "edit": edit}
        result = action_mapper[query['action']](
            query, process_index, aspect_index, data, filename, inputdata)
        return result
    except Exception as e:
        print "Error in function storage_processor: " + str(e)
        return False


def delete(query, process_index, aspect_index, data, filename, inputdata):
    try:
        aspect = query.get('aspect', 'no_value')
        if aspect == "process":
            data['processes'].pop(process_index)
        if aspect == "threat_control":
            inputdata = query.get('inputdata', 'no_value')
            container_id = inputdata.get('container_id', 'no_value')
            control_id = inputdata.get('control_id', 'no_value')
            for index, container in enumerate(data['processes'][process_index][
                                              'threats'][aspect_index]['containers']):
                if container['reference'] == container_id:
                    data['processes'][process_index]['threats'][aspect_index][
                        'containers'][index]['control_ids'].remove(control_id)
        if aspect == "threat_container":
            inputdata = query.get('inputdata', 'no_value')
            container_id = inputdata.get('container_id', 'no_value')
            for index, container in enumerate(data['processes'][process_index][
                                              'threats'][aspect_index]['containers']):
                if container['reference'] == container_id:
                    data['processes'][process_index]['threats'][
                        aspect_index]['containers'].pop(index)

        output = json.dumps(data, indent=4)
        write_file(filename, output)
        return aspect + " deleted"
    except Exception as e:
        return "Error encountered in the delete function: " + str(e)


def report_all(query, process_index, aspect_index, data, filename, inputdata):
    """
    """
    try:
        aspect = query.get('aspect', '')
        result = []
        if aspect == "threat":
            for process in data['processes']:
                for threat in process['threats']:
                    row = {}
                    row['process_name'] = process['name']
                    for threat_lib_item in data['threatlib']:
                        if threat_lib_item['_id'] == threat[
                                'threat_lib_reference']:
                            row['threat_name'] = threat_lib_item['name']
                            row['threat_description'] = threat_lib_item[
                                'description']
                    affected_assets_list = []
                    for asset_id in threat['asset_ids']:
                        for asset in process['assets']:
                            if str(asset['_id']) == str(asset_id):
                                affected_assets_list.append(
                                    str(asset['name']).strip())
                    row['affected_assets'] = affected_assets_list
                    row['score_impact'] = threat['score_impact']
                    row['score_probability'] = threat['score_probability']
                    row['score_risk'] = threat['score_risk']
                    row['is_controlled'] = threat['is_controlled']
                    result.append(row)
        if aspect == "control":
            for process in data['processes']:
                # Find all controlids in all threats
                controlids = []
                for threat in process['threats']:
                    for container in threat['containers']:
                        controlids.extend(container['control_ids'])
                # Walk through all controls
                for control in data['controllib']:
                    row = {}
                    if control['_id'] in set(controlids):
                        row['process_name'] = process['name']
                        row['_id'] = str(control['_id'])
                        row['name'] = str(control['name'])
                        row['description'] = str(control['description'])
                        result.append(row)
        if aspect == "container":
            for process in data['processes']:
                for containeritem in data['containerlib']:
                    container_item_found = False
                    container_threat_list = []
                    container_asset_ids = []
                    container_control_ids = []
                    for threat in process['threats']:
                        for container in threat['containers']:
                            if container['reference'] == containeritem['_id']:
                                container_item_found = True
                                container_asset_ids.extend(threat['asset_ids'])
                                container_threat_list.append(
                                    threat['threat_lib_reference'])
                                container_control_ids.extend(
                                    container['control_ids'])
                    if container_item_found:
                        row = {}
                        row['process_name'] = process['name']
                        row['name'] = containeritem['name']
                        row['description'] = containeritem['description']

                        container_asset_names = []
                        for asset in process['assets']:
                            if asset['_id'] in container_asset_ids:
                                container_asset_names.append(
                                    asset['name'])
                        row['assets'] = container_asset_names

                        container_threat_names = []
                        for threatitem in data['threatlib']:
                            if threatitem['_id'] in container_threat_list:
                                container_threat_names.append(
                                    threatitem['name'])
                        row['threats'] = container_threat_names

                        container_control_names = []
                        for controlitem in data['controllib']:
                            if controlitem['_id'] in container_control_ids:
                                container_control_names.append(
                                    controlitem['_id'] + " " + controlitem['name'])
                        row['controls'] = container_control_names
                        result.append(row)
    except Exception as e:
        return "Error occured in function report_all: " + str(e)
    return result


def add(query, process_index, aspect_index, data, filename, inputdata):
    """
    """
    try:
        # Idea for improvement:
        # Add way to find next free ID in this context
        # add templates in this context
        aspect = query['aspect']
        process_id = query.get('processid', '')
        aspect_id = query.get('aspectid', '')

        schema = import_jsondata(SCHEMADATA)

        # Append data
        if aspect == "process":
            data['processes'].append(input_data)
        elif aspect == "assets":
            asset_ids = []
            for asset in data['processes'][process_index]['assets']:
                try:
                    asset_ids.append(int(asset.get('_id', '20000')))
                except ValueError as ve:
                    return "Error occured in add function: " + str(ve)
            input_data = schema["processes"][0]['assets'][0]
            input_data['_id'] = max(asset_ids) + 1
            data["processes"][process_index]['assets'].append(input_data)
        elif aspect == "threat":
            input_data = schema['processes'][0]['threats'][0]
            threat_ids = []
            for threat in data['processes'][process_index]['threats']:
                try:
                    threat_ids.append(int(threat.get('_id', '40000')))
                except ValueError as ve:
                    return "Error occured in add function: " + str(ve)
            input_data['_id'] = max(threat_ids) + 1
            data["processes"][process_index]['threats'].append(input_data)
        elif aspect == "threat_control":
            q_input_data = query.get('inputdata', '')
            control_id = q_input_data.get('control_id', '')
            containerlib_id = q_input_data.get('containerlib_id', '')
            for index, element in enumerate(data["processes"][process_index][
                                            'threats'][aspect_index]['containers']):
                if containerlib_id == element.get('reference', ''):
                    data["processes"][process_index]['threats'][aspect_index][
                        'containers'][index]['control_ids'].append(control_id)
        elif aspect == "threat_container":
            container_id = query.get('inputdata', '')
            newcontainer = {'reference': str(container_id), 'control_ids': []}
            data["processes"][process_index]['threats'][
                aspect_index]['containers'].append(newcontainer)
        output = json.dumps(data, indent=4)
        write_file(filename, output)
        return aspect + " added."
    except Exception as e:
        return "Error encountered in the add function " + str(e)


def load_item(query, process_index, aspect_index, data, filename, inputdata):
    """
    """
    try:
        aspect = query['aspect']
        load_item = {}
        if aspect == "process":
            load_item = data['processes'][process_index]
        elif aspect == "asset":
            load_item = data['processes'][
                process_index]['assets'][aspect_index]
        elif aspect == "threat":
            load_item = data['processes'][
                process_index]['threats'][aspect_index]
        elif aspect == "scoreweights":
            load_item = data['scoreweights']
        elif aspect == "impact_description":
            load_item = data['impact_description']
    except Exception as e:
        load_item = "Error in function load_item: " + str(e)
    return load_item


def load_list(query, process_index, aspect_index, data, filename, inputdata):
    """
    """
    try:
        aspect = query.get('aspect', '')
        input_data = query.get('inputdata', '')
        load_list = []
        if aspect == "process":
            for process in data['processes']:
                load_list.append(
                    {"_id": process['_id'], "name": process['name']})
        elif aspect == "asset":
            for asset in data['processes'][int(process_index)]['assets'][
                    int(aspect_index)]:
                load_list.append(asset['name'])
        elif aspect == "threat":
            load_list = data['processes'][int(process_index)].get(
                'threats', 'error running load_list on threat')
        elif aspect == "containerlib":
            load_list = data.get(
                'containerlib', 'error running load_list on containerlib')
        elif aspect == "controllib":
            load_list = data.get(
                'controllib', 'error running load_list on controllib')
        elif aspect == "threatlib":
            load_list = data.get(
                'threatlib', 'error running load_list on threatlib')
        elif aspect == "documents":
            load_list = data.get('documents', 'error loading documents list')
    except:
        load_list = ['load_list encountered an error']
    return load_list


def edit(query, process_index, aspect_index, data, filename, inputdata):
    """
    """
    try:
        aspect = query.get('aspect', '')
        inputdata = query.get('inputdata', '')

        if aspect == "containerlib":
            data['containerlib'][aspect_index] = inputdata
        elif aspect == "threat_details":
            data['processes'][process_index]['threats'][
                aspect_index].update(inputdata)
        elif aspect == "process":
            data['processes'][process_index].update(inputdata)
        elif aspect == "assets":
            data['processes'][process_index]['assets'][
                aspect_index].update(inputdata)

        outputdata = json.dumps(data, indent=4)
        write_file(filename, outputdata)
        return True
    except Exception as e:
        print 'edit function returned error: ' + str(e)
        return False


@app.route("/prepare_containerlib_query", methods=['POST'])
def prepare_containerlib_query():
    try:
        formdata = {}
        f = request.form
        output = {}
        for key in f.keys():
            for value in f.getlist(key):
                if key != "action":
                    output[key] = value.strip()
        query = {'action': 'edit', 'aspect': 'containerlib', 'processid': output[
            'process_id'], 'aspectid': output['_id'], 'inputdata': output}
        result = storage_processor(query)
    except Exception as e:
        print "Error occured in prepare_containerlib_query: " + str(e)
    return "Data updated"


@app.route("/prepare_process_query", methods=['POST'])
def prepare_process_query():
    try:
        formdata = {}
        f = request.form
        output = {}
        for key in f.keys():
            for value in f.getlist(key):
                output[key] = value.strip()
        action = output.get('action', 'error')
        output.pop("action", None)
        if action == "Apply process changes":
            process_id = f.get('process_id', '')
            threat_id = f.get('threat_id', '')
            query = {'action': 'edit', 'aspect': 'process',
                     'processid': process_id, 'aspectid': threat_id, 'inputdata': output}
            result = storage_processor(query)
            return "Process changes added"
    except Exception as e:
        return "Error occured in prepare_process_query: " + str(e)


@app.route("/prepare_threat_query", methods=['POST'])
def prepare_threat_query():
    try:
        formdata = {}
        f = request.form
        output = {}
        for key in f.keys():
            for value in f.getlist(key):
                output[key] = value.strip()
        action = output.get('action', 'error')
        output.pop('action', None)
        if action == "Change affected asset ids":
            process_id = f.get('process_id', '')
            threat_id = f.get('threat_id', '')
            asset_ids = request.form.getlist('asset_ids')
            asset_ids = map(int, asset_ids)
            inputdata = {"asset_ids": asset_ids}
            query = {'action': 'edit', 'aspect': 'threat_details',
                     'processid': process_id, 'aspectid': threat_id, 'inputdata': inputdata}
        elif action == "Change threat scores":
            process_id = f.get('process_id', '')
            threat_id = f.get('threat_id', '')
            score_financial = int(f.get('score_financial', 0))
            score_legal = int(f.get('score_legal', 0))
            score_operational = int(f.get('score_operational', 0))
            score_other = int(f.get('score_other', 0))
            score_reputation = int(f.get('score_reputation', 0))
            score_safety = int(f.get('score_safety', 0))
            score_probability = int(f.get('score_probability', 0))
            query = {'action': 'load_item', 'aspect': 'scoreweights',
                     'processid': None, 'aspectid': None, 'inputdata': None}
            scoreweights = storage_processor(query)
            # Calculate score_risk (0-10)
            score_impact = scoreweights['score_financial'] * score_financial + \
                scoreweights['score_legal'] * score_legal + \
                scoreweights['score_operational'] * score_operational + \
                scoreweights['score_other'] * score_other + \
                scoreweights['score_reputation'] * score_reputation +\
                scoreweights['score_safety'] * score_safety
            # score_impact is in range 15-60
            # score_probability is in range 1-4
            # these two multiplied is in range risk=15-240
            # We want risk to be in range 0-10, so we transform risk to
            # (risk-15)*2/9.
            score_risk = float(
                "{0:.2f}".format(
                    (float(
                        score_impact *
                        score_probability) -
                        15.0) *
                    2.0 /
                    45.0))
            # Store data
            inputdata = {"score_financial": score_financial,
                         "score_legal": score_legal,
                         "score_operational": score_operational,
                         "score_other": score_other,
                         "score_reputation": score_reputation,
                         "score_safety": score_safety,
                         "score_probability": score_probability,
                         "score_impact": score_impact,
                         "score_risk": score_risk}
            query = {'action': 'edit', 'aspect': 'threat_details',
                     'processid': process_id, 'aspectid': threat_id, 'inputdata': inputdata}
        elif action == "Apply decision changes":
            process_id = f.get('process_id', '')
            threat_id = f.get('threat_id', '')
            output.pop('process_id', None)
            output.pop('threat_id', None)
            inputdata = output
            query = {'action': 'edit', 'aspect': 'threat_details',
                     'processid': process_id, 'aspectid': threat_id, 'inputdata': inputdata}
        elif action == "Add threat":
            process_id = f.get('process_id', '')
            query = {'action': 'add', 'aspect': 'threat',
                     'processid': process_id}
        elif action == "Change threat template":
            process_id = f.get('process_id', '')
            threat_id = f.get('_id', '')
            threat_lib_reference = f.get('threat_lib_reference', '')
            inputdata = {"threat_lib_reference": threat_lib_reference}
            query = {'action': 'edit', 'aspect': 'threat_details',
                     'processid': process_id, 'aspectid': threat_id, "inputdata": inputdata}
        elif action == "Add container":
            threat_id = f.get('threat_id', '')
            process_id = f.get('process_id', '')
            container_id = f.get('container_id', '')
            query = {'action': 'add', 'aspect': 'threat_container',
                     'processid': process_id, 'aspectid': threat_id, 'inputdata': container_id}
        elif action == "Add control":
            threat_id = f.get('threat_id', '')
            containerlib_id = f.get('containerlib_id', '')
            process_id = f.get('process_id')
            control_id = f.get('control_id')
            inputdata = {
                'control_id': control_id,
                'containerlib_id': containerlib_id}
            query = {'action': 'add', 'aspect': 'threat_control',
                     'processid': process_id, 'aspectid': threat_id, 'inputdata': inputdata}
        elif action == "Delete container":
            process_id = f.get('process_id', 'no_value')
            threat_id = f.get('threat_id', 'no_value')
            container_id = f.get('container_id', 'no_value')
            inputdata = {"container_id": container_id}
            query = {'action': 'delete', 'aspect': 'threat_container',
                     'processid': process_id, 'aspectid': threat_id, 'inputdata': inputdata}
        elif action == "Delete control":
            process_id = f.get('process_id', 'no_value')
            threat_id = f.get('threat_id', 'no_value')
            container_id = f.get('container_id', 'no_value')
            control_id = f.get('control_id', 'no_value')
            inputdata = {
                "container_id": container_id,
                "control_id": control_id}
            query = {'action': 'delete', 'aspect': 'threat_control',
                     'processid': process_id, 'aspectid': threat_id, 'inputdata': inputdata}
        result = storage_processor(query)
        return "Threat detials saved"
    except Exception as e:
        return "Error occured in prepare_threat_query: " + str(e)


@app.route("/prepare_asset_query", methods=['POST'])
def load_asset_form():
    try:
        formdata = {}
        f = request.form
        output = {}
        for key in f.keys():
            for value in f.getlist(key):
                output[key] = value.strip()
        action = f.get('action', 'no_value')
        output.pop('action', None)
        if action == "Apply asset changes":
            process_id = f.get('process_id', 'no_value')
            asset_id = f.get('asset_id', 'no_value')
            output.pop('process_id', None)
            output.pop('asset_id', None)
            output['criticality_c'] = f.get('criticality_c', 'False')
            output['criticality_i'] = f.get('criticality_i', 'False')
            output['criticality_a'] = f.get('criticality_a', 'False')

            inputdata = output
            query = {'action': 'edit', 'aspect': 'assets',
                     'processid': process_id, 'aspectid': asset_id, 'inputdata': inputdata}
            result = storage_processor(query)
            return "Asset changes saved"
        if action == "Add asset":
            process_id = f.get('process_id', 'no_value')
            query = {'action': 'add', 'aspect': 'assets',
                     'processid': process_id}
            result = storage_processor(query)
            return "Asset added"
    except Exception as e:
        return "Error occured in prepare_asset_query " + str(e)


@app.route("/show_json", methods=['GET'])
def show_json():
    data = import_jsondata(DATAFILE)
    return jsonify(data)

@app.route("/alignment", methods=['GET'])
def alignment():
    query = {'action': 'load_item', 'aspect': 'impact_description'}
    impact_description = storage_processor(query)
    return render_template('alignment.html', impact_description=impact_description)

@app.route("/documents", methods=['GET'])
def documents():
    query = {'action': 'load_list', 'aspect': 'documents'}
    documents = storage_processor(query)
    return render_template('documents.html', documents=documents)

@app.route("/reports", methods=['GET'])
def reports():
    return render_template('reports.html')


@app.route("/threats", methods=['GET'])
def threats():
    query = {'action': 'report_all', 'aspect': 'threat',
             'processid': None, 'aspectid': None, 'inputdata': None}
    threats = storage_processor(query)
    return render_template('threats.html',threats=threats)


@app.route("/controls", methods=['GET'])
def controls():
    query = {'action': 'report_all', 'aspect': 'control',
             'processid': None, 'aspectid': None, 'inputdata': None}
    controls = storage_processor(query)
    return render_template('controls.html',controls=controls)


@app.route("/report_full", methods=['GET'])
def report_full():
    try:
        data = import_jsondata(DATAFILE)
        query = {'action': 'report_all', 'aspect': 'threat',
                 'processid': None, 'aspectid': None, 'inputdata': None}
        threats = storage_processor(query)

        query = {'action': 'report_all', 'aspect': 'control',
                 'processid': None, 'aspectid': None, 'inputdata': None}
        controls = storage_processor(query)

        query = {'action': 'report_all', 'aspect': 'container',
                 'processid': None, 'aspectid': None, 'inputdata': None}
        containers = storage_processor(query)
    except Exception as e:
        print "Error in function report_full: " + str(e)
    return render_template('report_full.html', data=data,
                           containers=containers, threats=threats, controls=controls)

if __name__ == '__main__':
    app.run()
