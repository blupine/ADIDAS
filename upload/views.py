from django.http import HttpResponse
from django.shortcuts import render
from upload.models import *
from django.db.models import Count
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse

import MySQLdb
import json
from ADiff.heuristics import *
from ADiff.Adiff import *
# Create your views here.
import random


def index(request):
    return HttpResponse("Test upload page for ADIDAS project")


# 2019.03.29 Receive function feature and add data to table
# Not using..
# @csrf_exempt
# def feature(request):
# 	if request.method == 'POST':
# 		data = json.loads(request.body.decode('utf-8'))
# 		try:
# 			add_data(data)
# 			print('upload success')
# 			return HttpResponse("upload success.")
# 		except (MySQLdb.Error, MySQLdb.Warning) as e:
# 			return HttpResponse("upload failed.")
# 	else:
# 		return HttpResponse("invalid data type")


# 2019.05.14 Receive multiple function features and add data to table
@csrf_exempt
def features(request):
    if request.method == 'POST':
        data = json.loads(request.body.decode('utf-8'))
        try:
            if not check_data_validation(data):
                raise
            success, failed = add_data(data)
            return HttpResponse(str([len(success), len(failed)]))
        # return HttpResponse("upload complete. \n success : %s \n\n failed  : %s" % (str(success), str(failed)))

        except (MySQLdb.Error, MySQLdb.Warning, ValueError) as e:
            return HttpResponse("upload failed. invalid data format")
    else:
        return HttpResponse("invalid http method")

# # 2019.05.14 Receive multiple function features and add data to table
# @csrf_exempt
# def features(request):
#     if request.method == 'POST':
#         data = json.loads(request.body.decode('utf-8'))
#         try:
#             if not check_data_validation(data):
#                 raise
#             success, failed = add_data(data)
#             print('===== upload end ============================================')
#             print(" success : ", len(success))
#             print(" fail    : ", len(failed))
#             return HttpResponse(str([len(success), len(failed)]))
#         # return HttpResponse("upload complete. \n success : %s \n\n failed  : %s" % (str(success), str(failed)))
#
#         except (MySQLdb.Error, MySQLdb.Warning, ValueError) as e:
#             print("upload failed", e)
#             return HttpResponse("upload failed. invalid data format")
#     else:
#         return HttpResponse("invalid http method")


# 0: None
# 1: Only Best matches
# 2: Only Partial matches
# 3: Best + Partial
# 4: Only Unreliable matches
# 5: Best + Unreliable
# 6: Partial + Unreliable
# 7: ALL

from time import sleep


# 2019.05.05 Receive list of function features
@csrf_exempt
def diff(request):
    if request.method == 'POST':
        try:
            d = json.loads(request.body.decode('utf-8'))
            option = d['option']
            data = json.loads(d['data'])
            if not check_data_validation(data):
                raise

            ad = ADiff(option)
            ret = ad.diff(data)  # ad.diff returns list of best, partial, reliable, vulnerable items

            return HttpResponse(str(ret))
        except Exception as e:
            log("Diff Request Failed - [ Invalid data type request ]")
            return HttpResponse("invalid data. check data")
    else:
        log("Diff Request Failed - [ Invalid http request method ]")
        return HttpResponse("invalid http method")
# # 2019.05.05 Receive list of function features
# @csrf_exempt
# def diff(request):
#     if request.method == 'POST':
#         try:
#             d = json.loads(request.body.decode('utf-8'))
#             option = d['option']
#             print("############")
#
#             data = json.loads(d['data'])
#             if not check_data_validation(data):
#                 raise
#
#             ad = ADiff(option)
#             ret = ad.diff(data)  # ad.diff returns list of best, partial, reliable, vulnerable items
#             log('\n\t===== diff end ============================================')
#             print(" \tbest match       : ", len(ret[0]))
#             print(" \tpartial match    : ", len(ret[1]))
#             print(" \tunreliable match : ", len(ret[2]))
#             print(" \tvulnerable match : ", len(ret[3]), '\n')
#
#             return HttpResponse(str(ret))
#         except Exception as e:
#             print(e)
#             log("Diff Request Failed - [ Invalid data type request ]")
#             return HttpResponse("invalid data. check data")
#     else:
#         log("Diff Request Failed - [ Invalid http request method ]")
#         return HttpResponse("invalid http method")


# 2019.06.08 Diff & return evalution
@csrf_exempt
def evaluation_diff(request):
    if request.method == 'POST':
        try:
            d = json.loads(request.body.decode('utf-8'))
            option = d['option']
            data = json.loads(d['data'])
            if not check_data_validation(data):
                # print("Diff Request Failed - [ Invalid data type request ]")
                raise
            # return HttpResponse("diff failed. invalid data format")

            ad = ADiff(option)
            ret = ad.evaluation_diff(data)  # ad.diff returns list of best, partial, reliable, vulnerable items
            log('\n\t===== diff end ============================================')
            print(" \tbest match       : ", len(ret[0]))
            print(" \tpartial match    : ", len(ret[1]))
            print(" \tunreliable match : ", len(ret[2]))
            print(" \tvulnerable match : ", len(ret[3]), '\n')
            return HttpResponse(str(ret))
        except:
            log("Diff Request Failed - [ Invalid data type request ]")
            return HttpResponse("invalid data. check data")
    else:
        log("Diff Request Failed - [ Invalid http request method ]")
        return HttpResponse("invalid http method")


# 2019.05.14 Add function data to each table
def add_data(data):
    success_list = []
    failed_list = []

    for index, func in data.items():
        feature = func['functions']
        program = func['program']
        arch = program['processor']
        name = feature['name']
        if name.startswith("sub_") or name.startswith("j_") or name.startswith("unknown") \
                or name.startswith("nullsub_"):
            failed_list.append(feature['name'])
            continue

        model = None
        if arch == 'pc':
            model = IA32_Functions
        elif arch == 'arm':
            model = ARM_Functions
        elif arch == 'mips':
            model = MIPS_Functions

        # print(arch)
        if model is None:
            print("upload/views add failed list - arch : [" + arch + "]")
            failed_list.append(feature['name'])
            continue
        if find_duplication(model, feature):
            f = model(
                name 					= feature['name'],
                address 				= feature['address'],
                nodes 					= feature["nodes"],
                edges 					= feature['edges'],
                indegree 				= feature['indegree'],
                outdegree 				= feature['outdegree'],
                size 					= feature['size'],
                instructions			= feature['instructions'],
                mnemonics 				= feature['mnemonics'],
                names					= feature['names'],
                prototype 				= feature['prototype'],
                cyclomatic_complexity 	= feature['cyclomatic_complexity'],
                primes_value 			= feature['primes_value'],
                comment 				= feature['comment'],
                mangled_function 		= feature['mangled_function'],
                bytes_hash 				= feature['bytes_hash'],
                pseudocode 				= feature['pseudocode'],
                pseudocode_lines 		= feature['pseudocode_lines'],
                pseudocode_hash1 		= feature['pseudocode_hash1'],
                pseudocode_primes 		= feature['pseudocode_primes'],
                function_flags 			= feature['function_flags'],
                assembly 				= feature['assembly'],
                prototype2 				= feature['prototype2'],
                pseudocode_hash2 		= feature['pseudocode_hash2'],
                pseudocode_hash3 		= feature['pseudocode_hash3'],
                strongly_connected 		= feature['strongly_connected'],
                loops 					= feature['loops'],
                rva 					= feature['rva'],
                tarjan_topological_sort = feature['tarjan_topological_sort'],
                strongly_connected_spp 	= feature['strongly_connected_spp'],
                clean_assembly 			= feature['clean_assembly'],
                clean_pseudo 			= feature['clean_pseudo'],
                mnemonics_spp 			= feature['mnemonics_spp'],
                switches 				= feature['switches'],
                function_hash 			= feature['function_hash'],
                bytes_sum 				= feature['bytes_sum'],
                md_index 				= feature['md_index'],
                constants 				= feature['constants'],
                constants_count 		= feature['constants_count'],
                segment_rva 			= feature['segment_rva'],
                assembly_addrs 			= feature['assembly_addrs'],
                kgh_hash 				= feature['kgh_hash'],
                binary_name				= feature['binary_name'],
                is_vul					= feature['is_vul'])

            f.save()
            success_list.append(feature['name'])
        else:
            failed_list.append(feature['name'])

    return success_list, failed_list


# Tight standard : 'bytes_hash'
# Loose standard : ?
def find_duplication(model, funcdict):
    result_list = model.objects.values_list('bytes_hash', flat=True).distinct()
    for item in result_list:
        if item == funcdict['bytes_hash']:
            print("upload/find_duplication - duplicated bytes hash [" + item + "] [" + funcdict['bytes_hash'] + "]")

            return 0
    return 1


def find_str_duplication(model, str):
    result_list = model.objects.values_list('name', flat=True).distinct()
    for item in result_list:
        if item == str:
            return 0
    return 1


def get_names(model):
    result_list = model.objects.values_list('name', flat=True).distinct()

    if result_list is not None :
        return ':'.join(result_list)
    return None


def add_names(model, string):
    if find_str_duplication(model, string):
        result = model(string)
        result.save()

def del_names(model, string):
    result = model.objects.filter(name=string).delete()
    return result

# check if all function table's attributes in input data
def check_data_validation(data):
    try:
        for index, func in data.items():
            feature = func["functions"]
            for key in FUNC_ATTR:
                if key not in feature:
                    log("key " + key + " is not in feature")
                    raise
        return 1
    except:
        log("invalid data")
        return 0

def getmodel(request):
    print("getmodel called")
    list = get_names(Model_Name)
    print(list)
    if list is not None :
        return HttpResponse(list)

def getmanufacture(request):
    print("getmanufacture called")
    list = get_names(Manufacture)
    return HttpResponse(list,content_type='charset=ascii')

def addmodel(request):
    print("addmodel called")

    req = request.GET.get("name")
    add_names(Model_Name, req)
    return HttpResponse("model")

def addmanufacture(request):
    req = request.GET.get("name")
    add_names(Manufacture, req)
    return HttpResponse("manufacture")

def delmodel(request):
    del_names(Model_Name, request.GET.get("name"))
    return HttpResponse("model")

def delmanufacture(request):
    del_names(Manufacture, request.GET.get("name"))
    return HttpResponse("manufacture")


def askmodels(request):
    result = dict()
    #MyEvent.objects.all().values('msg','event_type', 'msg__name', 'msg__description')
    models = []
    manufactures = []

    model_pair = dict()

    model_list = Model_Name.objects.all()
    for item in model_list:
        if item.name not in models:
            models.append(item.name)
        if item.manufacturer.name not in manufactures:
            manufactures.append(item.manufacturer.name)

        model_pair[item.manufacturer.name] = []
        model_pair[item.manufacturer.name].append(item.name)

    result['model'] = models
    result['manufactures'] = manufactures
    result['modelpair'] = model_pair

    return JsonResponse(result)

def newmodel(request):
    model_name = request.GET.get('model')
    manufacture_name = request.GET.get('manufacture')

    print(model_name)
    print(manufacture_name)
    model_list = Model_Name.objects.values_list('name', flat=True).distinct()

    if model_name not in model_list:
    #create new model name data
        try:
            manufacture_obj = Manufacture.objects.get(name=manufacture_name)
        except Exception as e:
            print("Err : " + str(e))
            # If there is no manufacture in database
            manufacture_obj = Manufacture(name=manufacture_name)
            manufacture_obj.save()

        print("id : " + str(manufacture_obj.id))
        new_model = Model_Name(name=model_name, manufacturer=manufacture_obj)
        new_model.save()
        return HttpResponse("Create model [%s] saved successfully."%model_name)

    else:
        return HttpResponse("Model name [%s] already exists." %model_name)



def test_model(model, func):
    result = model(func)
    result.save()

    func['test'] = 'random_value'

    result = model(func)
    result.save()




# data = {
#   "1" : {"functions": {"binary_name" : "", "is_vul" : 0 ,"comment": "", "rva": 6736, "pseudocode_hash1": None, "pseudocode_hash2": null, "pseudocode_hash3": null, "kgh_hash": "6983291813221350", "md_index": "0", "pseudocode": null, "switches": "", "strongly_connected_spp": "", "names": [], "loops": 0, "clean_pseudo": "", "size": 16, "constants_count": 2, "mangled_function": "", "mnemonics_spp": "", "function_flags": 1216, "outdegree": 1, "prototype2": null, "primes_value": "2", "clean_assembly": "", "nodes": 2, "prototype": null, "bytes_hash": "dafdeddcb27192df42baf9fa9c28e49b", "cyclomatic_complexity": 0, "assembly": "ADR     R12, 0x11A58\nADD     R12, R12, #0x2D000\nLDR     PC, [R12,#(__fxstatat64_ptr - 0x3EA58)]!; __imp___fxstatat64\nloc_406e0:\nIMPORT __imp___fxstatat64", "pseudocode_lines": 0, "pseudocode_primes": null, "strongly_connected": 1, "edges": 0, "address": 72272, "tarjan_topological_sort": "", "bytes_sum": 1907, "constants": [72280, 184320], "instructions": 4, "segment_rva": 368, "mnemonics": ["ADR", "ADD", "LDR", "RETEQ"], "name": "__fxstatat64", "indegree": 3, "function_hash": "dafdeddcb27192df42baf9fa9c28e49b", "assembly_addrs": [6736, 6740, 6744, 198368, 198368]}, "version": {}, "instruction": {}, "function_bblocks": {}, "bb_relations": {}, "program": {"callgraph_all_primes": "", "processor": "arm", "md5sum": "", "callgraph_primes": ""}, "callgraph": {}, "bb_instruction": {}, "basic_blocks": {}, "program_data": {}},
#   "2" : {"functions": {"binary_name" : "", "is_vul" : 0 ,"comment": "", "rva": 6736, "pseudocode_hash1": None, "pseudocode_hash2": null, "pseudocode_hash3": null, "kgh_hash": "6983291813221350", "md_index": "0", "pseudocode": null, "switches": "", "strongly_connected_spp": "", "names": [], "loops": 0, "clean_pseudo": "", "size": 16, "constants_count": 2, "mangled_function": "", "mnemonics_spp": "", "function_flags": 1216, "outdegree": 1, "prototype2": null, "primes_value": "2", "clean_assembly": "", "nodes": 2, "prototype": null, "bytes_hash": "dafdeddcb27192df42baf9fa9c28e49b", "cyclomatic_complexity": 0, "assembly": "ADR     R12, 0x11A58\nADD     R12, R12, #0x2D000\nLDR     PC, [R12,#(__fxstatat64_ptr - 0x3EA58)]!; __imp___fxstatat64\nloc_406e0:\nIMPORT __imp___fxstatat64", "pseudocode_lines": 0, "pseudocode_primes": null, "strongly_connected": 1, "edges": 0, "address": 72272, "tarjan_topological_sort": "", "bytes_sum": 1907, "constants": [72280, 184320], "instructions": 4, "segment_rva": 368, "mnemonics": ["ADR", "ADD", "LDR", "RETEQ"], "name": "__fxstatat64", "indegree": 3, "function_hash": "dafdeddcb27192df42baf9fa9c28e49b", "assembly_addrs": [6736, 6740, 6744, 198368, 198368]}, "version": {}, "instruction": {}, "function_bblocks": {}, "bb_relations": {}, "program": {"callgraph_all_primes": "", "processor": "arm", "md5sum": "", "callgraph_primes": ""}, "callgraph": {}, "bb_instruction": {}, "basic_blocks": {}, "program_data": {}},
#   "3" : {"functions": {"binary_name" : "", "is_vul" : 0 ,"comment": "", "rva": 6736, "pseudocode_hash1": None, "pseudocode_hash2": null, "pseudocode_hash3": null, "kgh_hash": "6983291813221350", "md_index": "0", "pseudocode": null, "switches": "", "strongly_connected_spp": "", "names": [], "loops": 0, "clean_pseudo": "", "size": 16, "constants_count": 2, "mangled_function": "", "mnemonics_spp": "", "function_flags": 1216, "outdegree": 1, "prototype2": null, "primes_value": "2", "clean_assembly": "", "nodes": 2, "prototype": null, "bytes_hash": "dafdeddcb27192df42baf9fa9c28e49b", "cyclomatic_complexity": 0, "assembly": "ADR     R12, 0x11A58\nADD     R12, R12, #0x2D000\nLDR     PC, [R12,#(__fxstatat64_ptr - 0x3EA58)]!; __imp___fxstatat64\nloc_406e0:\nIMPORT __imp___fxstatat64", "pseudocode_lines": 0, "pseudocode_primes": null, "strongly_connected": 1, "edges": 0, "address": 72272, "tarjan_topological_sort": "", "bytes_sum": 1907, "constants": [72280, 184320], "instructions": 4, "segment_rva": 368, "mnemonics": ["ADR", "ADD", "LDR", "RETEQ"], "name": "__fxstatat64", "indegree": 3, "function_hash": "dafdeddcb27192df42baf9fa9c28e49b", "assembly_addrs": [6736, 6740, 6744, 198368, 198368]}, "version": {}, "instruction": {}, "function_bblocks": {}, "bb_relations": {}, "program": {"callgraph_all_primes": "", "processor": "arm", "md5sum": "", "callgraph_primes": ""}, "callgraph": {}, "bb_instruction": {}, "basic_blocks": {}, "program_data": {}}
# }



# def test_vul():
#     data['1']['is_vul'] = '1'
#     add_data(data)
#     ad = ADiff(7)
#     res = ad.diff(data)
#     print(res)
#
#
# def test_diff():
#     option = 4
#     ad = ADiff(option)
#     res = ad.diff(data)
#     print(res)
#
#
# def test_upload():
#     check_data_validation(data)
#     add_data(data)
#     find_duplication(data)
