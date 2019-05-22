from django.http import HttpResponse
from django.shortcuts import render
from upload.models import *
from django.db.models import Count
from django.views.decorators.csrf import csrf_exempt

import MySQLdb
import json
from .heuristics import *

# Create your views here.
def index(request):
    return HttpResponse("Test upload page for ADIDAS project")

#2019.03.29 Receive function feature and add data to table
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

def sibal(request):
	return

@csrf_exempt
def features(request):
	if request.method == 'POST':
		data = json.loads(request.body.decode('utf-8'))
		try:
			if not check_data_validation(data):
				raise
			success, failed = add_data(data)
			print("upload end", success, failed)
			return HttpResponse("upload complete. \n success : %s \n\n failed  : %s" % (str(success), str(failed)))

		except (MySQLdb.Error, MySQLdb.Warning, ValueError) as e:
			print("upload failed", e)
			return HttpResponse("upload failed. invalid data format")
	else:
		return HttpResponse("invalid http method")


#2019.05.05 Receive list of function features
@csrf_exempt
def diff(request):
	if request.method == 'POST':
		data = json.loads(request.body.decode('utf-8'))
		if not check_data_validation(data):
			return HttpResponse("diff failed. invalid data format")

		ad = ADiff()
		best, partial, reliable = ad.diff(data)
		ret = list()
		ret.append(best)
		ret.append(partial)
		ret.append(reliable)

		return HttpResponse(str(ret))
	else:
		return HttpResponse("invalid http method")


#2019.05.14 Add function data to each table
def add_data(data):
	print("add data called")
	success_list = []
	failed_list  = []
	for index, func in data.items():
		feature = func['functions']
		program = func['program']
		arch = program['processor']

		#if feature['name'].
		f = ''
		if arch == 'pc':
			if find_duplication(IA32_Functions, feature):
				f = IA32_Functions(feature)
				f.save()
				success_list.append(feature['name'])
			else:
				failed_list.append(feature['name'])

		elif arch == 'arm':
			if find_duplication(ARM_Functions, feature):
				f = ARM_Functions(feature)
				f.save()

				success_list.append(feature['name'])
			else:
				failed_list.append(feature['name'])

		elif arch == 'mips':
			if find_duplication(MIPS_Functions, feature):
				f = MIPS_Functions(feature)
				f.save()
				success_list.append(feature['name'])

			else:
				failed_list.appned(feature['name'])

		else:
			failed_list.append(feature['name'])


	return success_list, failed_list

#2019.03.29 Adding function data to tables
# def add_data(data):
# 	func = data['functions']
# 	program = data['program']
# 	arch = program['processor']
# 	f = ''
# 	if arch == 'pc':
# 		if find_duplication(IA32_Functions, func):
# 			f = IA32_Functions(func)
# 		else:
# 			raise MySQLdb.Error
#
# 	elif arch == 'arm':
# 		if find_duplication(ARM_Functions, func):
# 			f = ARM_Functions(func)
# 		else:
# 			raise MySQLdb.Error
#
# 	elif arch == 'mips':
# 		if find_duplication(MIPS_Functions, func):
# 			f = MIPS_Functions(func)
# 		else:
# 			raise MySQLdb.Error
#
# 	else:
# 		raise MySQLdb.Error
#
# 	f.save()

# 2019.04.13 Need standard of duplication
# Tight standard : 'bytes_hash'
# Loose standard : ?
def find_duplication(model, funcdict):
	result_list = model.objects.values_list('bytes_hash', flat=True).distinct()
	for item in result_list:
		if item == funcdict['bytes_hash']:
			return 0
	return 1

# check if all function table's attributes in input data
def check_data_validation(data):
	try:
		for index, func in data.items():
			feature = func["functions"]
			for key in FUNC_ATTR:
				if key not in feature:
					print("key " + key + " is not in feature")
					raise
	except:
		return 0
	return 1