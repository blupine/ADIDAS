from django.shortcuts import render

# Create your views here.
from django.http import HttpResponse
from django.template import Context, loader
from statistic.templates.admin import *

def userdata(request):
    # parameter
    if request.method == 'GET':
        filename = request.GET.get('filename')
        base_dir = "/static/userdata/"
        filename = base_dir + filename

        context = {'filename' : filename + '.json', 'file_link' : filename + '.xlsx'}
        return render(request, 'index.html', context)
