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
    # template = loader.get_template('index.html')
    # #index.html -> "data.json" -> parameter
    #
    # #여기서 data.json을 어캐바꾸누
    # # 해줘
    # # 쉬벌
    #
    # return HttpResponse(template.render())

