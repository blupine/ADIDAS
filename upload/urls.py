#from django.urls import path
from django.conf.urls import url
from django.contrib import admin

from . import views

urlpatterns = [
    # url('', admin.site.urls),
    # url(r'', admin.site.urls),

    url(r'^features', views.features, name='features'),
    url(r'^diff', views.diff, name='diff'),
    url(r'^eval', views.evaluation_diff, name='eval'),
    url(r'^getmodel', views.getmodel, name='getmodel'),
	url(r'^getmanufacture', views.getmanufacture, name='getmanufacture'),
    url(r'^addmodel', views.addmodel, name='addmodel'),
	url(r'^addmanufacture', views.addmanufacture, name='addmanufacture'),
    url(r'^delmodel', views.delmodel, name='delmodel'),
	url(r'^delmanufacture', views.delmanufacture, name='delmanufacture'),
    url(r'^newmodel', views.newmodel, name='newmodel'),
    url(r'^askmodels', views.askmodels, name='askmodels')
]

