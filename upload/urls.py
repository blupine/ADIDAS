#from django.urls import path
from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    #url(r'^feature', views.features, name='feature'),
    url(r'^features', views.features, name='features'),
    url(r'^diff', views.diff, name='diff'),

    #url(r'^diff', views.diff, name='do_diff')
]