from django.conf.urls import url
from . import views


urlpatterns = [
    url(r'^userdata', views.userdata, name='userdata')
]
