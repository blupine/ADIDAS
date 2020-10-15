from django.contrib import admin
from .models import *

# Register your models here.
@admin.register(Model_Name)
class statisticAdmin(admin.ModelAdmin):

    # change_list_template = "admin/TEST_change_list.html"
    list_display = ["id", "name", "manufacturer_id"]
    # ordering = ("id",)
    # search_fields = ("name",)