from django.contrib import admin
from .models import ARM_Functions, IA32_Functions, MIPS_Functions
# Register your models here.

class Functions(admin.ModelAdmin):
    list_display = ["name", "nodes", "instructions", "bytes_hash","rva", "is_vul", "comment"]
    list_filter = ("is_vul",)
    ordering = ("id",)
    search_fields = ("name",)


admin.site.register(IA32_Functions, Functions)
admin.site.register(ARM_Functions, Functions)
admin.site.register(MIPS_Functions, Functions)

# admin.site.register(UploadIa32Functions, Functions)
# admin.site.register(UploadArmFunctions, Functions)
# admin.site.register(UploadMipsFunctions, Functions)