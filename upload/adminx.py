import xadmin
# from .models import ARM_Functions, IA32_Functions, MIPS_Functions
from .models_1 import UploadMipsFunctions, UploadArmFunctions, UploadIa32Functions

class ModelDetail(object):
    search_fields = ('name',)
    list_display = ("id", "name", "nodes", "instructions", "bytes_hash", "rva", "is_vul", "comment")
    # list_display_links = ('nameadMipsFunctions, PostAdmin)', )
    ordering = ('id',)
    # fields above just like django admin


xadmin.site.register(UploadArmFunctions, ModelDetail)
xadmin.site.register(UploadIa32Functions, ModelDetail)
xadmin.site.register(UploadMipsFunctions, ModelDetail)