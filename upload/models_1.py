# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey has `on_delete` set to the desired behavior.
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
from django.db import models

class AuthGroup(models.Model):
    name = models.CharField(unique=True, max_length=150)

    class Meta:
        managed = False
        db_table = 'auth_group'


class AuthGroupPermissions(models.Model):
    group = models.ForeignKey(AuthGroup, models.DO_NOTHING)
    permission = models.ForeignKey('AuthPermission', models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'auth_group_permissions'
        unique_together = (('group', 'permission'),)


class AuthPermission(models.Model):
    name = models.CharField(max_length=255)
    content_type = models.ForeignKey('DjangoContentType', models.DO_NOTHING)
    codename = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'auth_permission'
        unique_together = (('content_type', 'codename'),)


class AuthUser(models.Model):
    password = models.CharField(max_length=128)
    last_login = models.DateTimeField(blank=True, null=True)
    is_superuser = models.IntegerField()
    username = models.CharField(unique=True, max_length=150)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=150)
    email = models.CharField(max_length=254)
    is_staff = models.IntegerField()
    is_active = models.IntegerField()
    date_joined = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'auth_user'


class AuthUserGroups(models.Model):
    user = models.ForeignKey(AuthUser, models.DO_NOTHING)
    group = models.ForeignKey(AuthGroup, models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'auth_user_groups'
        unique_together = (('user', 'group'),)


class AuthUserUserPermissions(models.Model):
    user = models.ForeignKey(AuthUser, models.DO_NOTHING)
    permission = models.ForeignKey(AuthPermission, models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'auth_user_user_permissions'
        unique_together = (('user', 'permission'),)


class DjangoAdminLog(models.Model):
    action_time = models.DateTimeField()
    object_id = models.TextField(blank=True, null=True)
    object_repr = models.CharField(max_length=200)
    action_flag = models.PositiveSmallIntegerField()
    change_message = models.TextField()
    content_type = models.ForeignKey('DjangoContentType', models.DO_NOTHING, blank=True, null=True)
    user = models.ForeignKey(AuthUser, models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'django_admin_log'


class DjangoContentType(models.Model):
    app_label = models.CharField(max_length=100)
    model = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'django_content_type'
        unique_together = (('app_label', 'model'),)


class DjangoMigrations(models.Model):
    app = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    applied = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'django_migrations'


class DjangoSession(models.Model):
    session_key = models.CharField(primary_key=True, max_length=40)
    session_data = models.TextField()
    expire_date = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'django_session'



class UploadArmFunctions(models.Model):
    name = models.CharField(max_length=255)
    address = models.TextField(blank=True, null=True)
    nodes = models.IntegerField(blank=True, null=True)
    edges = models.IntegerField(blank=True, null=True)
    indegree = models.IntegerField(blank=True, null=True)
    outdegree = models.IntegerField(blank=True, null=True)
    size = models.IntegerField(blank=True, null=True)
    instructions = models.IntegerField(blank=True, null=True)
    mnemonics = models.TextField(blank=True, null=True)
    names = models.TextField(blank=True, null=True)
    prototype = models.TextField(blank=True, null=True)
    cyclomatic_complexity = models.IntegerField(blank=True, null=True)
    primes_value = models.TextField(blank=True, null=True)
    comment = models.TextField(blank=True, null=True)
    mangled_function = models.TextField(blank=True, null=True)
    bytes_hash = models.TextField(blank=True, null=True)
    pseudocode = models.TextField(blank=True, null=True)
    pseudocode_lines = models.IntegerField(blank=True, null=True)
    pseudocode_hash1 = models.TextField(blank=True, null=True)
    pseudocode_primes = models.TextField(blank=True, null=True)
    function_flags = models.IntegerField(blank=True, null=True)
    assembly = models.TextField(blank=True, null=True)
    prototype2 = models.TextField(blank=True, null=True)
    pseudocode_hash2 = models.TextField(blank=True, null=True)
    pseudocode_hash3 = models.TextField(blank=True, null=True)
    strongly_connected = models.IntegerField(blank=True, null=True)
    loops = models.IntegerField(blank=True, null=True)
    rva = models.TextField(blank=True, null=True)
    tarjan_topological_sort = models.TextField(blank=True, null=True)
    strongly_connected_spp = models.TextField(blank=True, null=True)
    clean_assembly = models.TextField(blank=True, null=True)
    clean_pseudo = models.TextField(blank=True, null=True)
    mnemonics_spp = models.TextField(blank=True, null=True)
    switches = models.TextField(blank=True, null=True)
    function_hash = models.TextField(blank=True, null=True)
    bytes_sum = models.IntegerField(blank=True, null=True)
    md_index = models.TextField(blank=True, null=True)
    constants = models.TextField(blank=True, null=True)
    constants_count = models.IntegerField(blank=True, null=True)
    segment_rva = models.TextField(blank=True, null=True)
    assembly_addrs = models.TextField(blank=True, null=True)
    kgh_hash = models.TextField(blank=True, null=True)
    binary_name = models.TextField(blank=True, null=True)
    is_vul = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'upload_arm_functions'


class UploadIa32Functions(models.Model):
    name = models.CharField(max_length=255)
    address = models.TextField(blank=True, null=True)
    nodes = models.IntegerField(blank=True, null=True)
    edges = models.IntegerField(blank=True, null=True)
    indegree = models.IntegerField(blank=True, null=True)
    outdegree = models.IntegerField(blank=True, null=True)
    size = models.IntegerField(blank=True, null=True)
    instructions = models.IntegerField(blank=True, null=True)
    mnemonics = models.TextField(blank=True, null=True)
    names = models.TextField(blank=True, null=True)
    prototype = models.TextField(blank=True, null=True)
    cyclomatic_complexity = models.IntegerField(blank=True, null=True)
    primes_value = models.TextField(blank=True, null=True)
    comment = models.TextField(blank=True, null=True)
    mangled_function = models.TextField(blank=True, null=True)
    bytes_hash = models.TextField(blank=True, null=True)
    pseudocode = models.TextField(blank=True, null=True)
    pseudocode_lines = models.IntegerField(blank=True, null=True)
    pseudocode_hash1 = models.TextField(blank=True, null=True)
    pseudocode_primes = models.TextField(blank=True, null=True)
    function_flags = models.IntegerField(blank=True, null=True)
    assembly = models.TextField(blank=True, null=True)
    prototype2 = models.TextField(blank=True, null=True)
    pseudocode_hash2 = models.TextField(blank=True, null=True)
    pseudocode_hash3 = models.TextField(blank=True, null=True)
    strongly_connected = models.IntegerField(blank=True, null=True)
    loops = models.IntegerField(blank=True, null=True)
    rva = models.TextField(blank=True, null=True)
    tarjan_topological_sort = models.TextField(blank=True, null=True)
    strongly_connected_spp = models.TextField(blank=True, null=True)
    clean_assembly = models.TextField(blank=True, null=True)
    clean_pseudo = models.TextField(blank=True, null=True)
    mnemonics_spp = models.TextField(blank=True, null=True)
    switches = models.TextField(blank=True, null=True)
    function_hash = models.TextField(blank=True, null=True)
    bytes_sum = models.IntegerField(blank=True, null=True)
    md_index = models.TextField(blank=True, null=True)
    constants = models.TextField(blank=True, null=True)
    constants_count = models.IntegerField(blank=True, null=True)
    segment_rva = models.TextField(blank=True, null=True)
    assembly_addrs = models.TextField(blank=True, null=True)
    kgh_hash = models.TextField(blank=True, null=True)
    binary_name = models.TextField(blank=True, null=True)
    is_vul = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'upload_ia32_functions'


class UploadMipsFunctions(models.Model):
    name = models.CharField(max_length=255)
    address = models.TextField(blank=True, null=True)
    nodes = models.IntegerField(blank=True, null=True)
    edges = models.IntegerField(blank=True, null=True)
    indegree = models.IntegerField(blank=True, null=True)
    outdegree = models.IntegerField(blank=True, null=True)
    size = models.IntegerField(blank=True, null=True)
    instructions = models.IntegerField(blank=True, null=True)
    mnemonics = models.TextField(blank=True, null=True)
    names = models.TextField(blank=True, null=True)
    prototype = models.TextField(blank=True, null=True)
    cyclomatic_complexity = models.IntegerField(blank=True, null=True)
    primes_value = models.TextField(blank=True, null=True)
    comment = models.TextField(blank=True, null=True)
    mangled_function = models.TextField(blank=True, null=True)
    bytes_hash = models.TextField(blank=True, null=True)
    pseudocode = models.TextField(blank=True, null=True)
    pseudocode_lines = models.IntegerField(blank=True, null=True)
    pseudocode_hash1 = models.TextField(blank=True, null=True)
    pseudocode_primes = models.TextField(blank=True, null=True)
    function_flags = models.IntegerField(blank=True, null=True)
    assembly = models.TextField(blank=True, null=True)
    prototype2 = models.TextField(blank=True, null=True)
    pseudocode_hash2 = models.TextField(blank=True, null=True)
    pseudocode_hash3 = models.TextField(blank=True, null=True)
    strongly_connected = models.IntegerField(blank=True, null=True)
    loops = models.IntegerField(blank=True, null=True)
    rva = models.TextField(blank=True, null=True)
    tarjan_topological_sort = models.TextField(blank=True, null=True)
    strongly_connected_spp = models.TextField(blank=True, null=True)
    clean_assembly = models.TextField(blank=True, null=True)
    clean_pseudo = models.TextField(blank=True, null=True)
    mnemonics_spp = models.TextField(blank=True, null=True)
    switches = models.TextField(blank=True, null=True)
    function_hash = models.TextField(blank=True, null=True)
    bytes_sum = models.IntegerField(blank=True, null=True)
    md_index = models.TextField(blank=True, null=True)
    constants = models.TextField(blank=True, null=True)
    constants_count = models.IntegerField(blank=True, null=True)
    segment_rva = models.TextField(blank=True, null=True)
    assembly_addrs = models.TextField(blank=True, null=True)
    kgh_hash = models.TextField(blank=True, null=True)
    binary_name = models.TextField(blank=True, null=True)
    is_vul = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'upload_mips_functions'


class XadminBookmark(models.Model):
    title = models.CharField(max_length=128)
    url_name = models.CharField(max_length=64)
    query = models.CharField(max_length=1000)
    is_share = models.IntegerField()
    content_type = models.ForeignKey(DjangoContentType, models.DO_NOTHING)
    user = models.ForeignKey(AuthUser, models.DO_NOTHING, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'xadmin_bookmark'


class XadminLog(models.Model):
    action_time = models.DateTimeField()
    ip_addr = models.CharField(max_length=39, blank=True, null=True)
    object_id = models.TextField(blank=True, null=True)
    object_repr = models.CharField(max_length=200)
    action_flag = models.CharField(max_length=32)
    message = models.TextField()
    content_type = models.ForeignKey(DjangoContentType, models.DO_NOTHING, blank=True, null=True)
    user = models.ForeignKey(AuthUser, models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'xadmin_log'


class XadminUsersettings(models.Model):
    key = models.CharField(max_length=256)
    value = models.TextField()
    user = models.ForeignKey(AuthUser, models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'xadmin_usersettings'


class XadminUserwidget(models.Model):
    page_id = models.CharField(max_length=256)
    widget_type = models.CharField(max_length=50)
    value = models.TextField()
    user = models.ForeignKey(AuthUser, models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'xadmin_userwidget'
