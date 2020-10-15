from django.db import models
# Create your models here.

#database statics status

class Manufacture(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)

class Model_Name(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    manufacturer = models.ForeignKey(Manufacture, on_delete=models.SET_NULL, null=True)
