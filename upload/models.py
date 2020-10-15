from django.db import models
from statistic.models import *

# Create your models here.
class Functions(models.Model):
	id 						= models.AutoField(primary_key = True) 
	model_type 				= models.ForeignKey(Model_Name, null=True, on_delete=models.SET_NULL)
	name 					= models.CharField(max_length = 255)
	address 				= models.TextField(null = True)
	nodes 					= models.IntegerField(null = True)
	edges 					= models.IntegerField(null = True)
	indegree 				= models.IntegerField(null = True)
	outdegree 				= models.IntegerField(null = True)
	size 					= models.IntegerField(null = True)
	instructions 			= models.IntegerField(null = True)
	mnemonics 				= models.TextField(null = True)
	names		 			= models.TextField(null = True)
	prototype 				= models.TextField(null = True)
	cyclomatic_complexity 	= models.IntegerField(null = True)
	primes_value 			= models.TextField(null = True)
	comment 				= models.TextField(null = True)
	mangled_function 		= models.TextField(null = True)
	bytes_hash 				= models.TextField(null = True)
	pseudocode 				= models.TextField(null = True)
	pseudocode_lines 		= models.IntegerField(null = True)
	pseudocode_hash1 		= models.TextField(null = True)
	pseudocode_primes 		= models.TextField(null = True)
	function_flags 			= models.IntegerField(null = True)
	assembly 				= models.TextField(null = True)
	prototype2 				= models.TextField(null = True)
	pseudocode_hash2 		= models.TextField(null = True)
	pseudocode_hash3 		= models.TextField(null = True)
	strongly_connected 		= models.IntegerField(null = True)
	loops 					= models.IntegerField(null = True)
	rva 					= models.TextField(null = True)
	tarjan_topological_sort = models.TextField(null = True)
	strongly_connected_spp 	= models.TextField(null = True)
	clean_assembly 			= models.TextField(null = True)
	clean_pseudo 			= models.TextField(null = True)
	mnemonics_spp 			= models.TextField(null = True)
	switches 				= models.TextField(null = True)
	function_hash 			= models.TextField(null = True)
	bytes_sum 				= models.IntegerField(null = True)
	md_index 				= models.TextField(null = True)
	constants 				= models.TextField(null = True)
	constants_count 		= models.IntegerField(null = True)
	segment_rva 			= models.TextField(null = True)
	assembly_addrs 			= models.TextField(null = True)
	kgh_hash 				= models.TextField(null = True)

	# new field
	binary_name				= models.TextField(null = True)
	is_vul					= models.TextField(null = True)

	class Meta:
			abstract = True

class ARM_Functions(Functions):
	pass

class IA32_Functions(Functions):
	pass

class MIPS_Functions(Functions):
	pass

#class Program(models.Model):
#	id 						= models.AutoField(primary_key = True)
#	callgraph_primes 		= models.TextField(null = True)
#	callgraph_all_primes	= models.TextField(null = True)
#	processor				= models.TextField(null = True)
#	md5sum					= models.TextField(null = True)
 	
 # not creating 'version' model
