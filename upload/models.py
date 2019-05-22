from django.db import models

# Create your models here.
class Functions(models.Model):
	id 						= models.AutoField(primary_key = True) 
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
	is_vul					= models.IntegerField(null = True)
	
	def __init__(self, datadict):
		models.Model.__init__(self,
			name 					= datadict['name'],
			address 				= datadict['address'],
			nodes 					= datadict["nodes"],
			edges 					= datadict['edges'],
			indegree 				= datadict['indegree'],
			outdegree 				= datadict['outdegree'],
			size 					= datadict['size'],
			instructions			= datadict['instructions'],
			mnemonics 				= datadict['mnemonics'],
			names					= datadict['names'],
			prototype 				= datadict['prototype'],
			cyclomatic_complexity 	= datadict['cyclomatic_complexity'],
			primes_value 			= datadict['primes_value'],
			comment 				= datadict['comment'],
			mangled_function 		= datadict['mangled_function'],
			bytes_hash 				= datadict['bytes_hash'],
			pseudocode 				= datadict['pseudocode'],
			pseudocode_lines 		= datadict['pseudocode_lines'],
			pseudocode_hash1 		= datadict['pseudocode_hash1'],
			pseudocode_primes 		= datadict['pseudocode_primes'],
			function_flags 			= datadict['function_flags'],
			assembly 				= datadict['assembly'],
			prototype2 				= datadict['prototype2'],
			pseudocode_hash2 		= datadict['pseudocode_hash2'],
			pseudocode_hash3 		= datadict['pseudocode_hash3'],
			strongly_connected 		= datadict['strongly_connected'],
			loops 					= datadict['loops'],
			rva 					= datadict['rva'],
			tarjan_topological_sort = datadict['tarjan_topological_sort'],
			strongly_connected_spp 	= datadict['strongly_connected_spp'],
			clean_assembly 			= datadict['clean_assembly'],
			clean_pseudo 			= datadict['clean_pseudo'],			
			mnemonics_spp 			= datadict['mnemonics_spp'],
			switches 				= datadict['switches'],
			function_hash 			= datadict['function_hash'],
			bytes_sum 				= datadict['bytes_sum'],
			md_index 				= datadict['md_index'],
			constants 				= datadict['constants'],
			constants_count 		= datadict['constants_count'],
			segment_rva 			= datadict['segment_rva'],			
			assembly_addrs 			= datadict['assembly_addrs'],
			kgh_hash 				= datadict['kgh_hash'])

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
