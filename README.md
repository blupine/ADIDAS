# ADIDAS
### ADvanced Integrated binary Difference Analyzing System

Django based symbol of stripped binary analyzer. 
Upload and collect symbols with function information using client_extension.py on IDA disassembler.
And diff your stripped binary to restore symbol with database.
Used binary diffing logic of [diaphora](https://github.com/joxeankoret/diaphora) 

Use *client_extension.py* as a client plugin in IDA Disassembler.



### How to use (install django first)
```
python -m pip install django
```

### Run server on local machine
```
python3 manage.py runserver:[port]
```

### Run client_extension.py on IDA Disassembler
[File] - [Script file] - [select client_extension.py] 

