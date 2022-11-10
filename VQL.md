# VQL: Velociraptor query language

## it's pretty like sql, you open the terminal and type: 
> velociraptor.exe -v query "select * from info()" 
## but not very recommended. It's better to use the UI, using the notebook of velociraptor. 
## It provides useful data of the execution of the queries and makes some suggestions. (also it's shared).

> SELECT OS, log(message='I ran') as LOG from info() where OS =~ "Linux"
## Here, log message will always return true
## 	as LOG means an alias, as in SQL
##	=~ means "matches", it's like 'like' in PostgreSQL

#Chuletas

## Creating Configuration
.> velocidex.exe config generate -i

server.config.yaml -> to config server
client.config.yaml -> to config client

##Once you generate a config, you can't regenerate it, it breaks, you'll have to update the existing config.
.\velociraptor.exe --config server.config.yaml debian server --binary velociraptor-debian

# VQL
## If we put 
> SELECT OS, log(message='I ran') as LOG from info() where Log AND OS =~ "Linux"
## we are filtering for the Log column, so there will be no results.

## If 'Permission denied', means that the user has no administrator role.

## Scopes:
## they're like variable:value dictionaries. 

#  foreach() plugin: It's like a join in sql. 

## It takes 2 parameters, it takes the row emitted, and builds a new scope in which 
## it evaluates another query. Example:
> select * from pslists(pid=getpid())
## here we take the exe (executable file) from pslist and use as filename value for the stat plugin. 
## first they were select * but now we take some columns in order to have less
## information on the output. 
> select name, CommandLine, exe from pslist(pid=getpid())

> select Btime, Mtime, FullPath from stat(filename="/usr/local/bin/velociraptor.bin")
## !! the column names are CASE SENSITIVE !! 
## Not, for each row in the first table, we want to generate a query in the second table. Example
> select * from foreach(
  row={select name, Cmdline, Exe from pslist(pid=getpid())},
  query={select Btime, Mtime, FullPath from stat(filename=Exe)}
  )
## Also we can take another columns in the selects.
## For each takes any think iterable as row.

# glob() plugin: Is used to search for files by filenames. Example:
> SELECT FullPath, hash(path=FullPath)
  FROM glob(globs="/bin/*")
  WHERE NOT isDir

## Also we can define variables using LET var = query.
## where var can be one variable, or a table.
> LET processes = SELECT * FROM pslist()
> LET times = SELECT * FROM stat(filename=Exe)
> SELECT * FROM foreach(row=processes, query=times)

## The LET doesn't launch the query, it stores it, and it's called when we use it (no materializing)

## But if we want the query  to be materialized, we use the <= operator. 
> LET processes <= SELECT * FROM pslist()

## scope(): plugin means nothing, if we want something like 
> SELECT 1+1 FROM scope()

# ARTIFACTS # 
## An artifact is a encapsulation of the queries inside something that makes it reusable
## Artifacts View:
### We can use one of the prebuilt artifacts,customize one of them or create a whole new artifact.

## Let's create a new artifact from a query
## When we create it, a default yaml file is created where we can have our modifications.
{name: Custom.Artifact.Name
description: |
   This is the human readable description of the artifact.

# Can be CLIENT, CLIENT_EVENT, SERVER, SERVER_EVENT
type: CLIENT

parameters:
   - name: FirstParameter
     default: Default Value of first parameter

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows' OR OS = 'linux' OR OS = 'darwin'

    query: |
      SELECT * FROM info()
      LIMIT 10
}
## where 
### Description: Must be human readable and can be used to find the artifact, so choose well the words.
### Type: is about where the artifact's query will be executed:
	- Client
	- Client-event (monitorization)
	- Server (Administration)
	- Server-event
### Parameters: Is used like parameter of a function, you can define values and when we go to client > Collected > new collection > choose our artifact > configure parameters
###			we can chat change the parameter velociraptor takes
###		Types of parameters:	
			- int, integer
			- timestamp
			- csv
			- json
			- json_array
			- blob
			- bool

### Artifact example: (wmic process call create cmd.exe) < on client
> [Custom.Windows.Wmi.ParentProces] 
> type: CLIENT

parameters:
   - name: ProcessRegex
     default: cmd.exe

sources:
  - precondition:
      SELECT OS From info() where OS = 'windows'

    query: |
      SELECT Name, Pid, Ppid, {
          SELECT Name FROM pslist(pid=ppid)
      } AS ParentName,
      CmdLine, Exe from pslist()
      WHERE Exe =~ ProcessRegex  and ParentName=~"WmiPrvSE"

## Hunting: Launching queries through all the organization, instead of one client.
### Creating a new hunt we can configure it to run only in a range of dates, matching or excluding specific labels or operating systems, or different
### clients depending on the time they have been active.
## * If a hunt is creating using a VQL from the notebook (select hunt(artifact, parameters) from scope()), velociraptor asumes that we know 
### what we are doing it is executed inmediately, without having to push the start button manually.
### Example:
> SELECT hunt(artifacts="Generic.Client.Info", description="An autohunt") FROM scope()

## Shell feature!
### We have a shell console where we can launch VQL queries as well. But it is better to create an artifact and collect the 
### information from it.

## On file finder, we can use a yara rule finder as parameter)

# Exercise: Enrich netstat
### we create in notebook a new query like this 
> SELECT * FROM netstat()
> LIMIT 50
### and it reutrns a json(table) with the information of netstat info of the connections 
### also we can query for only the listening connections, with:
> SELECT * FROM netstat()
> WHERE Status =~ "Listen"
> LIMITE 50
### and also join with some pid (processes' connections)
> SELECT Laddr, Pid, Timestmap, {
> 	SELECT * FROM pslist(pid=Pid)}
> FROM netstat()
> WHERE Status =~ "Listen"
> LIMITE 50.

## User that executes a process:
> SELECT Laddr, Pid, Timestmap, {
> 	SELECT Exe, Username, CommandLine FROM pslist(pid=Pid)}
> FROM netstat()
> WHERE Status =~ "Listen"
> LIMITE 50.

## Linked DLLs
> SELECT Laddr, Pid, Timestmap, {
> 	SELECT Exe, Username, CommandLine FROM pslist(pid=Pid)}
> } as ProcessInfo, {
>	SELECT ExePath FROM modules(pid=Pid)
> } as LinkedDlls
> FROM netstat()
> WHERE Status =~ "Listen"
> LIMITE 50.

## Manufacturer is available
> SELECT Laddr, Pid, Timestmap, {
> 	SELECT Exe, parse_pe(file=Exe).VersionInformation AS VersionInformation,
> 		Username, CommandLine FROM pslist(pid=Pid)}
> } as ProcessInfo, {
>	SELECT ExePath FROM modules(pid=Pid)
> } as LinkedDlls
> FROM netstat()
> WHERE Status =~ "Listen"
> LIMITE 50.

## Signature if valid
### Plugin: authenticode (filename)
> SELECT Laddr, Pid, Timestmap, {
> 	SELECT Exe, parse_pe(file=Exe).VersionInformation AS VersionInformation,
>		authenticode(filename=Exe),
> 		Username, CommandLine FROM pslist(pid=Pid)}
> } as ProcessInfo, {
>	SELECT ExePath FROM modules(pid=Pid)
> } as LinkedDlls
> FROM netstat()
> WHERE Status =~ "Listen"
> LIMITE 50.

## Format data
### We can format some data in order to get them in better way (more representable)
> SELECT format(format="%v:%v", args=[Laddr.IP, Laddr.Port]), 
>		Pid, Timestmap, {
> 	SELECT Exe, parse_pe(file=Exe).VersionInformation AS VersionInformation,
> 		Username, CommandLine FROM pslist(pid=Pid)}
> } as ProcessInfo, {
>	SELECT ExePath FROM modules(pid=Pid)
> } as LinkedDlls
> FROM netstat()
> WHERE Status =~ "Listen"
> LIMITE 50.

### [%v : value, %T : time]

## Artifact plugin: we can use an artifact in VQL notebook by using the Artifact(arg=artifactName) plugin.
 
## IF plugin.
> SELECT * FROM if(
>	condition= query of value,
>	then={sub query},
>	else={sub query}	
> )

## EVENT QUERIES
### A plugin that returns data for indefinite time (or too long), is considered an event.

# Client Monitoring architecture

### The client mantains a set of vql event queries in parallel, if any row is produced, the client
### sends them to the server which saves them in the filestore. If the client is offline, this data will
### be stored in a local file buffer. 


























































