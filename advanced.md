# Advanced Settings  
##Console Output  
###You want to change the text size of output?  
No problem! Type `set font_size 14.5`, where you replace 14.5 with your own preferered text size and hit enter.  
###Doesn't want to see any messages about warnings?
You can disable it. Just follow through this block of commands:  
`logger up` - Enable the log manager service  
`logger` - Enter the interactive mode of log manager  
`set output_data error service, request, response` - Set the output data types to be printed (see how warning is not included!)  
`exit` - to eyit out of log manager interactive mode.  
And that's it warning messages doesn't get printed out!
For more help on output data types type `help param Log Levels` 
###You want to save the output to a file?  
You can do it!  
Type
`logger up` - Enable the log manager  
`logger` - Enter the interactive mode of log manager  
`set file_logger up` - Enable the file logging service (for more help on states of services type `help param state`)  
`set file_path example.txt` - Where example.txt is your choice of file name, set the file path to save the output to.  
`exit` - Exit interactive mode  
And it's completed.  
You can read your new log file under the *Logs* folder.  
##Server Stuff
###Unstable server?  
Maybe the pending connection limit is not high enough for your setup!  
Try setting it higher, type:  
`set pending_limit 100` - Set the pending connection limit to 100, where 100 is your desired connection limit.  
Check if the server run's better like this!  
###How to stop the server without exit?  
Simple, just type `stop` and the server will no longer run!  
###Fear of hitting exitting accidentally?  
Fear no more! Typing `exit` while the server is running will cause the console to prompt you a question, which you can cancel, to keep running  
###Not sure about a command?  
Just type `help [command]` - Where [command] is your choice of command.  
You can use `help param [parameter]` - where [parameter] is your choice of parameter, to get help about a parameter of a command
