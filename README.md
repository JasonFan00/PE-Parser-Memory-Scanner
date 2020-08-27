# PE-Parser-Memory-Scanner
One of my first "significant" learning projects.  The code is probably a mess, and there's much more I could understand about the PE format (and window apps in general), but a lot of what I learned from this project formed the basis for my future.

A windows console application I made that parses the portable executable file format and scans the data segment for an inputted int value.

Picks apart the MS-PE file format of an external running process and scans the global variable data segment for a inputted integer value, and gives the option to write to that value. All you need to do is give it the external process's ID (can get it from task manager or my process explorer application!) and a value to scan for, and if there are any matches, a override value. I made this in C++ and the windows API.

This program opens handles to other processes, so it needs certain privileges if a process is protected. Currently it scans for integer values, however that can be easily changed. I made this solely as a demonstration and to improve my knowledge, so an actual debugger would be more useful than this. I got the idea of this program when looking into how video game hackers created their "tools".

To test I made a simple dummy console application with a global integer variable. 
