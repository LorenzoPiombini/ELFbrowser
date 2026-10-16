# ELF vulnerability

Nothing new here, is just a simple C program that browse the ELF(Executable and Linkable Format) file used in Unix system.

this is just a mere study, to understand the vulnerability of a system, and the security implication.


### What the program does

#### `inject_instruction`

simply **injects** an istrunction inside an executable, you can choose one of the shellcode in include/bin.h.
if you use this function, you can acctually target any section in the program,pass the section you want to target in the host program as an agument.
this rudimental funtion works with all the ELF file, regardles the source code that the ELF was generated from. 

#### `inject_instruction_silent`
this is an expansion on the previous function, in the previous example the target will know right away that somenthing went wrong.
the `_silent` funcion is meant to inject the code but the host program will not change its beaviour, at list from the user point of view. 
it is also smarter because does not need Section header, if the host strip the section header form the ELF file, they still won't be safe. 
here we target the `.fini` section which is present at the end of `.text` in all executable made with a compiler,(at least so far, I've found that to be true).

## THE SILENT APPROACH
the former approach, let's call it the silent approach, opens up a big problem that I discover when targeting an ELF from a rust source code, during the compilation process some references got written in the binary code, and they point to the code that we are trying to inject in the executable, so there is a need to write code that inspect the binary istructions and when we find the code that lands to that offset, we need to overwrite those instruction to pointto our new offset.

I added the funciton to inspect the machine code, and is still crashing, so I am getting closer but is still not there.

## How to test it 

you have two source C files in this repo. you can build your target from hello.c:
```
gcc hello.c -o CIAO_pie
```

then you can build your injector program

```
gcc test.c
```

run the program
```
./a.out
```

now your `./CIAO_pie` is injected with the reboot instruction, and if you run it with super user privilegies, it will reboot your computer.

## The rust source code

just to experiment, I added the hello world equivalent in rust, once you compiled it with rustc, the executable is larger and different from the one generated from C source code,however is still an ELF file, so the injection, works on this executable as well.

## Why this

this force me to study a topic without using LLMs. 
asking LLMs how to make computer viruses, it is probably a bad idea.
The goals of this project are, learning, keep using C (clearly my favourite language), learning new cool stuff like assembly.
**THERE ARE NO BAD INTENTIONS** this is not a project aimed to create any harm to anybody.


# BE CAREFUL 
this is a study, aimed to understand how attackers can manipulate programs to take advange of your system.
is an exercise to understand how a computer works.
it can be dangerous to play around with this stuff. you should use a virtual machine to run this, if you decided to experiment from this project 








