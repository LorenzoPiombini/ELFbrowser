# ELF browser

Nothing new here, is just a simple C program that browse the ELF(Executable and Linkable Format) file used in Unix system.

this is just a mere study, to understand the vulnerability of a system, and the security implication.


### What the program does

is simply **inject** an istrunction (reboot) in an executable, and if the user run it, with sudo privileges, than this would reboot your unix system. 
this is fairly harmles and dangerous at the same time.
the program browses the ELF structure to find the `.text` section where the machine code instructions seats.
you can acctually target any section in the program, in the funciton `browse_header()`, you can pass the program that you want to target, and the section that you want to inject your shell code in.

## How to test it 

you have to source C files in this repo. you can build your target from hello.c:
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

# BE CAREFUL 
this is a study, aimed to understand how attackers can manipulate programs to take advange of your system.
it can be dangerous to play around with this stuff. you should use a virtual machine to run this, if you decided to experiment from this project 








