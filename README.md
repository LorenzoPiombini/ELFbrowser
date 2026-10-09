# ELF browser

Nothing new here, is just a simple C program that browse the ELF(Executable and Linkable Format) file used in Unix system.

this is just a mere study, to understand the vulnerability of a system, and the security implication

### What the program does

is simply **inject** an istrunction (reboot) in an executable, and if the user run it, with sudo privileges, than this would reboot your unix system. 
this is fairly harmles and dangerous at the same time.
the program browses the ELF structure to find the `.text` section where the machine code instructions seats.
you can acctually target any section in the program, in the funciton `browse_header()`, you can pass the program that you want to target, and the section that you want to inject your shell code in.






