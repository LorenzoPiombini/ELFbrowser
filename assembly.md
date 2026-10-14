# Assembly notes

we need to write assembly to inject shellcode in the target.
we can use assembly to create an executable, and then we use objdump to see the binary code,
which it will become our shell code.


# System call in assembly
this is the structure to perform system calls in 

## assembly(`AMD x86_64`)
```assembly
    mov eax, NUMBER     ; syscall number
    mov rdi, ARG1       ; 1st argument
    mov rsi, ARG2       ; 2nd argument
    mov rdx, ARG3       ; 3rd argument
    mov r10, ARG4       ; 4th argument (not rcx!)
    mov r8,  ARG5       ; 5th argument
    mov r9,  ARG6       ; 6th argument
    syscall             ; result comes back in rax
```

## assembly(`AMD x86_32`)
```assembly
    mov eax, NUMBER     ; syscall number
    mov ebx, ARG1       ; 1st argument
    mov ecx, ARG2       ; 2nd argument
    mov edx, ARG3       ; 3rd argument
    mov esi, ARG4       ; 4th argument
    mov edi, ARG5       ; 5th argument
    mov ebp, ARG6       ; 6th argument
    int 0x80            ; result comes back in eax
```

the number of system calls chage according to the architecture

