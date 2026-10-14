# System call in assembly


this is the structure to perform system calls in assembly(`AMD x86_64`)

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


