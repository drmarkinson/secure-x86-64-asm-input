; secure_read.asm
; NASM x86-64 Linux Assembly
; Translates the complete C secure_input.c logic to low-level assembly
; Uses Linux syscalls: sys_read (0), sys_write (1), sys_exit (60)

; ============================================================
; Function: secure_read_line
; Prototype: char *secure_read_line(char *buf, size_t size, FILE *stream)
;
; rdi = char *buf         (pointer to output buffer)
; rsi = size_t size       (buffer size in bytes)
; rdx = FILE *stream      (file descriptor: 0=stdin, 1=stdout, 2=stderr)
;
; Returns: rax = buf pointer on success, 0 (NULL) on error
; ============================================================

global secure_read_line
global secure_read_line_trimmed
global secure_read_bounded
global main

extern printf

section .data
    ; Prompts and messages
    prompt1     db "Enter your name (max 49 characters): ", 0
    prompt2     db "Enter your email (with trimming): ", 0
    prompt3     db "Enter a comment (max 100 characters): ", 0
    
    output_fmt  db "Hello, %s!", 10, 0
    email_fmt   db "Your email is: %s", 10, 0
    comment_fmt db "Comment (%d chars): %s", 10, 0
    error_fmt   db "Error: Invalid parameters to secure_read_line", 10, 0
    error_read  db "Error reading from stream", 10, 0
    warning_fmt db "Warning: Input was truncated to %zu characters", 10, 0
    success_msg db "=== Input reading completed successfully ===", 10, 0
    title_msg   db "=== Secure Input Reading Example ===", 10, 10, 0
    
    space_char  equ 32
    tab_char    equ 9
    cr_char     equ 13
    lf_char     equ 10

section .bss
    name_buf    resb 50
    email_buf   resb 100
    comment_buf resb 256

section .text

; ============================================================
; secure_read_line - Basic safe line reader
; ============================================================
secure_read_line:
    ; Input validation: check if buffer is NULL
    test rdi, rdi
    jz .read_line_fail
    
    ; Input validation: check if size is 0
    test rsi, rsi
    jz .read_line_fail
    
    ; Input validation: check if stream is valid (non-zero fd)
    test rdx, rdx
    jz .read_line_fail
    
    ; Save callee-saved registers
    push rbp
    push rbx
    push r12
    push r13
    push r14
    
    mov rbp, rsp
    sub rsp, 16              ; Local storage for temp variables
    
    mov r12, rdi             ; r12 = buf
    mov r13, rsi             ; r13 = size
    mov r14, rdx             ; r14 = fd (stream)
    
    ; Reduce size by 1 to leave room for null terminator
    dec r13
    jz .read_line_fail_cleanup
    
    ; --------- sys_read(fd, buf, size-1) ---------
    mov rax, 0               ; __NR_read = 0
    mov rdi, r14             ; fd
    mov rsi, r12             ; buf
    mov rdx, r13             ; size - 1
    syscall
    
    ; Check if read failed (rax < 0) or EOF (rax == 0)
    cmp rax, 0
    jle .read_line_eof_error
    
    mov rbx, rax             ; rbx = bytes actually read
    
    ; --------- Remove trailing newline ---------
    cmp rbx, 0
    je .add_null_term
    
    ; Check if last byte is '\n' (10)
    lea rcx, [r12 + rbx - 1]
    cmp byte [rcx], lf_char
    jne .add_null_term
    
    ; Found newline, replace with null
    mov byte [rcx], 0
    jmp .read_line_success
    
.add_null_term:
    ; Add null terminator after the data
    mov byte [r12 + rbx], 0
    
.read_line_success:
    mov rax, r12             ; return buf pointer
    add rsp, 16
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
    
.read_line_eof_error:
    ; Check if it's an actual error (rax < 0) or just EOF
    cmp rax, 0
    jl .read_line_error_sys
    ; Otherwise it's EOF, return NULL
    jmp .read_line_fail_cleanup
    
.read_line_error_sys:
    lea rdi, [error_read]
    xor rax, rax
    call printf
    
.read_line_fail_cleanup:
    add rsp, 16
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    
.read_line_fail:
    xor rax, rax             ; return NULL
    ret


; ============================================================
; secure_read_line_trimmed - Read and trim whitespace
; Removes leading and trailing whitespace
; ============================================================
secure_read_line_trimmed:
    ; Input validation
    test rdi, rdi
    jz .trim_fail
    test rsi, rsi
    jz .trim_fail
    test rdx, rdx
    jz .trim_fail
    
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi             ; r12 = buf
    mov r13, rsi             ; r13 = size
    mov r14, rdx             ; r14 = fd
    
    ; First, call secure_read_line to read the input
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    call secure_read_line
    
    test rax, rax
    jz .trim_fail_cleanup
    
    ; --------- Trim trailing whitespace ---------
    mov r15, rax             ; r15 = returned buffer
    xor rcx, rcx             ; rcx = length counter
    
.trim_trailing_loop:
    mov al, byte [r12 + rcx]
    test al, al
    jz .trim_trailing_done
    inc rcx
    jmp .trim_trailing_loop
    
.trim_trailing_done:
    ; rcx now contains string length (excluding null)
    mov r8, rcx              ; r8 = original length
    
    ; Trim from the end
.trim_trailing_back:
    cmp rcx, 0
    je .trim_leading_start
    
    dec rcx
    mov al, byte [r12 + rcx]
    
    ; Check if it's space (32), tab (9), or CR (13)
    cmp al, space_char
    je .trim_trailing_back
    cmp al, tab_char
    je .trim_trailing_back
    cmp al, cr_char
    je .trim_trailing_back
    
    ; Not whitespace, move to next byte position
    inc rcx
    mov byte [r12 + rcx], 0  ; null terminate
    
    ; --------- Trim leading whitespace ---------
.trim_leading_start:
    xor r9, r9               ; r9 = start position
    
.trim_leading_loop:
    mov al, byte [r12 + r9]
    test al, al
    jz .trim_done
    
    cmp al, space_char
    je .trim_leading_advance
    cmp al, tab_char
    je .trim_leading_advance
    
    jmp .trim_leading_end
    
.trim_leading_advance:
    inc r9
    jmp .trim_leading_loop
    
.trim_leading_end:
    ; If r9 > 0, we need to move data
    cmp r9, 0
    je .trim_done
    
    ; Move data forward by r9 bytes
    xor r10, r10             ; r10 = copy counter
    
.trim_leading_copy:
    mov al, byte [r12 + r9 + r10]
    mov byte [r12 + r10], al
    test al, al
    je .trim_done
    inc r10
    jmp .trim_leading_copy
    
.trim_done:
    mov rax, r12             ; return buf pointer
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
    
.trim_fail_cleanup:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    
.trim_fail:
    xor rax, rax             ; return NULL
    ret


; ============================================================
; secure_read_bounded - Read with explicit character limit
; int secure_read_bounded(char *buf, size_t max_chars, size_t buffer_size, FILE *stream)
;
; rdi = char *buf
; rsi = size_t max_chars
; rdx = size_t buffer_size
; rcx = FILE *stream (fd)
;
; Returns: rax = number of characters read, -1 on error
; ============================================================
secure_read_bounded:
    ; Input validation
    test rdi, rdi
    jz .bounded_fail
    test rdx, rdx
    jz .bounded_fail
    test rcx, rcx
    jz .bounded_fail
    
    ; Check if max_chars >= buffer_size - 1 (invalid)
    mov r8, rdx
    dec r8
    cmp rsi, r8
    jge .bounded_fail
    
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi             ; r12 = buf
    mov r13, rsi             ; r13 = max_chars
    mov r14, rdx             ; r14 = buffer_size
    mov r15, rcx             ; r15 = fd
    
    ; Calculate read_limit: min(max_chars + 1, buffer_size - 1)
    mov rax, r13
    inc rax                  ; max_chars + 1
    mov rbx, r14
    dec rbx                  ; buffer_size - 1
    
    cmp rax, rbx
    jle .bounded_limit_set
    mov rax, rbx             ; use smaller limit
    
.bounded_limit_set:
    ; rax now contains the read limit
    mov r8, rax              ; r8 = read_limit
    
    ; --------- sys_read(fd, buf, read_limit) ---------
    mov rax, 0               ; __NR_read = 0
    mov rdi, r15             ; fd
    mov rsi, r12             ; buf
    mov rdx, r8              ; read_limit
    syscall
    
    ; Check for errors
    cmp rax, 0
    jle .bounded_error
    
    mov r9, rax              ; r9 = bytes read
    
    ; --------- Remove trailing newline ---------
    lea r10, [r12 + r9 - 1]
    cmp byte [r10], lf_char
    jne .bounded_check_truncate
    
    mov byte [r10], 0        ; replace newline with null
    dec r9
    jmp .bounded_check_truncate
    
.bounded_check_truncate:
    ; Add null terminator
    mov byte [r12 + r9], 0
    
    ; Check if input exceeded max_chars
    cmp r9, r13
    jle .bounded_success
    
    ; Input was truncated - show warning
    mov rdi, warning_fmt
    mov rsi, r13
    xor rax, rax
    call printf
    
.bounded_success:
    mov rax, r9              ; return chars read
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
    
.bounded_error:
    mov eax, -1              ; return -1 on error
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
    
.bounded_fail:
    mov eax, -1              ; return -1 on invalid params
    ret


; ============================================================
; main - Demonstration of secure input functions
; ============================================================
main:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Print title
    lea rdi, [title_msg]
    xor rax, rax
    call printf
    
    ; --------- Example 1: Basic secure input for name ---------
    lea rdi, [prompt1]
    xor rax, rax
    call printf
    
    lea rdi, [name_buf]
    mov rsi, 50
    mov rdx, 0               ; fd = 0 (stdin)
    call secure_read_line
    
    test rax, rax
    jz .main_error1
    
    lea rdi, [output_fmt]
    mov rsi, rax
    xor rax, rax
    call printf
    
    ; --------- Example 2: Trimmed input for email ---------
    lea rdi, [prompt2]
    xor rax, rax
    call printf
    
    lea rdi, [email_buf]
    mov rsi, 100
    mov rdx, 0               ; fd = 0 (stdin)
    call secure_read_line_trimmed
    
    test rax, rax
    jz .main_error2
    
    lea rdi, [email_fmt]
    mov rsi, rax
    xor rax, rax
    call printf
    
    ; --------- Example 3: Bounded input for comment ---------
    lea rdi, [prompt3]
    xor rax, rax
    call printf
    
    lea rdi, [comment_buf]
    mov rsi, 100            ; max 100 chars
    mov rdx, 256            ; buffer size
    mov rcx, 0              ; fd = 0 (stdin)
    call secure_read_bounded
    
    cmp rax, -1
    je .main_error3
    
    mov r12, rax             ; save char count
    lea rdi, [comment_fmt]
    mov rsi, r12
    lea rdx, [comment_buf]
    xor rax, rax
    call printf
    
    ; Print success message
    lea rdi, [success_msg]
    xor rax, rax
    call printf
    
    xor eax, eax             ; return 0
    add rsp, 32
    pop rbp
    ret
    
.main_error1:
    lea rdi, [error_fmt]
    xor rax, rax
    call printf
    mov eax, 1
    add rsp, 32
    pop rbp
    ret
    
.main_error2:
    lea rdi, [error_fmt]
    xor rax, rax
    call printf
    mov eax, 1
    add rsp, 32
    pop rbp
    ret
    
.main_error3:
    lea rdi, [error_fmt]
    xor rax, rax
    call printf
    mov eax, 1
    add rsp, 32
    pop rbp
    ret
