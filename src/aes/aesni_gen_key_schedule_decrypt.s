section .text
global aesni_gen_key_schedule_decrypt

    ; &key_schedule in rdi
    ; &key_schedule_decrypt in rsi
aesni_gen_key_schedule_decrypt:
    movdqu xmm1, [rdi]
    movdqu [rsi], xmm1
    add rdi, 0x10
    add rsi, 0x10

    mov ecx, 9 ; 9 for AES-128, 11 for AES-192, 13 for AES-256
    repeat_Nr_minus_one_times:
    movdqu xmm1, [rdi]
    aesimc xmm1, xmm1
    movdqu [rsi], xmm1
    add rdi, 0x10
    add rsi, 0x10
    loop repeat_Nr_minus_one_times
    movdqu xmm1, [rdi]
    movdqu [rsi], xmm1

    ret
