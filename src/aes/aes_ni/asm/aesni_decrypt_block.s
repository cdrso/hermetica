section .text
global aesni_decrypt_block

    ; &input_block in rdi
    ; &output_block in rsi
    ; &key_schedule_decrypt in rdx
aesni_decrypt_block:
    ; Copy input_block into xmm15
    movdqu     xmm15, [rdi]

    ; Copy round keys into xmm0-10
    movdqu     xmm0,  [rdx]
    movdqu     xmm1,  [rdx + 16]
    movdqu     xmm2,  [rdx + 32]
    movdqu     xmm3,  [rdx + 48]
    movdqu     xmm4,  [rdx + 64]
    movdqu     xmm5,  [rdx + 80]
    movdqu     xmm6,  [rdx + 96]
    movdqu     xmm7,  [rdx + 112]
    movdqu     xmm8,  [rdx + 128]
    movdqu     xmm9,  [rdx + 144]
    movdqu     xmm10, [rdx + 160]

    pxor       xmm15, xmm10 ; First xor
    aesdec     xmm15, xmm9 ; Round 1 (consuming round keys in reverse order)
    aesdec     xmm15, xmm8 ; Round 2
    aesdec     xmm15, xmm7 ; Round 3
    aesdec     xmm15, xmm6 ; Round 4
    aesdec     xmm15, xmm5 ; Round 5
    aesdec     xmm15, xmm4 ; Round 6
    aesdec     xmm15, xmm3 ; Round 7
    aesdec     xmm15, xmm2 ; Round 8
    aesdec     xmm15, xmm1 ; Round 9
    aesdeclast xmm15, xmm0 ; Round 10

    ; In the end, xmm15 holds the encryption result.
    movdqu     [rsi], xmm15

    ; Return from function
    ret
