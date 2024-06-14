section .text
global aesni_encrypt_block

    ; &input_block in rdi
    ; &output_block in rsi
    ; &round_keys in rdx
aesni_encrypt_block:
    ; Copy input_block into xmm15
    movdqu     xmm15, [rdi]

    ; Copy round_keys into xmm0-10
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

    pxor       xmm15, xmm0 ; Whitening step (Round 0)
    aesenc     xmm15, xmm1 ; Round 1
    aesenc     xmm15, xmm2 ; Round 2
    aesenc     xmm15, xmm3 ; Round 3
    aesenc     xmm15, xmm4 ; Round 4
    aesenc     xmm15, xmm5 ; Round 5
    aesenc     xmm15, xmm6 ; Round 6
    aesenc     xmm15, xmm7 ; Round 7
    aesenc     xmm15, xmm8 ; Round 8
    aesenc     xmm15, xmm9 ; Round 9
    aesenclast xmm15, xmm10 ; Round 10

    ; In the end, xmm15 holds the encryption result.
    movdqu     [rsi], xmm15

    ; Return from function
    ret
