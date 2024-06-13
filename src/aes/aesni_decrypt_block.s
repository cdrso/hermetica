section .text
global aesni_decrypt_block

    ; &input_block in rdi
    ; &output_block in rsi
    ; &round keys in rdx
aesni_decrypt_block:
    ; Copy input block into xmm15
    movdqu xmm15, [rdi]

    movdqu xmm12, [rdx + 160]
    pxor xmm15, xmm12 ; First xor

    movdqu xmm11, [rdx + 144]
    aesimc xmm11, xmm11
    aesdec xmm15, xmm11 ; Round 1 (consuming round keys in reverse order)

    movdqu xmm10, [rdx + 128]
    aesimc xmm10, xmm10
    aesdec xmm15, xmm10 ; Round 2

    movdqu xmm9, [rdx + 112]
    aesimc xmm9, xmm9
    aesdec xmm15, xmm9 ; Round 3

    movdqu xmm8, [rdx + 96]
    aesimc xmm8, xmm8
    aesdec xmm15, xmm8 ; Round 4

    movdqu xmm7, [rdx + 80]
    aesimc xmm7, xmm7
    aesdec xmm15, xmm7 ; Round 5

    movdqu xmm6, [rdx + 64]
    aesimc xmm6, xmm6
    aesdec xmm15, xmm6 ; Round 6

    movdqu xmm5, [rdx + 48]
    aesimc xmm5, xmm5
    aesdec xmm15, xmm5 ; Round 7

    movdqu xmm4, [rdx + 32]
    aesimc xmm4, xmm4
    aesdec xmm15, xmm4 ; Round 8

    movdqu xmm3, [rdx + 16]
    aesimc xmm3, xmm3
    aesdec xmm15, xmm3 ; Round 9

    movdqu xmm2, [rdx]
    aesdeclast xmm15, xmm3 ; Round 10

    ; In the end, xmm15 holds the decryption result.
    movdqu [rsi], xmm15

    ; Return from function
    ret
