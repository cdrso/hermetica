section .text
global aesni_encrypt_block

    ; &input_block in rdi
    ; &output_block in rsi
    ; &round keys in rdx
aesni_encrypt_block:
    ; Copy input block into xmm15
    movdqu xmm15, [rdi]

    pxor xmm15, [rsi] ; Whitening step (Round 0)
    aesenc xmm15, [rsi + 16] ; Round 1
    aesenc xmm15, [rsi + 32] ; Round 2
    aesenc xmm15, [rsi + 48] ; Round 3
    aesenc xmm15, [rsi + 64] ; Round 4
    aesenc xmm15, [rsi + 80] ; Round 5
    aesenc xmm15, [rsi + 96] ; Round 6
    aesenc xmm15, [rsi + 112] ; Round 7
    aesenc xmm15, [rsi + 128] ; Round 8
    aesenc xmm15, [rsi + 144] ; Round 9
    aesenclast xmm15, [rsi + 160] ; Round 10

    ; In the end, xmm15 holds the encryption result.
    movdqu [rsi], xmm15

    ; Return from function
    ret
