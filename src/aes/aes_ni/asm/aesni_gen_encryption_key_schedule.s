section .text
global aesni_gen_encryption_key_schedule

    ; &key in rdi
    ; &key_schedule in rsi
aesni_gen_encryption_key_schedule:
    ; Load the original 128-bit key from the address in rdi into xmm1
    movdqu xmm1, [rdi]

    ; Copy the initial key into the first 4 words of the key schedule
    movdqu [rsi], xmm1

    ; Set the offset in rcx for the next position in the key schedule
    ; (after the initial 4 words which is 16 bytes)
    lea rcx, [rsi + 16]

    ; Generate the subsequent key schedule words by calling key_expansion_128
    ; with aeskeygenassist providing necessary transformations.

    ; i = 4
    aeskeygenassist xmm2, xmm1, 0x1
    call _key_expansion_helper

    ; i = 8
    aeskeygenassist xmm2, xmm1, 0x2
    call _key_expansion_helper

    ; i = 12
    aeskeygenassist xmm2, xmm1, 0x4
    call _key_expansion_helper

    ; i = 16
    aeskeygenassist xmm2, xmm1, 0x8
    call _key_expansion_helper

    ; i = 20
    aeskeygenassist xmm2, xmm1, 0x10
    call _key_expansion_helper

    ; i = 24
    aeskeygenassist xmm2, xmm1, 0x20
    call _key_expansion_helper

    ; i = 28
    aeskeygenassist xmm2, xmm1, 0x40
    call _key_expansion_helper

    ; i = 32
    aeskeygenassist xmm2, xmm1, 0x80
    call _key_expansion_helper

    ; i = 36
    aeskeygenassist xmm2, xmm1, 0x1b
    call _key_expansion_helper

    ; i = 40
    aeskeygenassist xmm2, xmm1, 0x36
    call _key_expansion_helper

    ; return from function
    ret

_key_expansion_helper:
    ; Shuffle the bytes of xmm2 such that each 32-bit word in xmm2 is the same
    ; Corresponds to preparing the round constant and transformations
    pshufd xmm2, xmm2, 0xff

    ; Perform left logical shift by 4 bytes on xmm1 and store result in xmm3
    vpslldq xmm3, xmm1, 0x4

    ; XOR shifted xmm1 with original xmm1
    pxor xmm1, xmm3

    ; Repeat left logical shift by 4 bytes on xmm1 and XOR again
    vpslldq xmm3, xmm1, 0x4
    pxor xmm1, xmm3

    ; Repeat left logical shift by 4 bytes on xmm1 and XOR again
    vpslldq xmm3, xmm1, 0x4
    pxor xmm1, xmm3

    ; XOR xmm1 with the transformed round constant in xmm2
    pxor xmm1, xmm2

    ; Store the resulting 128-bit key into the key schedule at rcx location
    movdqu [rcx], xmm1

    ; Move the offset to the next position in the key schedule (next 16 bytes)
    add rcx, 0x10

    ; Return from the subroutine
    ret

