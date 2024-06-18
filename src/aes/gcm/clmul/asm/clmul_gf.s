section .text
global clmul_gf

    ; &operand_1 in rdi
    ; &operand_2 in rsi
    ; &result in rdx
clmul_gf:
    ; operand_1 in xmm0
    movdqu      xmm0, [rdi]

    ; operand_2 in xmm1
    movdqu      xmm1, [rsi]

    movdqa      xmm3, xmm0
    pclmulqdq   xmm3, xmm1, 0
    movdqa      xmm4, xmm0
    pclmulqdq   xmm4, xmm1, 16
    movdqa      xmm5, xmm0
    pclmulqdq   xmm5, xmm1, 1
    movdqa      xmm6, xmm0
    pclmulqdq   xmm6, xmm1, 17
    pxor        xmm4, xmm5
    movdqa      xmm5, xmm4
    psrldq      xmm4, 8
    pslldq      xmm5, 8
    pxor        xmm3, xmm5
    pxor        xmm6, xmm4

    ; <xmm6:xmm3> holds the result of carry-less multiplication
    ; shift bits by 1 bit left due to bits being reversed
    movdqa      xmm7, xmm3
    movdqa      xmm8, xmm6
    pslld       xmm3, 1
    pslld       xmm6, 1
    psrld       xmm7, 31
    psrld       xmm8, 31
    movdqa      xmm9, xmm7
    pslldq      xmm8, 4
    pslldq      xmm7, 4
    psrldq      xmm9, 12
    por         xmm3, xmm7
    por         xmm6, xmm8
    por         xmm6, xmm9

    ; first phase of reduction
    movdqa      xmm7, xmm3
    movdqa      xmm8, xmm3
    movdqa      xmm9, xmm3
    pslld       xmm7, 31
    pslld       xmm8, 30,
    pslld       xmm9, 25
    pxor        xmm7, xmm8
    pxor        xmm7, xmm9
    movdqa      xmm8, xmm7
    pslldq      xmm7, 12
    psrldq      xmm8, 4

    ; second phase of reduction
    pxor        xmm3, xmm7
    movdqa      xmm2, xmm3
    movdqa      xmm4, xmm3
    movdqa      xmm5, xmm3
    psrld       xmm2, 1
    psrld       xmm4, 2
    psrld       xmm5, 7
    pxor        xmm2, xmm4
    pxor        xmm2, xmm5
    pxor        xmm2, xmm8
    pxor        xmm3, xmm2
    pxor        xmm6, xmm3

    ; return result stored in xmm6
    movdqu      [rdx], xmm6
    ret
