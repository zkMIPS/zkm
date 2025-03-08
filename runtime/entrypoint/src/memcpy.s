// This is musl-libc commit 3b0a370020c4d5b80ff32a609e5322b7760f0dc4:
// 
// src/string/memcpy.c
// 
// This was compiled into assembly with:
// 
// clang -target mips -O3 -S memcpy.c -nostdlib -fno-builtin -funroll-loops
// 
// and labels manually updated to not conflict.
// 
// musl as a whole is licensed under the following standard MIT license:
// 
// ----------------------------------------------------------------------
// Copyright © 2005-2020 Rich Felker, et al.
// 
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// ----------------------------------------------------------------------
// 
// Authors/contributors include:
// 
// A. Wilcox
// Ada Worcester
// Alex Dowad
// Alex Suykov
// Alexander Monakov
// Andre McCurdy
// Andrew Kelley
// Anthony G. Basile
// Aric Belsito
// Arvid Picciani
// Bartosz Brachaczek
// Benjamin Peterson
// Bobby Bingham
// Boris Brezillon
// Brent Cook
// Chris Spiegel
// Clément Vasseur
// Daniel Micay
// Daniel Sabogal
// Daurnimator
// David Carlier
// David Edelsohn
// Denys Vlasenko
// Dmitry Ivanov
// Dmitry V. Levin
// Drew DeVault
// Emil Renner Berthing
// Fangrui Song
// Felix Fietkau
// Felix Janda
// Gianluca Anzolin
// Hauke Mehrtens
// He X
// Hiltjo Posthuma
// Isaac Dunham
// Jaydeep Patil
// Jens Gustedt
// Jeremy Huntwork
// Jo-Philipp Wich
// Joakim Sindholt
// John Spencer
// Julien Ramseier
// Justin Cormack
// Kaarle Ritvanen
// Khem Raj
// Kylie McClain
// Leah Neukirchen
// Luca Barbato
// Luka Perkov
// M Farkas-Dyck (Strake)
// Mahesh Bodapati
// Markus Wichmann
// Masanori Ogino
// Michael Clark
// Michael Forney
// Mikhail Kremnyov
// Natanael Copa
// Nicholas J. Kain
// orc
// Pascal Cuoq
// Patrick Oppenlander
// Petr Hosek
// Petr Skocik
// Pierre Carrier
// Reini Urban
// Rich Felker
// Richard Pennington
// Ryan Fairfax
// Samuel Holland
// Segev Finer
// Shiz
// sin
// Solar Designer
// Stefan Kristiansson
// Stefan O'Rear
// Szabolcs Nagy
// Timo Teräs
// Trutz Behn
// Valentin Ochs
// Will Dietz
// William Haddon
// William Pitcock
// 
// Portions of this software are derived from third-party works licensed
// under terms compatible with the above MIT license:
// 
// The TRE regular expression implementation (src/regex/reg* and
// src/regex/tre*) is Copyright © 2001-2008 Ville Laurikari and licensed
// under a 2-clause BSD license (license text in the source files). The
// included version has been heavily modified by Rich Felker in 2012, in
// the interests of size, simplicity, and namespace cleanliness.
// 
// Much of the math library code (src/math/* and src/complex/*) is
// Copyright © 1993,2004 Sun Microsystems or
// Copyright © 2003-2011 David Schultz or
// Copyright © 2003-2009 Steven G. Kargl or
// Copyright © 2003-2009 Bruce D. Evans or
// Copyright © 2008 Stephen L. Moshier or
// Copyright © 2017-2018 Arm Limited
// and labelled as such in comments in the individual source files. All
// have been licensed under extremely permissive terms.
// 
// The ARM memcpy code (src/string/arm/memcpy.S) is Copyright © 2008
// The Android Open Source Project and is licensed under a two-clause BSD
// license. It was taken from Bionic libc, used on Android.
// 
// The AArch64 memcpy and memset code (src/string/aarch64/*) are
// Copyright © 1999-2019, Arm Limited.
// 
// The implementation of DES for crypt (src/crypt/crypt_des.c) is
// Copyright © 1994 David Burren. It is licensed under a BSD license.
// 
// The implementation of blowfish crypt (src/crypt/crypt_blowfish.c) was
// originally written by Solar Designer and placed into the public
// domain. The code also comes with a fallback permissive license for use
// in jurisdictions that may not recognize the public domain.
// 
// The smoothsort implementation (src/stdlib/qsort.c) is Copyright © 2011
// Valentin Ochs and is licensed under an MIT-style license.
// 
// The x86_64 port was written by Nicholas J. Kain and is licensed under
// the standard MIT terms.
// 
// The mips and microblaze ports were originally written by Richard
// Pennington for use in the ellcc project. The original code was adapted
// by Rich Felker for build system and code conventions during upstream
// integration. It is licensed under the standard MIT terms.
// 
// The mips64 port was contributed by Imagination Technologies and is
// licensed under the standard MIT terms.
// 
// The powerpc port was also originally written by Richard Pennington,
// and later supplemented and integrated by John Spencer. It is licensed
// under the standard MIT terms.
// 
// All other files which have no copyright comments are original works
// produced specifically for use as part of this library, written either
// by Rich Felker, the main author of the library, or by one or more
// contibutors listed above. Details on authorship of individual files
// can be found in the git version control history of the project. The
// omission of copyright and license comments in each file is in the
// interest of source tree size.
// 
// In addition, permission is hereby granted for all public header files
// (include/* and arch/* /bits/* ) and crt files intended to be linked into
// applications (crt/*, ldso/dlstart.c, and arch/* /crt_arch.h) to omit
// the copyright notice and permission notice otherwise required by the
// license, and to use these files without any requirement of
// attribution. These files include substantial contributions from:
// 
// Bobby Bingham
// John Spencer
// Nicholas J. Kain
// Rich Felker
// Richard Pennington
// Stefan Kristiansson
// Szabolcs Nagy
// 
// all of whom have explicitly granted such permission.
// 
// This file previously contained text expressing a belief that most of
// the files covered by the above exception were sufficiently trivial not
// to be subject to copyright, resulting in confusion over whether it
// negated the permissions granted in the license. In the spirit of
// permissive licensing, and of not having licensing issues being an
// obstacle to adoption, that text has been removed.
	.text
	.file	"memcpy.c"
	.globl	memcpy                 # -- Begin function memcpy
	.p2align	2
	.type	memcpy,@function
	.set	nomicromips
	.set	nomips16
	.ent	memcpy
memcpy:                                # @memcpy
	.frame	$fp,8,$ra
	.mask 	0xc0000000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.set	noat
# %bb.0:
	addiu	$sp, $sp, -8
	sw	$ra, 4($sp)                     # 4-byte Folded Spill
	sw	$fp, 0($sp)                     # 4-byte Folded Spill
	move	$fp, $sp
	andi	$1, $5, 3
	beqz	$1, $BB0_15
	nop
# %bb.1:
	beqz	$6, $BB0_6
	nop
# %bb.2:
	addiu	$3, $5, 1
	addiu	$7, $zero, 1
	move	$2, $4
$BB0_3:                                 # =>This Inner Loop Header: Depth=1
	lbu	$1, 0($5)
	move	$8, $6
	addiu	$6, $6, -1
	addiu	$5, $5, 1
	sb	$1, 0($2)
	andi	$1, $3, 3
	beqz	$1, $BB0_7
	addiu	$2, $2, 1
# %bb.4:                                #   in Loop: Header=BB0_3 Depth=1
	bne	$8, $7, $BB0_3
	addiu	$3, $3, 1
# %bb.5:
	j	$BB0_7
	nop
$BB0_6:
	move	$2, $4
$BB0_7:
	andi	$7, $2, 3
	beqz	$7, $BB0_16
	nop
$BB0_8:
	sltiu	$1, $6, 32
	bnez	$1, $BB0_31
	nop
# %bb.9:
	lw	$3, 0($5)
	addiu	$1, $zero, 3
	beq	$7, $1, $BB0_28
	nop
# %bb.10:
	addiu	$1, $zero, 2
	bne	$7, $1, $BB0_36
	nop
# %bb.11:
	srl	$7, $3, 16
	srl	$1, $3, 24
	addiu	$5, $5, 16
	addiu	$6, $6, -2
	sb	$7, 1($2)
	addiu	$7, $2, 2
	sb	$1, 0($2)
$BB0_12:                                # =>This Inner Loop Header: Depth=1
	lw	$2, -12($5)
	srl	$1, $3, 16
	addiu	$8, $5, 16
	addiu	$6, $6, -16
	sll	$3, $2, 16
	or	$1, $3, $1
	lw	$3, -8($5)
	sw	$1, 0($7)
	srl	$1, $2, 16
	addiu	$2, $7, 16
	sll	$9, $3, 16
	or	$1, $9, $1
	sltiu	$9, $6, 18
	sw	$1, 4($7)
	srl	$1, $3, 16
	lw	$3, -4($5)
	sll	$10, $3, 16
	or	$1, $10, $1
	sw	$1, 8($7)
	srl	$1, $3, 16
	lw	$3, 0($5)
	sll	$5, $3, 16
	or	$1, $5, $1
	move	$5, $8
	sw	$1, 12($7)
	beqz	$9, $BB0_12
	move	$7, $2
# %bb.13:
	sltiu	$1, $6, 16
	beqz	$1, $BB0_39
	addiu	$5, $8, -14
# %bb.14:
	j	$BB0_32
	nop
$BB0_15:
	move	$2, $4
	andi	$7, $2, 3
	bnez	$7, $BB0_8
	nop
$BB0_16:
	sltiu	$1, $6, 16
	bnez	$1, $BB0_23
	nop
$BB0_17:                                # =>This Inner Loop Header: Depth=1
	lw	$1, 0($5)
	addiu	$3, $2, 16
	addiu	$7, $5, 16
	addiu	$6, $6, -16
	sw	$1, 0($2)
	lw	$1, 4($5)
	sw	$1, 4($2)
	lw	$1, 8($5)
	sw	$1, 8($2)
	lw	$1, 12($5)
	move	$5, $7
	sw	$1, 12($2)
	sltiu	$1, $6, 16
	beqz	$1, $BB0_17
	move	$2, $3
# %bb.18:
	sltiu	$1, $6, 8
	beqz	$1, $BB0_24
	nop
$BB0_19:
	andi	$1, $6, 4
	bnez	$1, $BB0_25
	nop
$BB0_20:
	andi	$1, $6, 2
	bnez	$1, $BB0_26
	nop
$BB0_21:
	andi	$1, $6, 1
	beqz	$1, $BB0_45
	nop
# %bb.22:
	j	$BB0_44
	nop
$BB0_23:
	move	$3, $2
	sltiu	$1, $6, 8
	bnez	$1, $BB0_19
	move	$7, $5
$BB0_24:
	lw	$1, 0($7)
	sw	$1, 0($3)
	lw	$1, 4($7)
	addiu	$7, $7, 8
	sw	$1, 4($3)
	andi	$1, $6, 4
	beqz	$1, $BB0_20
	addiu	$3, $3, 8
$BB0_25:
	lw	$1, 0($7)
	addiu	$7, $7, 4
	sw	$1, 0($3)
	andi	$1, $6, 2
	beqz	$1, $BB0_21
	addiu	$3, $3, 4
$BB0_26:
	lbu	$1, 0($7)
	sb	$1, 0($3)
	lbu	$1, 1($7)
	addiu	$7, $7, 2
	sb	$1, 1($3)
	andi	$1, $6, 1
	beqz	$1, $BB0_45
	addiu	$3, $3, 2
# %bb.27:
	j	$BB0_44
	nop
$BB0_28:
	srl	$1, $3, 24
	addiu	$5, $5, 16
	addiu	$6, $6, -1
	addiu	$7, $2, 1
	sb	$1, 0($2)
$BB0_29:                                # =>This Inner Loop Header: Depth=1
	lw	$2, -12($5)
	srl	$1, $3, 8
	addiu	$8, $5, 16
	addiu	$6, $6, -16
	sll	$3, $2, 24
	or	$1, $3, $1
	lw	$3, -8($5)
	sw	$1, 0($7)
	srl	$1, $2, 8
	addiu	$2, $7, 16
	sll	$9, $3, 24
	or	$1, $9, $1
	sltiu	$9, $6, 19
	sw	$1, 4($7)
	srl	$1, $3, 8
	lw	$3, -4($5)
	sll	$10, $3, 24
	or	$1, $10, $1
	sw	$1, 8($7)
	srl	$1, $3, 8
	lw	$3, 0($5)
	sll	$5, $3, 24
	or	$1, $5, $1
	move	$5, $8
	sw	$1, 12($7)
	beqz	$9, $BB0_29
	move	$7, $2
# %bb.30:
	addiu	$5, $8, -15
$BB0_31:
	sltiu	$1, $6, 16
	beqz	$1, $BB0_39
	nop
$BB0_32:
	move	$3, $2
	andi	$1, $6, 8
	beqz	$1, $BB0_40
	move	$7, $5
$BB0_33:
	lbu	$1, 0($7)
	addiu	$2, $3, 8
	sb	$1, 0($3)
	lbu	$1, 1($7)
	sb	$1, 1($3)
	lbu	$1, 2($7)
	sb	$1, 2($3)
	lbu	$1, 3($7)
	sb	$1, 3($3)
	lbu	$1, 4($7)
	sb	$1, 4($3)
	lbu	$1, 5($7)
	sb	$1, 5($3)
	lbu	$1, 6($7)
	sb	$1, 6($3)
	lbu	$1, 7($7)
	sb	$1, 7($3)
	andi	$1, $6, 4
	beqz	$1, $BB0_41
	addiu	$5, $7, 8
$BB0_34:
	lbu	$1, 0($5)
	addiu	$3, $2, 4
	sb	$1, 0($2)
	lbu	$1, 1($5)
	sb	$1, 1($2)
	lbu	$1, 2($5)
	sb	$1, 2($2)
	lbu	$1, 3($5)
	sb	$1, 3($2)
	andi	$1, $6, 2
	beqz	$1, $BB0_43
	addiu	$7, $5, 4
# %bb.35:
	j	$BB0_42
	nop
$BB0_36:
	srl	$8, $3, 8
	srl	$7, $3, 16
	srl	$1, $3, 24
	addiu	$5, $5, 16
	addiu	$6, $6, -3
	sb	$8, 2($2)
	sb	$7, 1($2)
	addiu	$7, $2, 3
	sb	$1, 0($2)
$BB0_37:                                # =>This Inner Loop Header: Depth=1
	lw	$2, -12($5)
	srl	$1, $3, 24
	addiu	$8, $5, 16
	addiu	$6, $6, -16
	sll	$3, $2, 8
	or	$1, $3, $1
	lw	$3, -8($5)
	sw	$1, 0($7)
	srl	$1, $2, 24
	addiu	$2, $7, 16
	sll	$9, $3, 8
	or	$1, $9, $1
	sltiu	$9, $6, 17
	sw	$1, 4($7)
	srl	$1, $3, 24
	lw	$3, -4($5)
	sll	$10, $3, 8
	or	$1, $10, $1
	sw	$1, 8($7)
	srl	$1, $3, 24
	lw	$3, 0($5)
	sll	$5, $3, 8
	or	$1, $5, $1
	move	$5, $8
	sw	$1, 12($7)
	beqz	$9, $BB0_37
	move	$7, $2
# %bb.38:
	sltiu	$1, $6, 16
	bnez	$1, $BB0_32
	addiu	$5, $8, -13
$BB0_39:
	lbu	$1, 0($5)
	addiu	$3, $2, 16
	sb	$1, 0($2)
	lbu	$1, 1($5)
	sb	$1, 1($2)
	lbu	$1, 2($5)
	sb	$1, 2($2)
	lbu	$1, 3($5)
	sb	$1, 3($2)
	lbu	$1, 4($5)
	sb	$1, 4($2)
	lbu	$1, 5($5)
	sb	$1, 5($2)
	lbu	$1, 6($5)
	sb	$1, 6($2)
	lbu	$1, 7($5)
	sb	$1, 7($2)
	lbu	$1, 8($5)
	sb	$1, 8($2)
	lbu	$1, 9($5)
	sb	$1, 9($2)
	lbu	$1, 10($5)
	sb	$1, 10($2)
	lbu	$1, 11($5)
	sb	$1, 11($2)
	lbu	$1, 12($5)
	sb	$1, 12($2)
	lbu	$1, 13($5)
	sb	$1, 13($2)
	lbu	$1, 14($5)
	sb	$1, 14($2)
	lbu	$1, 15($5)
	sb	$1, 15($2)
	andi	$1, $6, 8
	bnez	$1, $BB0_33
	addiu	$7, $5, 16
$BB0_40:
	move	$2, $3
	andi	$1, $6, 4
	bnez	$1, $BB0_34
	move	$5, $7
$BB0_41:
	move	$3, $2
	andi	$1, $6, 2
	beqz	$1, $BB0_43
	move	$7, $5
$BB0_42:
	lbu	$1, 0($7)
	sb	$1, 0($3)
	lbu	$1, 1($7)
	addiu	$7, $7, 2
	sb	$1, 1($3)
	addiu	$3, $3, 2
$BB0_43:
	andi	$1, $6, 1
	beqz	$1, $BB0_45
	nop
$BB0_44:
	lbu	$1, 0($7)
	sb	$1, 0($3)
$BB0_45:
	move	$2, $4
	move	$sp, $fp
	lw	$fp, 0($sp)                     # 4-byte Folded Reload
	lw	$ra, 4($sp)                     # 4-byte Folded Reload
	jr	$ra
	addiu	$sp, $sp, 8
	.set	at
	.set	macro
	.set	reorder
	.end	memcpy
$func_end0:
	.size	memcpy, ($func_end0)-memcpy
                                        # -- End function
	.ident	"Ubuntu clang version 18.1.3 (1ubuntu1)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
