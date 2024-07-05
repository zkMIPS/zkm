// This is musl-libc commit 3b0a370020c4d5b80ff32a609e5322b7760f0dc4:
// 
// src/string/memcpy.c
// 
// This was compiled into assembly with:
// 
// clang-10 -target mips -O3 -S memcpy.c -nostdlib -fno-builtin -funroll-loops
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
	.globl	memccpy                 # -- Begin function memccpy
	.p2align	2
	.type	memccpy,@function
	.set	nomicromips
	.set	nomips16
	.ent	memccpy
memccpy:                                # @memccpy
	.frame	$fp,8,$ra
	.mask 	0xc0000000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.set	noat
# %bb.0:
	addiu	$sp, $sp, -8
	sw	$ra, 4($sp)             # 4-byte Folded Spill
	sw	$fp, 0($sp)             # 4-byte Folded Spill
	move	$fp, $sp
	xor	$1, $5, $4
	andi	$1, $1, 3
	beqz	$1, $BBmemcpy0_7
	andi	$3, $6, 255
$BBmemcpy0_1:
	beqz	$7, $BBmemcpy0_5
	nop
# %bb.2:
	addiu	$2, $4, 1
$BBmemcpy0_3:                                 # =>This Inner Loop Header: Depth=1
	lbu	$1, 0($5)
	beq	$1, $3, $BBmemcpy0_6
	sb	$1, -1($2)
# %bb.4:                                #   in Loop: Header=BBmemcpy0_3 Depth=1
	addiu	$2, $2, 1
	addiu	$7, $7, -1
	bnez	$7, $BBmemcpy0_3
	addiu	$5, $5, 1
$BBmemcpy0_5:
	addiu	$2, $zero, 0
$BBmemcpy0_6:
	move	$sp, $fp
	lw	$fp, 0($sp)             # 4-byte Folded Reload
	lw	$ra, 4($sp)             # 4-byte Folded Reload
	jr	$ra
	addiu	$sp, $sp, 8
$BBmemcpy0_7:
	andi	$6, $5, 3
	beqz	$7, $BBmemcpy0_14
	sltu	$2, $zero, $6
# %bb.8:
	beqz	$6, $BBmemcpy0_14
	nop
# %bb.9:
	addiu	$2, $7, -1
	addiu	$6, $zero, 0
$BBmemcpy0_10:                                # =>This Inner Loop Header: Depth=1
	addu	$9, $5, $6
	addu	$8, $4, $6
	lbu	$1, 0($9)
	beq	$1, $3, $BBmemcpy0_22
	sb	$1, 0($8)
# %bb.11:                               #   in Loop: Header=BBmemcpy0_10 Depth=1
	addiu	$1, $9, 1
	addiu	$8, $6, 1
	beq	$2, $6, $BBmemcpy0_13
	andi	$9, $1, 3
# %bb.12:                               #   in Loop: Header=BBmemcpy0_10 Depth=1
	bnez	$9, $BBmemcpy0_10
	move	$6, $8
$BBmemcpy0_13:
	sltu	$2, $zero, $9
	subu	$7, $7, $8
	addu	$4, $4, $8
	addu	$5, $5, $8
$BBmemcpy0_14:
	beqz	$2, $BBmemcpy0_17
	nop
# %bb.15:
	bnez	$7, $BBmemcpy0_6
	addiu	$2, $4, 1
# %bb.16:
	j	$BBmemcpy0_5
	nop
$BBmemcpy0_17:
	sltiu	$1, $7, 4
	bnez	$1, $BBmemcpy0_1
	nop
# %bb.18:
	sll	$1, $3, 8
	sll	$2, $3, 16
	or	$1, $1, $3
	or	$1, $2, $1
	sll	$2, $3, 24
	or	$6, $2, $1
	lui	$1, 65278
	andi	$2, $7, 3
	ori	$8, $1, 65279
	lui	$1, 32896
	ori	$9, $1, 32896
$BBmemcpy0_19:                                # =>This Inner Loop Header: Depth=1
	lw	$10, 0($5)
	xor	$1, $10, $6
	addu	$11, $1, $8
	not	$1, $1
	and	$1, $1, $11
	and	$1, $1, $9
	bnez	$1, $BBmemcpy0_1
	nop
# %bb.20:                               #   in Loop: Header=BBmemcpy0_19 Depth=1
	addiu	$7, $7, -4
	sw	$10, 0($4)
	addiu	$4, $4, 4
	sltiu	$1, $7, 4
	beqz	$1, $BBmemcpy0_19
	addiu	$5, $5, 4
# %bb.21:
	j	$BBmemcpy0_1
	move	$7, $2
$BBmemcpy0_22:
	j	$BBmemcpy0_6
	addiu	$2, $8, 1
	.set	at
	.set	macro
	.set	reorder
	.end	memccpy
$memcpy_func_end0:
	.size	memccpy, ($memcpy_func_end0)-memccpy
                                        # -- End function
	.ident	"clang version 10.0.0-4ubuntu1 "
	.section	".note.GNU-stack","",@progbits
	.addrsig