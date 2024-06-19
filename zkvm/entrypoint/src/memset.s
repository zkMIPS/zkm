// This is musl-libc memset commit 5613a1486e6a6fc3988be6561f41b07b2647d80f:
// 
// src/string/memset.c
// 
// This was compiled into assembly with:
// 
// clang10 -target mips -O3 -S memset.c -nostdlib -fno-builtin -funroll-loops
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
	.file	"memset.c"
	.globl	memset                  # -- Begin function memset
	.p2align	2
	.type	memset,@function
	.set	nomicromips
	.set	nomips16
	.ent	memset
memset:                                 # @memset
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
	beqz	$6, $BBmemset0_9
	nop
# %bb.1:
	addu	$2, $6, $4
	sltiu	$1, $6, 3
	sb	$5, 0($4)
	bnez	$1, $BBmemset0_9
	sb	$5, -1($2)
# %bb.2:
	sltiu	$1, $6, 7
	sb	$5, 2($4)
	sb	$5, 1($4)
	sb	$5, -3($2)
	bnez	$1, $BBmemset0_9
	sb	$5, -2($2)
# %bb.3:
	sltiu	$1, $6, 9
	sb	$5, 3($4)
	bnez	$1, $BBmemset0_9
	sb	$5, -4($2)
# %bb.4:
	andi	$2, $5, 255
	negu	$1, $4
	sll	$5, $2, 8
	sll	$7, $2, 16
	andi	$1, $1, 3
	or	$5, $5, $2
	sll	$2, $2, 24
	addu	$3, $4, $1
	subu	$1, $6, $1
	or	$5, $7, $5
	or	$2, $2, $5
	addiu	$5, $zero, -4
	and	$5, $1, $5
	sw	$2, 0($3)
	addu	$6, $3, $5
	sltiu	$1, $5, 9
	bnez	$1, $BBmemset0_9
	sw	$2, -4($6)
# %bb.5:
	sltiu	$1, $5, 25
	sw	$2, 8($3)
	sw	$2, 4($3)
	sw	$2, -8($6)
	bnez	$1, $BBmemset0_9
	sw	$2, -12($6)
# %bb.6:
	andi	$1, $3, 4
	sw	$2, 24($3)
	sw	$2, 20($3)
	sw	$2, 16($3)
	sw	$2, 12($3)
	sw	$2, -16($6)
	sw	$2, -20($6)
	sw	$2, -24($6)
	sw	$2, -28($6)
	ori	$6, $1, 24
	subu	$5, $5, $6
	sltiu	$1, $5, 32
	bnez	$1, $BBmemset0_9
	nop
# %bb.7:
	addu	$3, $3, $6
$BBmemset0_8:                                 # =>This Inner Loop Header: Depth=1
	addiu	$5, $5, -32
	sw	$2, 24($3)
	sw	$2, 16($3)
	sw	$2, 8($3)
	sw	$2, 0($3)
	sw	$2, 28($3)
	sw	$2, 20($3)
	sw	$2, 12($3)
	sw	$2, 4($3)
	sltiu	$1, $5, 32
	beqz	$1, $BBmemset0_8
	addiu	$3, $3, 32
$BBmemset0_9:
	move	$2, $4
	move	$sp, $fp
	lw	$fp, 0($sp)             # 4-byte Folded Reload
	lw	$ra, 4($sp)             # 4-byte Folded Reload
	jr	$ra
	addiu	$sp, $sp, 8
	.set	at
	.set	macro
	.set	reorder
	.end	memset
$memset_func_end0:
	.size	memset, ($memset_func_end0)-memset
                                        # -- End function
	.ident	"clang version 10.0.0-4ubuntu1 "
	.section	".note.GNU-stack","",@progbits
	.addrsig