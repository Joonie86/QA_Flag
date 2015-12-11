
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <ppc_asm.h>

#define LV1_N_IN_0_OUT(API_NAME, API_NUMBER)						\
_GLOBAL(##API_NAME)									\
	mflr %r0;									\
	std %r0, 16(%r1);								\
	li %r11, API_NUMBER;								\
	sc;										\
	ld %r0, 16(%r1);								\
	mtlr %r0;                                                                       \
	blr

#define LV1_0_IN_0_OUT									LV1_N_IN_0_OUT
#define LV1_1_IN_0_OUT									LV1_N_IN_0_OUT
#define LV1_1_IN_0_OUT									LV1_N_IN_0_OUT
#define LV1_2_IN_0_OUT									LV1_N_IN_0_OUT
#define LV1_3_IN_0_OUT									LV1_N_IN_0_OUT
#define LV1_4_IN_0_OUT									LV1_N_IN_0_OUT
#define LV1_5_IN_0_OUT									LV1_N_IN_0_OUT
#define LV1_6_IN_0_OUT									LV1_N_IN_0_OUT
#define LV1_7_IN_0_OUT									LV1_N_IN_0_OUT
#define LV1_8_IN_0_OUT									LV1_N_IN_0_OUT

#define LV1_2_IN_1_OUT(API_NAME, API_NUMBER)						\
_GLOBAL(##API_NAME)									\
	mflr %r0;									\
	std %r0, 16(%r1);								\
	stdu %r5, -8(%r1);								\
	li %r11, API_NUMBER;								\
	sc;										\
	addi %r1, %r1, 8;								\
	ld %r11, -8(%r1);								\
	std %r4, 0(%r11);								\
	ld %r0, 16(%r1);								\
	mtlr %r0;									\
	blr

#define LV1_3_IN_1_OUT(API_NAME, API_NUMBER)						\
_GLOBAL(##API_NAME)									\
	mflr %r0;									\
	std %r0, 16(%r1);								\
	stdu %r6, -8(%r1);								\
	li %r11, API_NUMBER;								\
	sc;										\
	addi %r1, %r1, 8;								\
	ld %r11, -8(%r1);								\
	std %r4, 0(%r11);								\
	ld %r0, 16(%r1);								\
	mtlr %r0;									\
	blr

#define LV1_3_IN_2_OUT(API_NAME, API_NUMBER)						\
_GLOBAL(##API_NAME)									\
	mflr %r0;									\
	std %r0, 16(%r1);								\
	std %r6, -8(%r1);								\
	stdu %r7, -16(%r1);								\
	li %r11, API_NUMBER;								\
	sc;										\
	addi %r1, %r1, 16;								\
	ld %r11, -8(%r1);								\
	std %r4, 0(%r11);								\
	ld %r11, -16(%r1);								\
	std %r5, 0(%r11);								\
	ld %r0, 16(%r1);								\
	mtlr %r0;									\
	blr

#define LV1_4_IN_1_OUT(API_NAME, API_NUMBER)						\
_GLOBAL(##API_NAME)									\
	mflr %r0;									\
	std %r0, 16(%r1);								\
	stdu %r7, -8(%r1);								\
	li %r11, API_NUMBER;								\
	sc;										\
	addi %r1, %r1, 8;								\
	ld %r11, -8(%r1);								\
	std %r4, 0(%r11);								\
	ld %r0, 16(%r1);								\
	mtlr %r0;									\
	blr
	
#define LV1_4_IN_2_OUT(API_NAME, API_NUMBER)	\
_GLOBAL(##API_NAME)								\
	mflr %r0;									\
	std	%r0, 16(%r1);							\
	std %r7, -8(%r1);							\
	stdu %r8, -16(%r1);							\
	li %r11, API_NUMBER;						\
	sc;										\
	addi %r1, %r1, 16;							\
	ld %r11, -8(%r1);							\
	std %r4, 0(%r11);							\
	ld %r11, -16(%r1);							\
	std	%r5, 0(%r11);							\
	ld %r0, 16(%r1);							\
	mtlr %r0;									\
	blr

#define LV1_5_IN_2_OUT(API_NAME, API_NUMBER)						\
_GLOBAL(##API_NAME)									\
	mflr %r0;									\
	std %r0, 16(%r1);								\
	std %r8, -8(%r1);								\
	stdu %r9, -16(%r1);								\
	li %r11, API_NUMBER;								\
	sc;										\
	addi %r1, %r1, 16;								\
	ld %r11, -8(%r1);								\
	std %r4, 0(%r11);								\
	ld %r11, -16(%r1);								\
	std %r5, 0(%r11);								\
	ld %r0, 16(%r1);								\
	mtlr %r0;									\
	blr

#define LV1_6_IN_3_OUT(API_NAME, API_NUMBER)						\
_GLOBAL(##API_NAME)									\
	mflr %r0;									\
	std %r0, 16(%r1);								\
	std %r9, -8(%r1);								\
	stdu %r10, -16(%r1);								\
	li %r11, API_NUMBER;								\
	sc;										\
	addi %r1, %r1, 16;								\
	ld %r11, -8(%r1);								\
	std %r4, 0(%r11);								\
	ld %r11, -16(%r1);								\
	std %r5, 0(%r11);								\
	ld %r11, 48+8*8(%r1);								\
	std %r6, 0(%r11);								\
	ld %r0, 16(%r1);								\
	mtlr %r0;									\
	blr

/*
 * lv2 syscall 615 (3.41)
 */
//#define LV1_HVCALL(name, in, out, num)							LV1_##in##_IN_##out##_OUT(_lv1_##name, 615)

/*
 * lv2 syscall 811 (3.55)
 */
#define LV1_HVCALL(name, in, out, num)							LV1_##in##_IN_##out##_OUT(_lv1_##name, 11)

.text

#include <lv1_hvcall.h>
