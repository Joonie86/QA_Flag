
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

#ifndef _MM_H_
#define _MM_H_

#include <stdint.h>

#define HTAB_HASH_MASK				0x7ffull
#define HPTES_PER_GROUP				8

#define HPTE_V_AVPN_SHIFT			7
#define HPTE_V_BOLTED				0x0000000000000010ull
#define HPTE_V_LARGE				0x0000000000000004ull
#define HPTE_V_VALID				0x0000000000000001ull
#define HPTE_V_FLAGS_MASK			0x000000000000007Full

#define HPTE_R_R				0x0000000000000100ull
#define HPTE_R_C				0x0000000000000080ull
#define HPTE_R_W				0x0000000000000040ull
#define HPTE_R_I				0x0000000000000020ull
#define HPTE_R_M				0x0000000000000010ull
#define HPTE_R_G				0x0000000000000008ull
#define HPTE_R_N				0x0000000000000004ull
#define HPTE_R_FLAGS_MASK			0x000000000000ffffull

#define PAGE_SIZES(_ps0, _ps1)			(((u64) (_ps0) << 56) | ((u64) (_ps1) << 48))
#define PAGE_SIZE_4KB				12
#define PAGE_SIZE_64KB				16
#define PAGE_SIZE_1MB				20
#define PAGE_SIZE_16MB				24

#define MM_EA2VA(ea)				((ea) & ~(1ULL << 63))

int mm_map_lpar_memory_region(uint64_t vas_id, uint64_t va_start_addr, uint64_t lpar_start_addr,
	uint64_t size, uint64_t page_shift, uint64_t vflags, uint64_t rflags);

int mm_insert_htab_entry(uint64_t vas_id, uint64_t va_addr, uint64_t lpar_addr,
	uint64_t page_shift, uint64_t vflags, uint64_t rflags, uint64_t *index);

#endif
