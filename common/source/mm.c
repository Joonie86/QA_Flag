
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

#include <mm.h>

#include <lv1_hvcall.h>

/*
 * mm_map_lpar_memory_region
 */
int mm_map_lpar_memory_region(uint64_t vas_id, uint64_t va_start_addr, uint64_t lpar_start_addr,
	uint64_t size, uint64_t page_shift, uint64_t vflags, uint64_t rflags)
{
	int i, result;

	for (i = 0; i < size >> page_shift; i++) {
		result = mm_insert_htab_entry(vas_id, va_start_addr, lpar_start_addr,
			page_shift, vflags, rflags, 0);
		if (result != 0)
			return result;

		va_start_addr += (1 << page_shift);
		lpar_start_addr += (1 << page_shift);
	}

	return 0;
}

/*
 * mm_insert_htab_entry
 */
int mm_insert_htab_entry(uint64_t vas_id, uint64_t va_addr, uint64_t lpar_addr,
	uint64_t page_shift, uint64_t vflags, uint64_t rflags, uint64_t *index)
{
	uint64_t hpte_group, hpte_index, hpte_v, hpte_r, hpte_evicted_v, hpte_evicted_r;
        int result;

	hpte_group = (((va_addr >> 28) ^ ((va_addr & 0xFFFFFFFULL) >> page_shift)) & HTAB_HASH_MASK) *
		HPTES_PER_GROUP;

	hpte_v = ((va_addr >> 23) << HPTE_V_AVPN_SHIFT) | HPTE_V_VALID | (vflags & HPTE_V_FLAGS_MASK);

	if (page_shift != PAGE_SIZE_4KB)
		hpte_v |= HPTE_V_LARGE;

	hpte_r = (lpar_addr & ~((1ULL << page_shift) - 1)) | (rflags & HPTE_R_FLAGS_MASK);

	if (page_shift == PAGE_SIZE_1MB)
		hpte_r |= (1 << 12);

	result = lv1_insert_htab_entry(vas_id, hpte_group, hpte_v, hpte_r, HPTE_V_BOLTED, 0,
		&hpte_index, &hpte_evicted_v, &hpte_evicted_r);
	if (result != 0)
		return result;

	if (index != 0)
		*index = hpte_index;

        return 0;
}
