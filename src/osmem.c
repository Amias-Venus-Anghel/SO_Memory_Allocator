// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "helpers.h"

#define  ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define META_SIZE sizeof(struct block_meta)
#define MMAP_THRESHOLD	(128 * 1024)

struct block_meta *global_base;

/* merge all free adiacent blocks */
void merge_blocks(void)
{
	struct block_meta *current = global_base;

	while (current->next) {
		struct block_meta *next = current->next;

		if (current->status == STATUS_FREE && next->status == STATUS_FREE) {
			current->size = current->size + META_SIZE + next->size;
			current->next = next->next;
		} else {
			current = current->next;
		}
	}
}

/* find best fitting free block for the given size */
struct block_meta *find_best_fit(struct block_meta **last, size_t size)
{
	struct block_meta *current = global_base;
	struct block_meta *match = NULL;

	while (current) {
		if (current->size >= size && current->status == STATUS_FREE) {
			if (!match || current->size < match->size)
				match = current;
		}
		/* remember last element of list */
		*last = current;
		current = current->next;
	}

	return match;
}

/* alloc a new block with sbrk */
struct block_meta *request_space(struct block_meta *last, size_t size)
{
	struct block_meta *block;

	block = sbrk(size + META_SIZE);
	DIE(block == (void *)-1, "sbrk failed");

	if ((void *)block == (void *) -1)
		return NULL;

	/* link the new block to the end of the list */
	if (last)
		last->next = block;

	/* set block data */
	block->size = size;
	block->next = NULL;
	block->status = STATUS_ALLOC;
	return block;
}

/* add aditional memory for the last block in list */
void expand_last(struct block_meta *last, size_t expand_size)
{
	void *mem = sbrk(expand_size);

	DIE(mem == (void *)-1, "sbrk failed");
	/* modify block size to reflect newly allocated memory */
	last->size += expand_size;
}

/* alloc a new block with mmap */
struct block_meta *request_space_mmap(size_t size)
{
	struct block_meta *block;
	void *mem = mmap(NULL, size + META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	DIE(mem == (void *)-1, "mmap failed");

	if (mem == MAP_FAILED)
		return NULL;

	/* set block data */
	block = (struct block_meta *)mem;
	block->size = size;
	block->status = STATUS_MAPPED;

	return block;
}

/* convert pointer to coresponding block */
struct block_meta *get_block(void *ptr)
{
	return (struct block_meta *)((char *)ptr - META_SIZE);
}

/* split a block into two */
void split_block(struct block_meta *block, size_t size_a)
{
	struct block_meta *new_block = (struct block_meta *)((char *)block + size_a + META_SIZE);

	/* remake list linking and modify sizes */
	new_block->next = block->next;
	new_block->size = block->size - META_SIZE - size_a;
	block->size = size_a;
	block->next = new_block;
	new_block->status = STATUS_FREE;
}

/* alloc memory for a given size and a threashold */
struct block_meta *allocMem(size_t size, size_t threashold)
{
	struct block_meta *block;

	/* align size */
	if (size <= 0)
		return NULL;


	size_t size_a = ALIGN(size);

	/* mmap allocation */
	if (size_a + META_SIZE >= threashold) {
		block = request_space_mmap(size_a);
		if (!block)
			return NULL;

		return block;
	}

	/* sbrk allocation */
	if (!global_base) {
		/* first call */
		block = request_space(NULL, MMAP_THRESHOLD - META_SIZE);
		if (!block)
			return NULL;

		if (size_a + META_SIZE + 1 < block->size)
			split_block(block, size_a);

		/* initiate list head */
		global_base = block;
	} else {
		/* merge free block before search */
		merge_blocks();
		struct block_meta *last = global_base;

		block = find_best_fit(&last, size_a);
		if (!block) {
			/* failed to find  free block */
			if (last->status == STATUS_FREE) {
				/* expand last block */
				expand_last(last, size_a - last->size);
				block = last;
			} else {
				block = request_space(last, size_a);
			}

			if (!block)
				return NULL;

		} else {
			/* found free block -> split block if neccesarry*/
			if (size_a + META_SIZE + 1 < block->size)
				split_block(block, size_a);
			/* update status */
			block->status = STATUS_ALLOC;
		}
	}

	return block;
}

/* merge blocks untill size can be fit into block */
void expandTillSize(struct block_meta *block, size_t size)
{
	/* marker for enough size optained */
	int goOn = 1;

	while (block->next && goOn) {
		struct block_meta *next = block->next;

		goOn = 0;

		if (next->status == STATUS_FREE) {
			block->size = block->size + META_SIZE + next->size;
			block->next = next->next;
			/* if expansion is done and block is still not big enough, continue */
			if (block->size < size)
				goOn = 1;
		}
	}
}

void *os_malloc(size_t size)
{
	/* alloc memory */
	struct block_meta *block = allocMem(size, MMAP_THRESHOLD);

	if (!block)
		return NULL;

	/* return pointer address */
	return (char *)block + META_SIZE;
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *block_ptr = get_block(ptr);

	/* free memory dipending on block status */
	if (block_ptr->status == STATUS_MAPPED) {
		int ret = munmap(block_ptr, block_ptr->size + META_SIZE);

		DIE(ret == -1, "munmap failed");
	} else {
		/* mark as free for reuse */
		block_ptr->status = STATUS_FREE;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* get threashold size */
	size_t pageSize = getpagesize();
	/* alloc memory */
	struct block_meta *block = allocMem(size * nmemb, pageSize);

	if (!block)
		return NULL;

	char *ptr = (char *)block + META_SIZE;
	/* initialize memory */
	memset(ptr, 0, block->size);
	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	/* check corner cases */
	if (size <= 0) {
		os_free(ptr);
		return NULL;
	}

	if (!ptr)
		return os_malloc(size);

	struct block_meta *block = get_block(ptr);

	if (block->status == STATUS_FREE)
		return NULL;

	size = ALIGN(size);

	/* realloc for big chancks of memory */
	if (block->status == STATUS_MAPPED || size + META_SIZE >= MMAP_THRESHOLD) {
		void *new_ptr = os_malloc(size);

		memcpy(new_ptr, ptr, size > block->size ? block->size : size);
		os_free(ptr);
		return new_ptr;
	}

	/* split block for smaller new size */
	if (block->size > size) {
		if (size + META_SIZE + 1 < block->size)
			split_block(block, size);

		return ptr;
	}

	/* try to expand block */
	size_t original_size = block->size;

	expandTillSize(block, size);

	if (block->size >= size) {
		/* check if new block can be split */
		if (size + META_SIZE + 1 < block->size)
			split_block(block, size);

		return ptr;
	}

	/* expand block if it's last in list */
	if (!block->next) {
		expand_last(block, size - block->size);
		return ptr;
	}

	/* no free block big enough was found */
	void *new_ptr = os_malloc(size);

	if (!new_ptr)
		return NULL;

	memcpy(new_ptr, ptr, original_size);
	os_free(ptr);

	return new_ptr;
}
