// SPDX-License-Identifier: GPL-2.0
/*
 * DMABUF secure heap exporter
 *
 * Copyright 2021 NXP.
 */

#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/genalloc.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "deferred-free-helper.h"
#include "page_pool.h"

#define MAX_SECURE_HEAP 2
#define MAX_HEAP_NAME_LEN 32

struct secure_heap_buffer {
	struct dma_heap *heap;
	struct list_head attachments;
	struct mutex lock;
	unsigned long len;
	struct sg_table sg_table;
	int vmap_cnt;
	struct deferred_freelist_item deferred_free;
	void *vaddr;
	bool uncached;
};

struct dma_heap_attachment {
	struct device *dev;
	struct sg_table *table;
	struct list_head list;
	bool no_map;
	bool mapped;
	bool uncached;
};

struct secure_heap_info {
	struct gen_pool *pool;

	bool no_map;
};

struct rmem_secure {
	phys_addr_t base;
	phys_addr_t size;

	char name[MAX_HEAP_NAME_LEN];

	bool no_map;
};

static struct rmem_secure secure_data[MAX_SECURE_HEAP] = {0};
static unsigned int secure_data_count;

static struct sg_table *dup_sg_table(struct sg_table *table)
{
	struct sg_table *new_table;
	int ret, i;
	struct scatterlist *sg, *new_sg;

	new_table = kzalloc(sizeof(*new_table), GFP_KERNEL);
	if (!new_table)
		return ERR_PTR(-ENOMEM);

	ret = sg_alloc_table(new_table, table->orig_nents, GFP_KERNEL);
	if (ret) {
		kfree(new_table);
		return ERR_PTR(-ENOMEM);
	}

	new_sg = new_table->sgl;
	for_each_sgtable_sg(table, sg, i) {
		sg_set_page(new_sg, sg_page(sg), sg->length, sg->offset);
		new_sg->dma_address = sg->dma_address;
#ifdef CONFIG_NEED_SG_DMA_LENGTH
		new_sg->dma_length = sg->dma_length;
#endif
		new_sg = sg_next(new_sg);
	}

	return new_table;
}

static int secure_heap_attach(struct dma_buf *dmabuf,
			      struct dma_buf_attachment *attachment)
{
	struct secure_heap_buffer *buffer = dmabuf->priv;
	struct secure_heap_info *info = dma_heap_get_drvdata(buffer->heap);
	struct dma_heap_attachment *a;
	struct sg_table *table;

	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return -ENOMEM;

	table = dup_sg_table(&buffer->sg_table);
	if (IS_ERR(table)) {
		kfree(a);
		return -ENOMEM;
	}

	a->table = table;
	a->dev = attachment->dev;
	INIT_LIST_HEAD(&a->list);
	a->no_map = info->no_map;
	a->mapped = false;
	a->uncached = buffer->uncached;
	attachment->priv = a;

	mutex_lock(&buffer->lock);
	list_add(&a->list, &buffer->attachments);
	mutex_unlock(&buffer->lock);

	return 0;
}

static void secure_heap_detach(struct dma_buf *dmabuf,
			       struct dma_buf_attachment *attachment)
{
	struct secure_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a = attachment->priv;

	mutex_lock(&buffer->lock);
	list_del(&a->list);
	mutex_unlock(&buffer->lock);

	sg_free_table(a->table);
	kfree(a->table);
	kfree(a);
}

static struct sg_table *secure_heap_map_dma_buf(struct dma_buf_attachment *attachment,
						enum dma_data_direction direction)
{
	struct dma_heap_attachment *a = attachment->priv;
	struct sg_table *table = a->table;
	int attr = 0;
	int ret;

	if (!a->no_map) {
		if (a->uncached)
			attr = DMA_ATTR_SKIP_CPU_SYNC;

		ret = dma_map_sgtable(attachment->dev, table, direction, attr);
		if (ret)
			return ERR_PTR(ret);

		a->mapped = true;
	}

	return table;
}

static void secure_heap_unmap_dma_buf(struct dma_buf_attachment *attachment,
				      struct sg_table *table,
				      enum dma_data_direction direction)
{
	struct dma_heap_attachment *a = attachment->priv;
	int attr = 0;

	if (!a->no_map)	{
		if (a->uncached)
			attr = DMA_ATTR_SKIP_CPU_SYNC;

		a->mapped = false;
		dma_unmap_sgtable(attachment->dev, table, direction, attr);
	}
}

static int secure_heap_dma_buf_begin_cpu_access(struct dma_buf *dmabuf,
						enum dma_data_direction direction)
{
	struct secure_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a;

	mutex_lock(&buffer->lock);

	if (buffer->vmap_cnt)
		invalidate_kernel_vmap_range(buffer->vaddr, buffer->len);

	if (!buffer->uncached) {
		list_for_each_entry(a, &buffer->attachments, list) {
			if (!a->mapped)
				continue;
			dma_sync_sgtable_for_cpu(a->dev, a->table, direction);
		}
	}
	mutex_unlock(&buffer->lock);

	return 0;
}

static int secure_heap_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
					      enum dma_data_direction direction)
{
	struct secure_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a;

	mutex_lock(&buffer->lock);

	if (buffer->vmap_cnt)
		flush_kernel_vmap_range(buffer->vaddr, buffer->len);

	if (!buffer->uncached) {
		list_for_each_entry(a, &buffer->attachments, list) {
			if (!a->mapped)
				continue;
			dma_sync_sgtable_for_device(a->dev, a->table, direction);
		}
	}
	mutex_unlock(&buffer->lock);

	return 0;
}

static int secure_heap_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct secure_heap_buffer *buffer = dmabuf->priv;
	struct sg_table *table = &buffer->sg_table;
	unsigned long addr = vma->vm_start;
	struct sg_page_iter piter;
	int ret;

	if (buffer->uncached)
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	for_each_sgtable_page(table, &piter, vma->vm_pgoff) {
		struct page *page = sg_page_iter_page(&piter);

		ret = remap_pfn_range(vma, addr, page_to_pfn(page), PAGE_SIZE,
				      vma->vm_page_prot);
		if (ret)
			return ret;
		addr += PAGE_SIZE;
	}
	return 0;
}

static void *secure_heap_do_vmap(struct secure_heap_buffer *buffer)
{
	struct sg_table *table = &buffer->sg_table;
	int npages = PAGE_ALIGN(buffer->len) / PAGE_SIZE;
	struct page **pages = vmalloc(sizeof(struct page *) * npages);
	struct page **tmp = pages;
	struct sg_page_iter piter;
	pgprot_t pgprot = PAGE_KERNEL;
	void *vaddr;

	if (!pages)
		return ERR_PTR(-ENOMEM);

	if (buffer->uncached)
		pgprot = pgprot_writecombine(PAGE_KERNEL);

	for_each_sgtable_page(table, &piter, 0) {
		WARN_ON(tmp - pages >= npages);
		*tmp++ = sg_page_iter_page(&piter);
	}

	vaddr = vmap(pages, npages, VM_MAP, pgprot);
	vfree(pages);

	if (!vaddr)
		return ERR_PTR(-ENOMEM);

	return vaddr;
}

static int secure_heap_vmap(struct dma_buf *dmabuf, struct dma_buf_map *map)
{
	struct secure_heap_buffer *buffer = dmabuf->priv;
	void *vaddr;
	int ret = 0;

	mutex_lock(&buffer->lock);
	if (buffer->vmap_cnt) {
		buffer->vmap_cnt++;
		goto out;
	}

	vaddr = secure_heap_do_vmap(buffer);
	if (IS_ERR(vaddr)) {
		ret = PTR_ERR(vaddr);
		goto out;
	}

	buffer->vaddr = vaddr;
	buffer->vmap_cnt++;
	dma_buf_map_set_vaddr(map, buffer->vaddr);
out:
	mutex_unlock(&buffer->lock);

	return ret;
}

static void secure_heap_vunmap(struct dma_buf *dmabuf, struct dma_buf_map *map)
{
	struct secure_heap_buffer *buffer = dmabuf->priv;

	mutex_lock(&buffer->lock);
	if (!--buffer->vmap_cnt) {
		vunmap(buffer->vaddr);
		buffer->vaddr = NULL;
	}
	mutex_unlock(&buffer->lock);
	dma_buf_map_clear(map);
}

static void secure_heap_zero_buffer(struct secure_heap_buffer *buffer)
{
	struct sg_table *sgt = &buffer->sg_table;
	struct sg_page_iter piter;
	struct page *p;
	void *vaddr;

	for_each_sgtable_page(sgt, &piter, 0) {
		p = sg_page_iter_page(&piter);
		vaddr = kmap_atomic(p);
		memset(vaddr, 0, PAGE_SIZE);
		kunmap_atomic(vaddr);
	}
}

static void secure_heap_buf_free(struct deferred_freelist_item *item,
				 enum df_reason reason)
{
	struct secure_heap_buffer *buffer;
	struct secure_heap_info *info;
	struct sg_table *table;
	struct scatterlist *sg;
	int i;

	buffer = container_of(item, struct secure_heap_buffer, deferred_free);
	info = dma_heap_get_drvdata(buffer->heap);

	if (!info->no_map) {
		// Zero the buffer pages before adding back to the pool 
		if (reason == DF_NORMAL)
			secure_heap_zero_buffer(buffer);
	}

	table = &buffer->sg_table;
	for_each_sg(table->sgl, sg, table->nents, i)
		gen_pool_free(info->pool, sg_dma_address(sg), sg_dma_len(sg));

	sg_free_table(table);
	kfree(buffer);
}

static void secure_heap_dma_buf_release(struct dma_buf *dmabuf)
{
	struct secure_heap_buffer *buffer = dmabuf->priv;
	int npages = PAGE_ALIGN(buffer->len) / PAGE_SIZE;

	deferred_free(&buffer->deferred_free, secure_heap_buf_free, npages);
}

static const struct dma_buf_ops secure_heap_buf_ops = {
	.attach = secure_heap_attach,
	.detach = secure_heap_detach,
	.map_dma_buf = secure_heap_map_dma_buf,
	.unmap_dma_buf = secure_heap_unmap_dma_buf,
	.begin_cpu_access = secure_heap_dma_buf_begin_cpu_access,
	.end_cpu_access = secure_heap_dma_buf_end_cpu_access,
	.mmap = secure_heap_mmap,
	.vmap = secure_heap_vmap,
	.vunmap = secure_heap_vunmap,
	.release = secure_heap_dma_buf_release,
};

static struct dma_buf *secure_heap_do_allocate(struct dma_heap *heap,
					       unsigned long len,
					       unsigned long fd_flags,
					       unsigned long heap_flags,
					       bool uncached)
{
	struct secure_heap_buffer *buffer;
	struct secure_heap_info *info = dma_heap_get_drvdata(heap);
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	unsigned long size = roundup(len, PAGE_SIZE);
	struct dma_buf *dmabuf;
	struct sg_table *table;
	int ret = -ENOMEM;
	unsigned long phy_addr;

	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&buffer->attachments);
	mutex_init(&buffer->lock);
	buffer->heap = heap;
	buffer->len = size;
	buffer->uncached = uncached;

	phy_addr = gen_pool_alloc(info->pool, size);
	if (!phy_addr)
		goto free_buffer;

	table = &buffer->sg_table;
	if (sg_alloc_table(table, 1, GFP_KERNEL))
		goto free_pool;

	sg_set_page(table->sgl,	phys_to_page(phy_addr),	size, 0);
	sg_dma_address(table->sgl) = phy_addr;
	sg_dma_len(table->sgl) = size;

	/* create the dmabuf */
	exp_info.exp_name = dma_heap_get_name(heap);
	exp_info.ops = &secure_heap_buf_ops;
	exp_info.size = buffer->len;
	exp_info.flags = fd_flags;
	exp_info.priv = buffer;
	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		goto free_pages;
	}

	return dmabuf;

free_pages:
	sg_free_table(table);

free_pool:
	gen_pool_free(info->pool, phy_addr, size);

free_buffer:
	mutex_destroy(&buffer->lock);
	kfree(buffer);

	return ERR_PTR(ret);
}

static struct dma_buf *secure_heap_allocate(struct dma_heap *heap,
					    unsigned long len,
					    unsigned long fd_flags,
					    unsigned long heap_flags)
{
	// use uncache buffer here by default
	return secure_heap_do_allocate(heap, len, fd_flags, heap_flags, true);
	// use cache buffer
	// return secure_heap_do_allocate(heap, len, fd_flags, heap_flags, false);
}

static const struct dma_heap_ops secure_heap_ops = {
	.allocate = secure_heap_allocate,
};

static int secure_heap_add(struct rmem_secure *rmem)
{
	struct dma_heap *secure_heap;
	struct dma_heap_export_info exp_info;
	struct secure_heap_info *info = NULL;
	struct gen_pool *pool = NULL;
	int ret = -EINVAL;

	if (rmem->base == 0 || rmem->size == 0) {
		pr_err("secure_data base or size is not correct\n");
		goto error;
	}

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		pr_err("dmabuf info allocation failed\n");
		ret = -ENOMEM;
		goto error;
	}

	pool = gen_pool_create(PAGE_SHIFT, -1);
	if (!pool) {
		pr_err("can't create gen pool\n");
		ret = -ENOMEM;
		goto error;
	}

	if (gen_pool_add(pool, rmem->base, rmem->size, -1) < 0) {
		pr_err("failed to add memory into pool\n");
		ret = -ENOMEM;
		goto error;
	}

	info->pool = pool;
	info->no_map = rmem->no_map;

	exp_info.name = rmem->name;
	exp_info.ops = &secure_heap_ops;
	exp_info.priv = info;

	secure_heap = dma_heap_add(&exp_info);
	if (IS_ERR(secure_heap)) {
		pr_err("dmabuf secure heap allocation failed\n");
		ret = PTR_ERR(secure_heap);
		goto error;
	}

	return 0;

error:
	if (info)
		kfree(info);
	if (pool)
		gen_pool_destroy(pool);

	return ret;
}

static int secure_heap_create(void)
{
	unsigned int i;
	int ret;

	for (i = 0; i < secure_data_count; i++) {
		ret = secure_heap_add(&secure_data[i]);
		if (ret)
			return ret;
	}
	return 0;
}

static int rmem_secure_heap_device_init(struct reserved_mem *rmem,
					 struct device *dev)
{
	dev_set_drvdata(dev, rmem);
	return 0;
}

static void rmem_secure_heap_device_release(struct reserved_mem *rmem,
					 struct device *dev)
{
	dev_set_drvdata(dev, NULL);
}

static const struct reserved_mem_ops rmem_dma_ops = {
	.device_init    = rmem_secure_heap_device_init,
	.device_release = rmem_secure_heap_device_release,
};

static int __init rmem_secure_heap_setup(struct reserved_mem *rmem)
{
	if (secure_data_count < MAX_SECURE_HEAP) {
		int name_len = 0;
		char *s = rmem->name;

		secure_data[secure_data_count].base = rmem->base;
		secure_data[secure_data_count].size = rmem->size;
		secure_data[secure_data_count].no_map =
			(of_get_flat_dt_prop(rmem->fdt_node, "no-map", NULL) != NULL);

		while (name_len < MAX_HEAP_NAME_LEN) {
			if ((*s == '@') || (*s == '\0'))
				break;
			name_len++;
			s++;
		}
		if (name_len == MAX_HEAP_NAME_LEN)
			name_len--;

		strncpy(secure_data[secure_data_count].name, rmem->name, name_len);

		rmem->ops = &rmem_dma_ops;
		pr_info("Reserved memory: DMA buf secure pool %s at %pa, size %ld MiB\n",
			secure_data[secure_data_count].name,
			&rmem->base, (unsigned long)rmem->size / SZ_1M);

		secure_data_count++;
		return 0;
	} else {
		WARN_ONCE(1, "Cannot handle more than %u secure heaps\n", MAX_SECURE_HEAP);
		return -EINVAL;
	}
}

RESERVEDMEM_OF_DECLARE(secure_heap, "linaro,secure-heap", rmem_secure_heap_setup);

module_init(secure_heap_create);
MODULE_LICENSE("GPL v2");
