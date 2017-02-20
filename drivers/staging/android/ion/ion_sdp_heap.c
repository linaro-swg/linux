/*
 * drivers/staging/android/ion/ion_sdp_heap.c
 *
 * Copyright (C) 2016-2017 Linaro, Inc.
 * Copyright (C) Allwinner 2014
 * Author: <sunny@allwinnertech.com> for Allwinner.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * ION heap type for handling Secure Data Path (SDP) buffers
 *
 * SDP requires ION heaps that are never mapped to linux world unless
 * explicitly requested by the client for some debug purpose.
 *
 * Based on Allwinner work (allocation thru gen_pool) and
 * HiSilicon work (create ION heaps from DT nodes,
 * Author: Chen Feng <puck.chen@hisilicon.com>).
 *
 * CONFIG_ION_SDP_POOL_BASE/_SIZE allows to statically define a SDP pool
 * physical location to be used to create an ION "sdp" heap.
 *
 * TODO: flexible creation of standard heaps from DT node (thru ion_parse_dt).
 */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/genalloc.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "ion.h"
#include "ion_priv.h"

/* Hard code SDP heap type for compliance with uapi and userland */
#define ION_HEAP_TYPE_SECURE	(ION_HEAP_TYPE_CUSTOM + 1)

#define ION_SDP_ALLOCATE_FAIL		-1

struct ion_secure_heap {
	struct ion_heap heap;
	struct gen_pool *pool;
	ion_phys_addr_t base;
	size_t          size;
};

struct sdp_buffer_priv {
	ion_phys_addr_t base;
};

static ion_phys_addr_t get_buffer_base(struct sdp_buffer_priv *priv)
{
	return priv->base;
}

static struct device *heap2dev(struct ion_heap *heap)
{
	return heap->dev->dev.this_device;
}

/*
 * FIXME: currently stores the buffer physical address into
 * field 'priv_virt' which should rather points to a private
 * structure where to store buffer physical address.
 */
ion_phys_addr_t ion_secure_allocate(struct ion_heap *heap,
				      unsigned long size,
				      unsigned long align)
{
	struct ion_secure_heap *secure_heap =
		container_of(heap, struct ion_secure_heap, heap);
	unsigned long offset = gen_pool_alloc(secure_heap->pool, size);

	if (!offset) {
		dev_err(heap2dev(heap),
			"%s(%d) err: alloc 0x%08x bytes failed\n",
			__func__, __LINE__, (u32)size);
		return ION_SDP_ALLOCATE_FAIL;
	}

	return offset;
}

void ion_secure_free(struct ion_heap *heap, ion_phys_addr_t addr,
		       unsigned long size)
{
	struct ion_secure_heap *secure_heap =
		container_of(heap, struct ion_secure_heap, heap);

	if (addr == ION_SDP_ALLOCATE_FAIL)
		return;
	gen_pool_free(secure_heap->pool, addr, size);
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0))
static int ion_secure_heap_phys(struct ion_heap *heap,
				  struct ion_buffer *buffer,
				  ion_phys_addr_t *addr, size_t *len)
{
	*addr = get_buffer_base(buffer->priv_virt);
	*len = buffer->size;
	return 0;
}
#endif

struct sg_table *ion_secure_heap_map_dma(struct ion_heap *heap,
					      struct ion_buffer *buffer)
{
	struct sg_table *table;
	int ret;

	table = kzalloc(sizeof(struct sg_table), GFP_KERNEL);
	if (!table)
		return ERR_PTR(-ENOMEM);
	ret = sg_alloc_table(table, 1, GFP_KERNEL);
	if (ret) {
		kfree(table);
		return ERR_PTR(ret);
	}
	sg_set_page(table->sgl,
		    phys_to_page(get_buffer_base(buffer->priv_virt)),
		    buffer->size, 0);

	return table;
}

void ion_secure_heap_unmap_dma(struct ion_heap *heap,
				 struct ion_buffer *buffer)
{
	sg_free_table(buffer->sg_table);
	kfree(buffer->sg_table);
}


static int ion_secure_heap_allocate(struct ion_heap *heap,
				      struct ion_buffer *buffer,
				      unsigned long size, unsigned long align,
				      unsigned long flags)
{
	struct sdp_buffer_priv *priv;
	int rc = -EINVAL;

	priv = devm_kzalloc(heap2dev(heap), sizeof(*priv), GFP_KERNEL);
	if (IS_ERR_OR_NULL(priv))
		return -ENOMEM;

	priv->base = ion_secure_allocate(heap, size, align);
	if (priv->base == ION_SDP_ALLOCATE_FAIL) {
		rc = -ENOMEM;
		goto err;
	}

	buffer->size = roundup(size, PAGE_SIZE);
	buffer->priv_virt = priv;

dev_err(heap2dev(heap), "sdp alloc pa:%lx sz:%x/%x align:%lu\n",
		priv->base, (unsigned)size, (unsigned)buffer->size, align);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0))
	buffer->sg_table = ion_secure_heap_map_dma(heap, buffer);
	if (!buffer->sg_table) {
		rc = -ENOMEM;
		goto err;
	}
#endif
	sg_dma_address(buffer->sg_table->sgl) = priv->base;
	sg_dma_len(buffer->sg_table->sgl) = size;
	return 0;
err:
	ion_secure_free(heap, priv->base, size);
	devm_kfree(heap2dev(heap), priv);
	buffer->priv_virt = NULL;
	return rc;
}

static void ion_secure_heap_free(struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0))
	ion_secure_heap_unmap_dma(heap, buffer);
#endif
	ion_secure_free(heap, get_buffer_base(buffer->priv_virt), buffer->size);
	devm_kfree(heap2dev(heap), buffer->priv_virt);
	buffer->priv_virt = NULL;
}

int ion_secure_heap_map_user(struct ion_heap *heap, struct ion_buffer *buffer,
			       struct vm_area_struct *vma)
{
	ion_phys_addr_t pa = get_buffer_base(buffer->priv_virt);

	/*
	 * when user call ION_IOC_ALLOC not with ION_FLAG_CACHED, ion_mmap will
	 * change prog to pgprot_writecombine itself, so we do not need change
	 * to pgprot_writecombine here manually.
	 */
	return remap_pfn_range(vma, vma->vm_start,
				__phys_to_pfn(pa) + vma->vm_pgoff,
				vma->vm_end - vma->vm_start,
				vma->vm_page_prot);
}

static struct ion_heap_ops secure_heap_ops = {
	.allocate = ion_secure_heap_allocate,
	.free = ion_secure_heap_free,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0))
	.phys = ion_secure_heap_phys,
	.map_dma = ion_secure_heap_map_dma,
	.unmap_dma = ion_secure_heap_unmap_dma,
#endif
	.map_user = ion_secure_heap_map_user,
	.map_kernel = ion_heap_map_kernel,
	.unmap_kernel = ion_heap_unmap_kernel,
};

struct ion_heap *ion_secure_heap_create(struct ion_platform_heap *heap_data)
{
	struct ion_secure_heap *secure_heap;

	secure_heap = kzalloc(sizeof(struct ion_secure_heap), GFP_KERNEL);
	if (!secure_heap)
		return ERR_PTR(-ENOMEM);

	secure_heap->pool = gen_pool_create(PAGE_SHIFT, -1);
	if (!secure_heap->pool) {
		kfree(secure_heap);
		return ERR_PTR(-ENOMEM);
	}
	secure_heap->base = heap_data->base;
	secure_heap->size = heap_data->size;
	gen_pool_add(secure_heap->pool, secure_heap->base, heap_data->size, -1);
	secure_heap->heap.ops = &secure_heap_ops;
	secure_heap->heap.type = ION_HEAP_TYPE_SECURE;

	/* save name and id as done from ion_heap_create() */
	secure_heap->heap.name = heap_data->name;
	secure_heap->heap.id = heap_data->id;

	return &secure_heap->heap;
}

void ion_secure_heap_destroy(struct ion_heap *heap)
{
	struct ion_secure_heap *secure_heap =
	     container_of(heap, struct  ion_secure_heap, heap);

	gen_pool_destroy(secure_heap->pool);
	kfree(secure_heap);
	secure_heap = NULL;
}

/*
 * Create SDP heaps from DT nodes or platform data
 */

/*
 * This is weird. Cannot register several ion devices.
 * A single driver must create all the heaps, or find
 * a way to get the already existing ion device.
 */
struct ion_device *sdp_idev;

/* sdp heap device used to create physical heaps */
struct sdp_heap_device {
	struct list_head list;
};

/* registered physical heap entry in heap device heaps list */
struct sdp_registered_heap {
	struct list_head link;
	struct ion_platform_heap *pheap;
	struct ion_heap *heap;
};

/* traces out the list of the created heaps (supports NULL device) */
static void list_heaps(struct platform_device *pdev,
			struct sdp_heap_device *heap_dev)
{
	struct sdp_registered_heap *r_heap;
	struct sdp_registered_heap *tmp;

	if (!heap_dev && pdev)
		heap_dev = platform_get_drvdata(pdev);
	if (!heap_dev)
		return;

	list_for_each_entry_safe(r_heap, tmp, &heap_dev->list, link) {

		if (r_heap->pheap && pdev)
			dev_info(&pdev->dev, "id/type %d/%d [%lx %lx] %s\n",
				r_heap->pheap->id, r_heap->pheap->type,
				r_heap->pheap->base,
				r_heap->pheap->base + r_heap->pheap->size - 1,
				r_heap->pheap->name);
		else if (r_heap->pheap)
			pr_info("ion-sdp-heap: id/type %d/%d [%lx %lx] %s\n",
				r_heap->pheap->id, r_heap->pheap->type,
				r_heap->pheap->base,
				r_heap->pheap->base + r_heap->pheap->size - 1,
				r_heap->pheap->name);
	}
}

static void create_heaps(struct platform_device *pdev,
			struct sdp_heap_device *heap_dev)
{

	struct sdp_registered_heap *r_heap;
	struct sdp_registered_heap *tmp;

	if (!heap_dev && pdev)
		heap_dev = platform_get_drvdata(pdev);
	if (!heap_dev)
		return;

	list_for_each_entry_safe(r_heap, tmp, &heap_dev->list, link) {
		struct ion_platform_heap *pheap = r_heap->pheap;
		struct ion_heap *heap;

		if (pheap->type == ION_HEAP_TYPE_SECURE)
			heap = ion_secure_heap_create(pheap);
		else
			heap = ion_heap_create(pheap);

		if (IS_ERR_OR_NULL(heap)) {
			if (pdev) {
				devm_kfree(&pdev->dev, r_heap->pheap);
				devm_kfree(&pdev->dev, r_heap);
				dev_warn(&pdev->dev, "bad heap \"%s\"\n",
								pheap->name);
			} else {
				kfree(r_heap->pheap);
				kfree(r_heap);
				pr_warn("bad heap \"%s\"\n", pheap->name);
			}
			list_del(&r_heap->link);
			continue;
		}

		r_heap->heap = heap;
		ion_device_add_heap(sdp_idev, r_heap->heap);
	}
}


/* releases resources from a registered heap list */
static void release_heaps(struct platform_device *pdev,
			  struct sdp_heap_device *heap_dev)
{
	struct sdp_registered_heap *r_heap;
	struct sdp_registered_heap *tmp;

	if (!heap_dev && pdev)
		heap_dev = platform_get_drvdata(pdev);
	if (!heap_dev)
		return;

	list_for_each_entry_safe(r_heap, tmp, &heap_dev->list, link) {

		if (r_heap->heap) {
			if (r_heap->pheap->type == ION_HEAP_TYPE_SECURE)
				ion_secure_heap_destroy(r_heap->heap);
			else
				ion_heap_destroy(r_heap->heap);
		}
		list_del(&r_heap->link);
		if (pdev) {
			devm_kfree(&pdev->dev, r_heap->pheap);
			devm_kfree(&pdev->dev, r_heap->heap);
			devm_kfree(&pdev->dev, r_heap);
		} else {
			kfree(r_heap->pheap);
			kfree(r_heap->heap);
			kfree(r_heap);
		}
	}

	if (pdev)
		devm_kfree(&pdev->dev, heap_dev);
	else
		kfree(heap_dev);
}

/* returns structured platform data to create a heap from a DT node */
static struct ion_platform_heap *pheap_from_dt_node(
					struct platform_device *pdev,
					struct device_node *np)
{
	struct ion_platform_heap *pheap;
	enum ion_heap_type type;
	const char *name;
	unsigned int base;
	unsigned int size;
	unsigned int id;
	int rc;

	rc = of_property_read_string(np, "heap-name", &name);
	if (rc < 0) {
		pr_err("check the name of node %s\n", np->name);
		return NULL;
	}

	rc = of_property_read_u32(np, "heap-id", &id);
	if (rc < 0) {
		pr_err("check the id %s\n", np->name);
		return NULL;
	}

	rc = of_property_read_u32(np, "heap-base", &base);
	if (rc < 0) {
		pr_err("check the base of node %s\n", np->name);
		return NULL;
	}
	rc = of_property_read_u32(np, "heap-size", &size);
	if (rc < 0) {
		pr_err("check the size of node %s\n", np->name);
		return NULL;
	}

	rc = of_property_read_u32(np, "heap-type", &type);
	if (rc < 0) {
		pr_err("check the type of node %s\n", np->name);
		return NULL;
	}
	if (type != ION_HEAP_TYPE_SECURE) {
		/* allow one to register other heaps (base/size ?) */
		pr_warn("check the type of node %s != %d\n", np->name,
						ION_HEAP_TYPE_SECURE);
	}

	pheap = devm_kzalloc(&pdev->dev,
			      sizeof(struct ion_platform_heap),
			      GFP_KERNEL);
	if (IS_ERR_OR_NULL(pheap))
		return pheap;

	pheap->name = name;
	pheap->base = base;
	pheap->size = size;
	pheap->id = id;
	pheap->type = type;

	return pheap;
}

/* parses DT node and create requested heaps */
static int register_heaps_from_dt(struct platform_device *pdev)
{
	struct sdp_heap_device *heap_dev = platform_get_drvdata(pdev);
	struct device_node *pnode = pdev->dev.of_node;
	struct device_node *np;

	if (!pnode)
		return 0;

	for_each_child_of_node(pnode, np) {
		struct sdp_registered_heap *r_heap;
		struct ion_platform_heap *pheap;

		r_heap = devm_kzalloc(&pdev->dev, sizeof(*r_heap), GFP_KERNEL);
		if (IS_ERR_OR_NULL(r_heap))
			return PTR_ERR(r_heap);

		pheap = pheap_from_dt_node(pdev, np);
		if (IS_ERR_OR_NULL(pheap)) {
			devm_kfree(&pdev->dev, r_heap);
			dev_warn(&pdev->dev, "bad DT node, ignored\n");
			continue;
		}

		r_heap->pheap = pheap;
		list_add_tail(&r_heap->link, &heap_dev->list);
	}

	create_heaps(pdev, heap_dev);
	return 0;
}

/* parses platform data and create requested heaps */
static int register_heaps_from_pdata(struct platform_device *pdev)
{
	struct sdp_heap_device *heap_dev = platform_get_drvdata(pdev);
	struct ion_platform_data *pdata = pdev->dev.platform_data;
	int i;

	if (!pdata)
		return 0;

	for (i = 0; i < pdata->nr; i++) {
		struct sdp_registered_heap *rheap;
		struct ion_platform_heap *pheap;

		rheap = devm_kzalloc(&pdev->dev, sizeof(*rheap), GFP_KERNEL);
		pheap = devm_kzalloc(&pdev->dev, sizeof(*pheap), GFP_KERNEL);
		if (IS_ERR_OR_NULL(rheap) || IS_ERR_OR_NULL(pheap)) {
			devm_kfree(&pdev->dev, rheap);
			devm_kfree(&pdev->dev, pheap);
			return -ENOMEM;
		}
		memcpy(pheap, &pdata->heaps[i], sizeof(*pheap));

		rheap->pheap = pheap;
		list_add_tail(&rheap->link, &heap_dev->list);
	}

	create_heaps(pdev, heap_dev);
	return 0;
}

static int sdp_heaps_probe(struct platform_device *pdev)
{
	struct sdp_heap_device *heap_dev;
	int rc = 0;

	if (!sdp_idev)
		sdp_idev = ion_device_create(NULL);
	if (IS_ERR_OR_NULL(sdp_idev))
		return PTR_ERR(sdp_idev);

	heap_dev = devm_kzalloc(&pdev->dev, sizeof(*heap_dev), GFP_KERNEL);
	if (IS_ERR_OR_NULL(heap_dev))
		return PTR_ERR(heap_dev);

	INIT_LIST_HEAD(&heap_dev->list);
	platform_set_drvdata(pdev, heap_dev);

	if (pdev->dev.of_node)
		rc = register_heaps_from_dt(pdev);
	else if (pdev->dev.platform_data)
		rc = register_heaps_from_pdata(pdev);
	else
		rc = -ENOENT;

	if (rc)
		release_heaps(pdev, NULL);
	else
		list_heaps(pdev, NULL);

	return rc;
}

static int sdp_heaps_remove(struct platform_device *pdev)
{
	release_heaps(pdev, NULL);
	return 0;
}

static const struct of_device_id sdp_heaps_match[] = {
	{.compatible = "linaro,ion-sdp-heap"},
	{.compatible = "ion-sdp-heap"},
	{},
};

static struct platform_driver sdp_heaps_driver = {
	.probe = sdp_heaps_probe,
	.remove = sdp_heaps_remove,
	.driver = {
		.name = "ion-sdp-heap",
		.of_match_table = sdp_heaps_match,
	},
};

module_platform_driver(sdp_heaps_driver);

//#define CONFIG_ION_SDP_POOL_BASE	0x7b080000
//#define CONFIG_ION_SDP_POOL_SIZE	0x00100000

#ifdef CONFIG_ION_SDP_POOL_BASE
/*
 * This is for test purpose. Statically define the pool location.
 * Code below supports several heap in 'static_heaps' table.
 */
static struct ion_platform_heap static_heaps[] = {
		{
			.id	= ION_HEAP_TYPE_SECURE,
			.type	= ION_HEAP_TYPE_SECURE,
			.name	= "sdp-static-pool",
			.base	= CONFIG_ION_SDP_POOL_BASE,
			.size	= CONFIG_ION_SDP_POOL_SIZE,
			.align	= PAGE_SIZE,
		},
};

static struct ion_platform_data sdp_static_pdata = {
	.nr = ARRAY_SIZE(static_heaps),
	.heaps = static_heaps,
};

struct sdp_heap_device *sdp_static_heaps;

static int __init sdp_static_heaps_init(void)
{
	struct sdp_heap_device *heap_dev;
	int rc = 0;
	int i;

	if (!sdp_idev)
		sdp_idev = ion_device_create(NULL);
	if (IS_ERR_OR_NULL(sdp_idev))
		return PTR_ERR(sdp_idev);

	heap_dev = kzalloc(sizeof(*heap_dev), GFP_KERNEL);
	if (IS_ERR_OR_NULL(heap_dev))
		return PTR_ERR(heap_dev);

	sdp_static_heaps = heap_dev;
	INIT_LIST_HEAD(&heap_dev->list);

	for (i = 0; i < sdp_static_pdata.nr; i++) {
		struct sdp_registered_heap *rheap;

		rheap = kzalloc(sizeof(*rheap), GFP_KERNEL);
		if (IS_ERR_OR_NULL(rheap)) {
			rc = -ENOMEM;
			break;
		}

		rheap->pheap = &static_heaps[i];
		list_add_tail(&rheap->link, &heap_dev->list);
	}

	if (rc) {
		release_heaps(NULL, sdp_static_heaps);
	} else {
		create_heaps(NULL, sdp_static_heaps);
		list_heaps(NULL, sdp_static_heaps);
	}
	return rc;
}

device_initcall(sdp_static_heaps_init);
#endif
