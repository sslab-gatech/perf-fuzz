/*
 *  linux/kernel/pfork.c
 *
 *  wxu
 */

#include <linux/slab.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/completion.h>
#include <linux/personality.h>
#include <linux/mempolicy.h>
#include <linux/sem.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/iocontext.h>
#include <linux/key.h>
#include <linux/binfmts.h>
#include <linux/mman.h>
#include <linux/mmu_notifier.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/vmacache.h>
#include <linux/nsproxy.h>
#include <linux/capability.h>
#include <linux/cpu.h>
#include <linux/cgroup.h>
#include <linux/security.h>
#include <linux/hugetlb.h>
#include <linux/seccomp.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#include <linux/jiffies.h>
#include <linux/futex.h>
#include <linux/compat.h>
#include <linux/kthread.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/rcupdate.h>
#include <linux/ptrace.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/memcontrol.h>
#include <linux/ftrace.h>
#include <linux/proc_fs.h>
#include <linux/profile.h>
#include <linux/rmap.h>
#include <linux/ksm.h>
#include <linux/acct.h>
#include <linux/tsacct_kern.h>
#include <linux/cn_proc.h>
#include <linux/freezer.h>
#include <linux/delayacct.h>
#include <linux/taskstats_kern.h>
#include <linux/random.h>
#include <linux/tty.h>
#include <linux/blkdev.h>
#include <linux/fs_struct.h>
#include <linux/magic.h>
#include <linux/perf_event.h>
#include <linux/posix-timers.h>
#include <linux/user-return-notifier.h>
#include <linux/oom.h>
#include <linux/khugepaged.h>
#include <linux/signalfd.h>
#include <linux/uprobes.h>
#include <linux/aio.h>
#include <linux/compiler.h>
#include <linux/sysctl.h>
#include <linux/kcov.h>
#include <linux/list.h>

#include <asm/pgtable.h>
#include <asm/pgtable_types.h>
#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/mmu_context.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/tlb.h>

#ifdef CONFIG_SNAPSHOT

#define SNAPSHOT_START	0x00000000
#define SNAPSHOT_END	0x00000001
#define SNAPSHOT_CLEAN  0x00000002

#ifdef CONFIG_SNAPSHOT_DEBUG
  #define dbg_printk(format, arg...)     \
    printk(pr_fmt(format), ##arg);
#else
  #define dbg_printk(format, arg...) ((void) 0)
#endif

pmd_t *get_page_pmd(unsigned long addr) {
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd = NULL;

	struct mm_struct *mm = current->mm;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
		dbg_printk("[WEN] Invalid pgd.\n");
		goto out;
	}

	pud = pud_offset(pgd, addr);
	if (pud_none(*pud) || pud_bad(*pud)) {
		dbg_printk("[WEN] Invalid pud.\n");
		goto out;
	}
	
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd)) {
		dbg_printk("[WEN] Invalid pmd.\n");
		pmd = NULL;
		goto out;
  }

out:
	return pmd;
}

pte_t *walk_page_table(unsigned long addr) {
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep = NULL;

	struct mm_struct *mm = current->mm;

	pgd = pgd_offset(mm, addr);
  	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
		dbg_printk("[WEN] Invalid pgd.\n");
		goto out;
  	}

  	pud = pud_offset(pgd, addr);
  	if (pud_none(*pud) || pud_bad(*pud)) {
    	dbg_printk("[WEN] Invalid pud.\n");
  		goto out;
  	}

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd)) {
		dbg_printk("[WEN] Invalid pmd.\n");
		goto out;
	}
	
	ptep = pte_offset_map(pmd, addr);
	if (!ptep) {
		dbg_printk("[NEW] Invalid pte.\n");
    	goto out;
  	}

out:
	return ptep;
}

void munmap_new_vmas(struct mm_struct *mm) {
	struct vm_area_struct *vma = mm->mmap;
	struct snapshot_vma *ss_vma = mm->ss.ss_mmap;

	unsigned long old_start = ss_vma->vm_start;
	unsigned long old_end = ss_vma->vm_end;
	unsigned long cur_start = vma->vm_start; 
	unsigned long cur_end = vma->vm_end;

	/* we believe that normally, the original mappings of the father process
	 * will not be munmapped by the child process when fuzzing.
	 * 
	 * load library on-the-fly?
	 */
	do {
		if (cur_start < old_start)
		{
			if (old_start >= cur_end) {
				dbg_printk("[WEN] new: from 0x%08lx to 0x%08lx\n", cur_start, cur_end);
				vm_munmap(cur_start, cur_end - cur_start);
				vma = vma->vm_next;
				if (!vma)
					break;
				cur_start = vma->vm_start;
				cur_end = vma->vm_end;
			} else {
				dbg_printk("[WEN] new: from 0x%08lx to 0x%08lx\n", cur_start, old_start);
				vm_munmap(cur_start, old_start - cur_start);
				cur_start = old_start;
			}
		} else {
			if (cur_end < old_end) {
				vma = vma->vm_next;
				if (!vma)
					break;
				cur_start = vma->vm_start;
				cur_end = vma->vm_end;

				old_start = cur_end;
			} else if (cur_end == old_end) {
				vma = vma->vm_next;
				if (!vma)
					break;
				cur_start = vma->vm_start;
				cur_end = vma->vm_end;

				ss_vma = ss_vma->vm_next;
				if (!ss_vma)
					break;
				old_start = ss_vma->vm_start;
				old_end = ss_vma->vm_end;
			} else if (cur_end > old_end) {
				cur_start = old_end;

				ss_vma = ss_vma->vm_next;
				if (!ss_vma)	
					break;
				old_start = ss_vma->vm_start;
				old_end = ss_vma->vm_end;
			}
		}
	} while (true);

	if (vma) {
		dbg_printk("[WEN] new: from 0x%08lx to 0x%08lx\n", cur_start, cur_end);
		vm_munmap(cur_start, cur_end - cur_start);
		while (vma->vm_next != NULL) {
			vma = vma->vm_next;	
			dbg_printk("[WEN]new: from 0x%08lx to 0x%08lx\n", vma->vm_start, vma->vm_end);
			vm_munmap(vma->vm_start, vma->vm_end - vma->vm_start);
		}
	}

}

void clean_snapshot_vmas(struct mm_struct *mm) {
	struct snapshot_vma *p = mm->ss.ss_mmap;
	struct snapshot_vma *q;

	dbg_printk("[WEN] freeing snapshot vmas\n");

	while (p != NULL) {
		dbg_printk("[WEN] start: 0x%08lx end: 0x%08lx\n", p->vm_start, p->vm_end);
		q = p;
		p = p->vm_next;
		kfree(q);
	}

	mm->ss.ss_mmap = NULL;
}

void do_recover_page(struct snapshot_page *sp) {
	dbg_printk("[WEN] found reserved page: 0x%08lx page_base: 0x%08lx page_prot: 0x%08lx\n", 
				(unsigned long)sp->page_data, (unsigned long)sp->page_base, sp->page_prot);
	
	copy_to_user((void __user *)sp->page_base, 
								sp->page_data, PAGE_SIZE); 	
	
}

void do_recover_none_pte(struct snapshot_page *sp) {
	struct mm_struct *mm = current->mm;
	struct mmu_gather tlb;	
	pmd_t *pmd;

	dbg_printk("[WEN] found none_pte refreshed page_base: 0x%08lx page_prot: 0x%08lx\n",
				sp->page_base, sp->page_prot);

	/* 1. find pmd of the page */
	pmd = get_page_pmd(sp->page_base);	
	if (!pmd) {
		dbg_printk("[WEN] invalid pmd for page base 0x%08lx\n", sp->page_base);
		return;
	}

	/* 2. with the help of zap_pte_range(?) to safely free a page */
	lru_add_drain(); // ?
	tlb_gather_mmu(&tlb, mm, sp->page_base, sp->page_base + PAGE_SIZE);
	zap_pte_range(&tlb, mm->mmap, pmd, sp->page_base, sp->page_base + PAGE_SIZE, NULL);
	tlb_finish_mmu(&tlb, sp->page_base, sp->page_base + PAGE_SIZE);

	/* check it again? */	
	/*
	pte = walk_page_table(sp->page_base);
	if (!pte) {
		dbg_printk("[WEN] re-checking addr 0x%08lx fail!\n", sp->page_base); 
		return;
	}

	page = pte_page(*pte);
	dbg_printk("[WEN] re-checking addr: 0x%08lx PTE: 0x%08lx Page: 0x%08lx PageAnon: %d\n", 
						sp->page_base, pte->pte, (unsigned long)page, 
						page ? PageAnon(page) : 0);
	*/
}

void clean_memory_snapshot(struct mm_struct *mm) {
	struct snapshot_page *sp;
	int i;

	hash_for_each(mm->ss.ss_page, i, sp, next) {
		if (sp->page_data != NULL)
			kfree(sp->page_data);

		kfree(sp);
	}
}

void recover_memory_snapshot(struct mm_struct *mm) {
	struct snapshot_page *sp, *prev_sp = NULL;
    	pte_t *pte, entry;
	int i;

	hash_for_each(mm->ss.ss_page, i, sp, next) {

        if (sp->valid) {
		    if (sp->has_been_copied) // it has been captured by page fault
			    do_recover_page(sp);	
            else if (is_snapshot_page_private(sp)) { // private page that has not been captured
                pte = walk_page_table(sp->page_base); 
                if (pte) {
                    entry = pte_mkwrite(*pte);
                    set_pte_at(mm, sp->page_base, pte, entry);
                    __flush_tlb_one(sp->page_base & PAGE_MASK); 
                }
            }

		    else if (is_snapshot_page_none_pte(sp) && sp->has_had_pte)
			    do_recover_none_pte(sp);	
            sp->valid = false;
        }

	}		
}

void recover_brk(struct mm_struct *mm) {
	if (mm->brk > mm->ss.oldbrk) {
		sys_brk(mm->ss.oldbrk);	
	}
}

inline void init_snapshot(struct mm_struct *mm) {
    if (!had_snapshot(mm)) {
        // printk("init snapshot...\n");
        set_had_snapshot(mm);
	    hash_init(mm->ss.ss_page);
    }
	// multi-threading?
	set_snapshot(mm);
	// INIT_LIST_HEAD(&(mm->ss.ss_mmap));
	mm->ss.ss_mmap = NULL;
	return;
}

struct snapshot_page *add_snapshot_page(struct mm_struct *mm, unsigned long page_base) {
	struct snapshot_page *sp;

    sp = get_snapshot_page(mm, page_base);
    if (sp == NULL) {
	    sp = kmalloc(sizeof(struct snapshot_page), GFP_KERNEL);
        
            sp->page_base = page_base;
            sp->page_data = NULL;
	    hash_add(mm->ss.ss_page, &sp->next, sp->page_base);
    }

    sp->page_prot = 0;
    sp->has_been_copied = false;
    sp->valid = true;

	return sp;
}

void make_snapshot_page(struct vm_area_struct *vma, unsigned long addr) {
	pte_t *pte;
	struct snapshot_page *sp;
	struct page *page;

	pte = walk_page_table(addr);
	if (!pte)
		goto out;

	page = pte_page(*pte);
	
	dbg_printk("[WEN] making snapshot: 0x%08lx PTE: 0x%08lx Page: 0x%08lx PageAnon: %d\n", 
						addr, pte->pte, (unsigned long)page, 
						page ? PageAnon(page) : 0);

	sp = add_snapshot_page(vma->vm_mm, addr);

	if (pte_none(*pte)) { 
		/* empty pte */
        sp->has_had_pte = false;
		set_snapshot_page_none_pte(sp);

	} else {
        sp->has_had_pte = true;
		if (pte_write(*pte)) {
			/* Private rw page */
			dbg_printk("[WEN] private writable addr: 0x%08lx\n", addr);
			ptep_set_wrprotect(vma->vm_mm, addr, pte);
			set_snapshot_page_private(sp);

			/* flush tlb to make the pte change effective */
			flush_tlb_page(vma, addr & PAGE_MASK);
			dbg_printk("[WEN] writable now: %d\n", pte_write(*pte));
		} else { 
			/* COW ro page */
			dbg_printk("[WEN] cow writable addr: 0x%08lx\n", addr);
			set_snapshot_page_cow(sp);
		}
	}

	pte_unmap(pte);

out:
	return;
}

void add_snapshot_vma(struct mm_struct *mm, unsigned long start, unsigned long end) {
	struct snapshot_vma *ss_vma;
	struct snapshot_vma *p;

	dbg_printk("[WEN] adding snapshot vmas start: 0x%08lx end: 0x%08lx\n", start, end);
	ss_vma = (struct snapshot_vma *)kmalloc(sizeof(struct snapshot_vma), GFP_ATOMIC);
	ss_vma->vm_start = start;
	ss_vma->vm_end = end;

	if (mm->ss.ss_mmap == NULL) {
		mm->ss.ss_mmap = ss_vma;
	} else {
		p = mm->ss.ss_mmap;
		while (p->vm_next != NULL)
			p = p->vm_next;

		p->vm_next = ss_vma;
	}
	ss_vma->vm_next = NULL;
}

inline bool is_stack(struct vm_area_struct *vma) {
	return vma->vm_start <= vma->vm_mm->start_stack 
		&& vma->vm_end >= vma->vm_mm->start_stack;
}

void do_memory_snapshot(unsigned long arg) {
	unsigned long __user *buf = (unsigned long *)arg;
	struct task_struct *tsk = current;
	struct mm_struct *mm = tsk->mm;
	struct vm_area_struct *pvma = mm->mmap;
	unsigned long addr;

	unsigned long shm_addr = buf[1], shm_size = buf[2];

	dbg_printk("[WEN] shm_addr: 0x%08lx shm_size: 0x%08lx\n", shm_addr, shm_size);

	init_snapshot(mm);

	do {
		// temporarily store all the vmas
		add_snapshot_vma(mm, pvma->vm_start, pvma->vm_end);

		/* we only care about writable pages.
		 * we do not care about all the stack pages (temporarily).
		 */

		if (pvma->vm_flags & VM_WRITE && !is_stack(pvma) && pvma->vm_start != shm_addr) {
			dbg_printk("[WEN] make snapshot start: 0x%08lx end: 0x%08lx\n", pvma->vm_start, pvma->vm_end);
		
			for (addr = pvma->vm_start; 
				addr < pvma->vm_end; 
				addr += PAGE_SIZE) {

				make_snapshot_page(pvma, addr);
			}
		}

		pvma = pvma->vm_next;

	} while (pvma != NULL);

	return;
}

void recover_files_snapshot(void) {
	/*
	 * assume the child process will not close any
	 * father's fd?
	 */

	struct files_struct *files = current->files;
	struct fdtable *fdt = rcu_dereference_raw(files->fdt);

	int i, j = 0;
	for (;;) {
		unsigned long cur_set, old_set;
		i = j * BITS_PER_LONG;
		if (i >= fdt->max_fds)
			break;
		cur_set = fdt->open_fds[j];
		old_set = files->snapshot_open_fds[j++];
		// dbg_printk("cur_set: 0x%08lx old_set: 0x%08lx\n", cur_set, old_set);
		while (cur_set) {
			if (cur_set & 1) {
				if (!(old_set & 1) 
						&& fdt->fd[i] != NULL) {
						struct file *file = fdt->fd[i];
						dbg_printk("[WEN] find new fds %d file* 0x%08lx\n", i, (unsigned long)file); 
						// fdt->fd[i] = NULL;
						// filp_close(file, files);
						__close_fd(files, i);
				}
			}

			i++;
			cur_set >>= 1;
			old_set >>= 1;
		}
	}
}

void clean_files_snapshot(void) {
	struct files_struct *files = current->files;

	if (files->snapshot_open_fds != NULL)
		kfree(files->snapshot_open_fds);

	files->snapshot_open_fds = NULL;
}

void do_files_snapshot(void) {
	struct files_struct *files = current->files;
	struct fdtable *fdt = rcu_dereference_raw(files->fdt);		
	int size, i;

	size = (fdt->max_fds - 1) / BITS_PER_LONG + 1; 

    if (files->snapshot_open_fds == NULL)
	    files->snapshot_open_fds = (unsigned long *)kmalloc(
												size * sizeof(unsigned long), GFP_ATOMIC);

	for (i = 0; i < size; i++)
		files->snapshot_open_fds[i] = fdt->open_fds[i];
}

void reserve_context(unsigned long arg) {
	unsigned long __user *buf = (unsigned long *)arg;
    struct snapshot_context *sctx = current->mm->ss.ucontext;

    if (sctx == NULL) {
	    sctx = (struct snapshot_context *)kmalloc(sizeof(struct snapshot_context), GFP_ATOMIC);
	    current->mm->ss.ucontext = sctx;
    }

	sctx->cleanup = buf[0];

}

inline void reserve_brk(void) {
	struct mm_struct *mm = current->mm;
	mm->ss.oldbrk = mm->brk;
}

void clean_context(struct mm_struct *mm) {
	if (mm->ss.ucontext != NULL)
		kfree(mm->ss.ucontext);
	mm->ss.ucontext = NULL;
}

void make_snapshot(unsigned long arg) {
	reserve_context(arg);
	reserve_brk();
	do_memory_snapshot(arg);
    do_files_snapshot();
}

void recover_snapshot(unsigned long arg) {
	if (have_snapshot(current->mm)) {
        clear_snapshot(current->mm);
		recover_memory_snapshot(current->mm);
		recover_brk(current->mm);
		munmap_new_vmas(current->mm);
		clean_snapshot_vmas(current->mm);
		recover_files_snapshot();
		// clean_files_snapshot();
		// clean_context(current->mm);
		// clear_snapshot(current->mm);
	}
}

void clean_snapshot(void) {
	clean_memory_snapshot(current->mm);
	clean_snapshot_vmas(current->mm);
	clean_files_snapshot();
	clean_context(current->mm);
	clear_snapshot(current->mm);
}

#endif

SYSCALL_DEFINE2(snapshot, unsigned long, option, unsigned long, arg)
{

#ifdef CONFIG_SNAPSHOT
	dbg_printk("[WEN] in snapshot(%ld)!\n", option);
	switch (option) {
		case SNAPSHOT_START:
			make_snapshot(arg);
			break;
		case SNAPSHOT_END:
			recover_snapshot(arg);
			break;
		default:
			break;
	}
#endif

	return 0;
}



