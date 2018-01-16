#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/mempolicy.h>
#include <linux/moduleparam.h>
#include <linux/llist.h>
#include <linux/list.h>
#include <linux/rbtree.h>

MODULE_LICENSE("GPL");

static char *tskname;
module_param(tskname, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

void dump(char *buf, unsigned long len)
{
	unsigned long i = 0;
	for (; i < len; ++i)
	{
		printk("%02x ", (unsigned char)(buf[i]));
	}
	printk("\n");
}

void tskdump(struct task_struct *p)
{
	printk("task struct @ %p\n", p);

	printk("state: %ld\n", p->state);
	printk("stack: %p\n", p->stack);
	printk("usage: %d\n", p->usage.counter);
	printk("flags: %d\n", p->flags);
	printk("ptrace %d\n", p->ptrace);

#ifdef CONFIG_SMP
	printk("wake_entry.next: %p\n", p->wake_entry.next);
	printk("on_cpu: %d\n", p->on_cpu);
	printk("wakee_flips: %d\n", p->wakee_flips);
	printk("wakee_flip_decay_ts: %ld\n", p->wakee_flip_decay_ts);
	printk("last_wakee: %p\n", p->last_wakee);

	printk("wake_cpu: %d\n", p->wake_cpu);
#endif

	printk("on_rq: %d\n", p->on_rq);

	printk("prio: %d\n", p->prio);
	printk("static_prio: %d\n", p->static_prio);
	printk("normal_prio: %d\n", p->normal_prio);
	printk("rt_priority: %d\n", p->rt_priority);
	printk("sched_class: %p\n", p->sched_class);

	printk("se.load.weight: %ld\n", p->se.load.weight);
	printk("se.load.inv_weight: %d\n", p->se.load.inv_weight);
	printk("se.run_node.__rb_parent_color: %ld\n", p->se.run_node.__rb_parent_color);
	printk("se.run_node.rb_right: %p\n", p->se.run_node.rb_right);
	printk("se.run_node.rb_left: %p\n", p->se.run_node.rb_left);
	printk("se.group_node.next: %p\n", p->se.group_node.next);
	printk("se.group_node.prev: %p\n", p->se.group_node.prev);
	printk("se.on_rq: %d\n", p->se.on_rq);
	printk("se.exec_start: %lld\n", p->se.exec_start);
	printk("se.sum_exec_runtime: %lld\n", p->se.sum_exec_runtime);
	printk("se.vruntime: %lld\n", p->se.vruntime);
	printk("se.prev_sum_exec_runtime: %lld\n", p->se.prev_sum_exec_runtime);
	printk("se.nr_migrations: %lld\n", p->se.nr_migrations);

#ifdef CONFIG_SCHEDSTATS
	printk("se.statistics: ");
	dump((char *)(&p->se.statistics), sizeof(struct sched_statistics));
#endif

#ifdef CONFIG_FAIR_GROUP_SCHED
	printk("se.depth: %d\n", p->se.depth);
	printk("se.parent: %p\n", p->se.parent);
	printk("se.cfs_rq: %p\n", p->se.cfs_rq);
	printk("se.my_q: %p\n", p->se.my_q);
#endif

#ifdef CONFIG_SMP
	printk("se.avg: ");
	dump((char *)(&p->se.avg), sizeof(struct sched_avg));
#endif

	printk("rt.run_list.next: %p\n", p->rt.run_list.next);
	printk("rt.run_list.prev: %p\n", p->rt.run_list.prev);
	printk("rt.timeout: %ld\n", p->rt.timeout);
	printk("rt.watchdog_stamp: %ld\n", p->rt.watchdog_stamp);
	printk("rt.time_slice: %d\n", p->rt.time_slice);
	printk("rt.on_rq: %d\n", p->rt.on_rq);
	printk("rt.on_list: %d\n", p->rt.on_list);
	printk("rt.back: %p\n", p->rt.back);

#ifdef CONFIG_RT_GROUP_SCHED
	printk("rt.parent: %p\n", p->rt.parent);
	printk("rt.rt_rq: %p\n", p->rt.rt_rq);
	printk("rt.my_q: %p\n", p->rt.my_q);
#endif


#ifdef CONFIG_CGROUP_SCHED
	printk("sched_task_group: %p\n", p->sched_task_group);
#endif

	printk("dl.rb_node.__rb_parent_color: %ld\n", p->dl.rb_node.__rb_parent_color);
	printk("dl.rb_node.rb_right: %p\n", p->dl.rb_node.rb_right);
	printk("dl.rb_node.rb_left: %p\n", p->dl.rb_node.rb_left);
	printk("dl.dl_runtime: %lld\n", p->dl.dl_runtime);
	printk("dl.dl_deadline: %lld\n", p->dl.dl_deadline);
	printk("dl.dl_period: %lld\n", p->dl.dl_period);
	printk("dl.dl_bw: %lld\n", p->dl.dl_bw);
	printk("dl.runtime: %lld\n", p->dl.runtime);
	printk("dl.deadline: %lld\n", p->dl.deadline);
	printk("dl.flags: %d\n", p->dl.flags);
	printk("dl.dl_throttled: %d\n", p->dl.dl_throttled);
	printk("dl.dl_boosted: %d\n", p->dl.dl_boosted);
	printk("dl.dl_yielded: %d\n", p->dl.dl_yielded);
	printk("dl.dl_timer: ");
	dump((char *)(&p->dl.dl_timer), sizeof(struct hrtimer));

#ifdef CONFIG_PREEMPT_NOTIFIERS
	printk("preempt_notifiers.first: %p\n", p->preempt_notifiers.first);
#endif	

#ifdef CONFIG_BLK_DEV_IO_TRACE
	printk("btrace_seq: %d\n", p->btrace_seq);
#endif

	printk("policy: %d\n", p->policy);
	printk("nr_cpus_allowed: %d\n", p->nr_cpus_allowed);
	printk("cpus_allowed: %ld\n", p->cpus_allowed.bits[0]);

#ifdef CONFIG_PREEMPT_RCU
	printk("rcu_read_lock_nesting: %d\n", p->rcu_read_lock_nesting);
	printk("rcu_read_unlock_special.s: %d\n", p->rcu_read_unlock_special.s);
	printk("rcu_node_entry.next: %p\n", p->rcu_node_entry.next);
	printk("rcu_node_entry.prev: %p\n", p->rcu_node_entry.prev);
	printk("rcu_blocked_node: %p\n", p->rcu_blocked_node);
#endif /* #ifdef CONFIG_PREEMPT_RCU */
#ifdef CONFIG_TASKS_RCU
	printk("rcu_tasks_nvcsw: %d\n", p->rcu_tasks_nvcsw);
	printk("rcu_tasks_holdout: %d\n", p->rcu_tasks_holdout);
	printk("rcu_tasks_holdout_list.next: %p\n", p->rcu_tasks_holdout_list.next);
	printk("rcu_tasks_holdout_list.prev: %p\n", p->rcu_tasks_holdout_list.prev);
	printk("rcu_tasks_idle_cpu: %d\n", p->rcu_tasks_idle_cpu);
#endif /* #ifdef CONFIG_TASKS_RCU */

#ifdef CONFIG_SCHED_INFO
	printk("sched_info.pcount: %ld\n", p->sched_info.pcount);
	printk("sched_info.run_delay: %lld\n", p->sched_info.run_delay);
	printk("sched_info.last_arrival: %lld\n", p->sched_info.last_arrival);
	printk("sched_info.last_queued: %lld\n", p->sched_info.last_queued);
#endif

	printk("tasks.next: %p\n", p->tasks.next);
	printk("tasks.prev: %p\n", p->tasks.prev);
}

void vmadump(struct vm_area_struct *mmap)
{
	printk("vm_area_struct @ %p\n", mmap);

	printk("vm_start: %ld\n", mmap->vm_start);
	printk("vm_end: %ld\n", mmap->vm_end);

	printk("vm_next: %p\n", mmap->vm_next);
	printk("vm_prev: %p\n", mmap->vm_prev);

	printk("vm_rb.__rb_parent_color: %ld\n", mmap->vm_rb.__rb_parent_color);
	printk("vm_rb.rb_right: %p\n", mmap->vm_rb.rb_right);
	printk("vm_rb.rb_left: %p\n", mmap->vm_rb.rb_left);

	printk("rb_subtree_gap: %ld\n", mmap->rb_subtree_gap);

	printk("vm_mm: %p\n", mmap->vm_mm);
	printk("vm_page_prot: ");
	dump((char *)(&mmap->vm_page_prot), sizeof(pgprot_t));
	printk("vm_flags: %ld\n", mmap->vm_flags);

	printk("shared.rb.__rb_parent_color: %ld\n", mmap->shared.rb.__rb_parent_color);
	printk("shared.rb.rb_right: %p\n", mmap->shared.rb.rb_right);
	printk("shared.rb.rb_left: %p\n", mmap->shared.rb.rb_left);
	printk("shared.rb_subtree_last: %ld\n", mmap->shared.rb_subtree_last);

	printk("anon_vma_chain.next: %p\n", mmap->anon_vma_chain.next);
	printk("anon_vma_chain.prev: %p\n", mmap->anon_vma_chain.prev);

	printk("anon_vma: %p\n", mmap->anon_vma);

	printk("vm_ops: %p\n", mmap->vm_ops);

	printk("vm_pgoff: %ld\n", mmap->vm_pgoff);

	printk("vm_file: %p\n", mmap->vm_file);
	printk("vm_private_data: %p\n", mmap->vm_private_data);

#ifndef CONFIG_MMU
	printk("vm_region: %p\n", mmap->vm_region);
#endif
#ifdef CONFIG_NUMA
	printk("vm_policy: %p\n", mmap->vm_policy);
#endif
	printk("vm_userfaultfd_ctx: ");
	dump((char *)(&mmap->vm_userfaultfd_ctx), sizeof(struct vm_userfaultfd_ctx));

	return;
}

void pgddump(pgd_t *pgd)
{

}

void mmdump(struct mm_struct *mm)
{
	printk("mm_struct @ %p\n", mm);

	vmadump(mm->mmap);

	printk("mm_rb.rb_node: %p\n", mm->mm_rb.rb_node);
	printk("vmacache_seqnum: %d\n", mm->vmacache_seqnum);
#ifdef CONFIG_MMU
	printk("get_unmapped_area: %p\n", mm->get_unmapped_area);
#endif
	printk("mmap_base: %ld\n", mm->mmap_base);
	printk("mmap_legacy_base: %ld\n", mm->mmap_legacy_base);
	printk("task_size: %ld\n", mm->task_size);
	printk("highest_vm_end: %ld\n", mm->highest_vm_end);

	printk("pgd: %ld\n", mm->pgd->pgd);
	// pgddump(mm->pgd);

	printk("mm_users: %d\n", mm->mm_users.counter);
	printk("mm_count: %d\n", mm->mm_count.counter);
	printk("nr_ptes: %ld\n", mm->nr_ptes.counter);

#if CONFIG_PGTABLE_LEVELS > 2
	printk("nr_pmds: %ld\n", mm->nr_pmds.counter);
#endif

	printk("map_count: %d\n", mm->map_count);
	printk("page_table_lock: %d\n", mm->page_table_lock.rlock.raw_lock.val.counter);
	printk("mmap_sem.count: %ld\n", mm->mmap_sem.count.counter);
	printk("mmap_sem.wait_lock: %d\n", mm->mmap_sem.wait_lock.raw_lock.val.counter);
	printk("mmap_sem.wait_list.next: %p\n", mm->mmap_sem.wait_list.next);
	printk("mmap_sem.wait_list.prev: %p\n", mm->mmap_sem.wait_list.prev);

	printk("mmlist.next: %p\n", mm->mmlist.next);
	printk("mmlist.prev: %p\n", mm->mmlist.prev);

	printk("hiwater_rss: %ld\n", mm->hiwater_rss);
	printk("hiwater_vm: %ld\n", mm->hiwater_vm);

	printk("total_vm: %ld\n", mm->total_vm);
	printk("locked_vm: %ld\n", mm->locked_vm);
	printk("pinned_vm: %ld\n", mm->pinned_vm);

	printk("data_vm: %ld\n", mm->data_vm);
	printk("exec_vm: %ld\n", mm->exec_vm);
	printk("stack_vm: %ld\n", mm->stack_vm);
	printk("def_flags: %ld\n", mm->def_flags);
	printk("start_code: %ld\n", mm->start_code);
	printk("end_code: %ld\n", mm->end_code);
	printk("start_data: %ld\n", mm->start_data);
	printk("end_data: %ld\n", mm->end_data);
	printk("start_brk: %ld\n", mm->start_brk);
	printk("brk: %ld\n", mm->brk);
	printk("start_stack: %ld\n", mm->start_stack);
	printk("arg_start: %ld\n", mm->arg_start);
	printk("arg_end: %ld\n", mm->arg_end);
	printk("env_start: %ld\n", mm->env_start);
	printk("env_end: %ld\n", mm->env_end);

	printk("saved_auxv: ");
	dump((char *)(&mm->saved_auxv), sizeof(((struct mm_struct *)0)->saved_auxv));

	printk("rss_stat: ");
	dump((char *)(&mm->rss_stat), sizeof(struct mm_rss_stat));

	printk("binfmt: %p\n", mm->binfmt);

	printk("cpu_vm_mask_var: ");
	dump((char *)(&mm->cpu_vm_mask_var), sizeof(cpumask_var_t));

	printk("context: ");
	dump((char *)(&mm->context), sizeof(mm_context_t));
	
	printk("flags: %ld\n", mm->flags);
	printk("core_state: %p\n", mm->core_state);

#ifdef CONFIG_AIO
	printk("ioctx_lock: %d\n", mm->ioctx_lock.rlock.raw_lock.val.counter);
	printk("ioctx_table: %p\n", mm->ioctx_table);
#endif

#ifdef CONFIG_MEMCG
	printk("owner: %p\n", mm->owner);
#endif

	printk("exe_file: %p\n", mm->exe_file);
#ifdef CONFIG_MMU_NOTIFIER
	printk("mmu_notifier_mm: %p\n", mm->mmu_notifier_mm);
#endif
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && !USE_SPLIT_PMD_PTLOCKS
	printk("pmd_huge_pte: ");
	dump((char *)(&mm->pmd_huge_pte), sizeof(pgtable_t));
#endif
#ifdef CONFIG_CPUMASK_OFFSTACK
	printk("cpumask_allocation: ");
	dump((char *)(&mm->cpumask_allocation), sizoef(struct cpumask));
#endif
#ifdef CONFIG_NUMA_BALANCING
	printk("numa_next_scan: %ld\n", mm->numa_next_scan);
	printk("numa_scan_offset: %ld\n", mm->numa_scan_offset);
	printk("numa_scan_seq: %d\n", mm->numa_scan_seq);
#endif
#if defined(CONFIG_NUMA_BALANCING) || defined(CONFIG_COMPACTION)
	printk("tlb_flush_pending: %d\n", mm->tlb_flush_pending);
#endif
	printk("uprobes_state: ");
	dump((char *)(&mm->uprobes_state), sizeof(struct uprobes_state));
#ifdef CONFIG_X86_INTEL_MPX
	printk("bd_addr: %p\n", mm->bd_addr);
#endif
#ifdef CONFIG_HUGETLB_PAGE
	printk("hugetlb_usage: %ld\n", mm->hugetlb_usage.counter);
#endif
#ifdef CONFIG_MMU
	printk("async_put_work: ");
	dump((char *)(&mm->async_put_work), sizeof(struct work_struct));
#endif
}

struct task_struct *find_tsk(char *name)
{
	struct task_struct *start = &init_task;
	struct task_struct *cur = start;

	do
	{
		// printk("found %s!\n", cur->comm);
		if (!strcmp(cur->comm, name))
		{
			printk("found %p!\n", cur);
			return cur;
		}
		cur = container_of(cur->tasks.next, struct task_struct, tasks);
	} while (cur != start);

	return NULL;
}

static int __init tskdump_init(void)
{
	struct task_struct *target = find_tsk(tskname);
    
    mmdump(target->mm);
    // tskdump(target);

    return 0;
}

static void __exit tskdump_cleanup(void)
{
    printk(KERN_INFO "Cleaning up module.\n");
}

module_init(tskdump_init);
module_exit(tskdump_cleanup);
