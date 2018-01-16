#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/mempolicy.h>
#include <linux/moduleparam.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/rbtree.h>

MODULE_LICENSE("GPL");

struct mystruct {
	int data;
	struct hlist_node next;
};

static DEFINE_HASHTABLE(ht, 7);

static int __init hlist_init(void)
{ 
	struct mystruct *temp;
	struct mystruct *obj;
	int i;
	int j;
	int key;

	for (i = 11; i < 17; i++) {
		temp = kmalloc(sizeof(struct mystruct), GFP_KERNEL);
		temp->data = i * i;
		hash_add(ht, &temp->next, temp->data);
	}

	for (i = 11; i < 17; i++) {
		printk("trying %d * %d = %d\n", i, i, i * i);
		key = i * i;
		hash_for_each_possible(ht, obj, next, key) {
			printk("value: %d\n", obj->data);
		};
	}

    return 0;
}

static void __exit hlist_cleanup(void)
{
    printk(KERN_INFO "Cleaning up module.\n");
}

module_init(hlist_init);
module_exit(hlist_cleanup);
