#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/syscalls.h>
#include <linux/scatterlist.h>
#include <linux/timer.h>
#include <linux/workqueue.h>

#define SHA256_LENGTH   32
#define START_MEM       0xffffffff81000000 
#define END_MEM         0xffffffffa2000000

unsigned long *syscall_table = NULL;
typedef struct timer_list timer;
static timer t;
struct work_struct work_to_do;
int working = 0; 
unsigned char csum[SHA256_LENGTH]; 
void do_shit(struct work_struct *work);
void timer_listener(unsigned long);

void register_timer_interrupt(void)
{
    setup_timer(&t, timer_listener, 0);
    mod_timer(&t, jiffies + msecs_to_jiffies(1000));
}

unsigned long *finder(void)
{
    unsigned long ptr;
    for (ptr = (unsigned long)START_MEM;
    ptr < (unsigned long)END_MEM;
    ptr += sizeof(void *))
    {
        unsigned long *p = (unsigned long *)ptr;

        if(p[__NR_close] == (unsigned long)sys_close)
        {
            return p;
        }
    }
    return NULL;
}

void timer_listener(unsigned long data)
{
    schedule_work(&work_to_do);
    register_timer_interrupt();
}

void do_shit (struct work_struct *work)
{
    struct scatterlist sg;
    struct crypto_hash *tfm;
    struct hash_desc desc;
    unsigned char output[SHA256_LENGTH];
    int i;

    syscall_table = finder();

    if ( syscall_table != NULL ) 
    {
        tfm = crypto_alloc_hash("sha256", 0, CRYPTO_ALG_ASYNC);
        desc.tfm = tfm;
        desc.flags = 0;

        sg_init_one(&sg, syscall_table, 2500);

        crypto_hash_init(&desc);

        crypto_hash_update(&desc, &sg, sg.length);
        crypto_hash_final(&desc, output);

        if (working != 0 && *csum != *output)
        {
            printk("Warning: sys_call_table SHA256 has changed!! (Rootkit Heuristic!)\n");
        }

        for (i = 0; i < 32; i++) 
        {
            printk("%02x", output[i]);
        }
        printk("\n");

        crypto_free_hash(tfm);
        working = 1;
        *csum = *output;
    }
    else 
    {
        printk("Oh bollocks!! Syscall table not found..\n");
    }
}

static int sha1_init(void) 
{
    INIT_WORK(&work_to_do, do_shit);
    register_timer_interrupt();
    return 0;
}

static void sha1_exit(void)
{
    del_timer(&t);
    flush_work_sync(&work_to_do);
}

module_init(sha1_init);
module_exit(sha1_exit);

MODULE_LICENSE("GPL");
