#include "mem.h"
#include "stdlib.h"
#include "string.h"
#include <pthread.h>
#include <stdio.h>
#define LOG_MEM 0

static BYTE _ram[RAM_SIZE];

static struct
{
  uint32_t proc; // ID of process currently uses this page
  int index;     // Index of the page in the list of pages allocated to the process.
  int next;      // The next page in the list. -1 if it is the last page.
} _mem_stat[NUM_PAGES];

static pthread_mutex_t mem_lock;
static pthread_mutex_t ram_lock;

void init_mem(void)
{
  memset(_mem_stat, 0, sizeof(*_mem_stat) * NUM_PAGES);
  memset(_ram, 0, sizeof(BYTE) * RAM_SIZE);
  pthread_mutex_init(&mem_lock, NULL);
  pthread_mutex_init(&ram_lock, NULL);
}

/* get offset of the virtual address */
static addr_t get_offset(addr_t addr)
{
  return addr & ~((~0U) << OFFSET_LEN);
}

/* get the first layer index */
static addr_t get_first_lv(addr_t addr)
{
  return addr >> (OFFSET_LEN + PAGE_LEN);
}

/* get the second layer index */
static addr_t get_second_lv(addr_t addr)
{
  return (addr >> OFFSET_LEN) - (get_first_lv(addr) << PAGE_LEN);
}

/* Search for page table table from the a segment table */
static struct page_table_t *get_page_table(
    addr_t index, // segment index
    struct seg_table_t *seg_table)
{ // first level table

  /*
	 * TODO: Given the Segment index [index], you must go through each
	 * row of the segment table [seg_table] and check if the v_index
	 * field of the row is equal to the index
	 *
	 * */

  if (!seg_table)
    return NULL;

  for (int i = 0; i < seg_table->size; i++)
    if (index == seg_table->table[i].v_index)
      return seg_table->table[i].pages;

  return NULL;
}

/* Translate virtual address to physical address. If [virtual_addr] is valid,
 * return 1 and write its physical counterpart to [physical_addr].
 * Otherwise, return 0 */
static int translate(
    addr_t virtual_addr,   // Given virtual address
    addr_t *physical_addr, // Physical address to be returned
    struct pcb_t *proc)
{ // Process uses given virtual address

  /* Offset of the virtual address */
  addr_t offset = get_offset(virtual_addr);
  /* The first layer index */
  addr_t first_lv = get_first_lv(virtual_addr);
  /* The second layer index */
  addr_t second_lv = get_second_lv(virtual_addr);

  /* Search in the first level */
  struct page_table_t *page_table = get_page_table(first_lv, proc->seg_table);
  if (!page_table)
    return 0;

  for (int i = 0; i < page_table->size; i++)
  {
    if (page_table->table[i].v_index == second_lv)
    {
      /* TODO: Concatenate the offset of the virtual addess
			 * to [p_index] field of page_table->table[i] to 
			 * produce the correct physical address and save it to
			 * [*physical_addr]  */

      *physical_addr = (page_table->table[i].p_index << OFFSET_LEN) | (offset);
      return 1;
    }
  }
  return 0;
}

/* Check if both physical and virtual mem have enough memory to allocate */
int enough_mem_to_alloc(int num_pages, struct pcb_t *proc)
{
  if (num_pages == 0)
    return 1;

  /* Check virtual space */
  if (proc->bp + num_pages * PAGE_SIZE >= RAM_SIZE)
    return 0; //not enough virtual space

  /* Check physical space */
  int free_pages = 0;
  for (int i = 0; i < NUM_PAGES; i++)
    if (_mem_stat[i].proc == 0)
    {
      free_pages++;
      if (free_pages == num_pages)
        return 1;
    }

  return 0; //not enough physical space
}

addr_t alloc_mem(uint32_t size, struct pcb_t *proc)
{
  pthread_mutex_lock(&mem_lock);
  addr_t ret_mem = 0;
  /* Allocate [size] byte in the memory for the
	 * process [proc] and save the address of the first
	 * byte in the allocated memory region to [ret_mem].
	 * */

  uint32_t num_pages = (size % PAGE_SIZE == 0) ? size / PAGE_SIZE : size / PAGE_SIZE + 1;

  if (enough_mem_to_alloc(num_pages, proc))
  {
    ret_mem = proc->bp;
    proc->bp += num_pages * PAGE_SIZE;

    int allocated_pages = 0;
    int last_allocated_page = -1;

    for (int i = 0; i < NUM_PAGES && allocated_pages < num_pages; i++)
    {
      if (_mem_stat[i].proc != 0)
        continue;

      _mem_stat[i].proc = proc->pid;          //use this page
      _mem_stat[i].index = allocated_pages++; //index in list of allocated pages

      if (last_allocated_page > -1) //update last allocated page (if not first page)
        _mem_stat[last_allocated_page].next = i;
      last_allocated_page = i;
      if (allocated_pages == num_pages)
        _mem_stat[i].next = -1; //last page in list

      // Find or create virtual page table
      addr_t v_address = ret_mem + (allocated_pages - 1) * PAGE_SIZE;

      struct page_table_t *v_page_table = get_page_table(get_first_lv(v_address), proc->seg_table);
      if (!v_page_table)
      {
        // If no such page_table, create one
        int idx = proc->seg_table->size++;
        proc->seg_table->table[idx].v_index = get_first_lv(v_address);
        proc->seg_table->table[idx].pages = (struct page_table_t *)malloc(sizeof(struct page_table_t));
        v_page_table = proc->seg_table->table[idx].pages;
      }
      v_page_table->table[v_page_table->size + 1].v_index = get_second_lv(v_address);
      v_page_table->table[v_page_table->size + 1].p_index = i;
      v_page_table->size++;
    }
  }
  pthread_mutex_unlock(&mem_lock);

  if (LOG_MEM)
  {
    printf("<<============== ALLOCATE %2d ==============>>\n", num_pages);
    dump();
  }

  return ret_mem;
}

int free_mem(addr_t address, struct pcb_t *proc)
{
  /* Release memory region allocated by [proc]. The first byte of
	 * this region is indicated by [address]. Task to do:
	 * 	- Set flag [proc] of physical page use by the memory block
	 * 	  back to zero to indicate that it is free.
	 * 	- Remove unused entries in segment table and page tables of
	 * 	  the process [proc].
	 * 	- Remember to use lock to protect the memory from other
	 * 	  processes.  */
  pthread_mutex_lock(&mem_lock);
  addr_t p_address = 0; //physical address

  //Get physical address
  if (!translate(address, &p_address, proc))
    return 1;

  //Free physical pages
  int freed_pages = 0;
  for (int i = p_address >> OFFSET_LEN; i > -1; i = _mem_stat[i].next)
  {
    freed_pages++;
    _mem_stat[i].proc = 0;
  }

  //Free virtual pages
  for (int i = 0; i < freed_pages; i++)
  {
    addr_t v_address = address + PAGE_SIZE * i;

    struct page_table_t *page_table = get_page_table(get_first_lv(v_address), proc->seg_table);
    if (!page_table)
      continue; //never happens, just in case

    for (int j = 0; j < page_table->size; j++)
      if (page_table->table[j].v_index == get_second_lv(v_address))
      {
        page_table->table[j] = page_table->table[--page_table->size];
        break;
      }

    //delete page table if no longer use
    if (page_table->size == 0)
      for (int i = 0; i < proc->seg_table->size; i++)
      {
        if (proc->seg_table->table[i].v_index == get_first_lv(v_address))
        {
          free(proc->seg_table->table[i].pages);
          proc->seg_table->table[i] = proc->seg_table->table[--proc->seg_table->size];
        }
      }
  }

  //Update break pointer, only when top of stack
  if (proc->bp - address == freed_pages * PAGE_SIZE)
    proc->bp = address;
  pthread_mutex_unlock(&mem_lock);

  if (LOG_MEM)
  {
    printf("<<============= DEALLOCATE %2d =============>>\n", freed_pages);
    dump();
  }

  return 0;
}

int read_mem(addr_t address, struct pcb_t *proc, BYTE *data)
{
  addr_t physical_addr;
  if (translate(address, &physical_addr, proc))
  {
    pthread_mutex_lock(&ram_lock);
    *data = _ram[physical_addr];
    pthread_mutex_unlock(&ram_lock);
    return 0;
  }
  else
  {
    return 1;
  }
}

int write_mem(addr_t address, struct pcb_t *proc, BYTE data)
{
  addr_t physical_addr;
  if (translate(address, &physical_addr, proc))
  {
    pthread_mutex_lock(&ram_lock);
    _ram[physical_addr] = data;
    pthread_mutex_unlock(&ram_lock);
    return 0;
  }
  else
  {
    return 1;
  }
}

void dump(void)
{
  int i;
  for (i = 0; i < NUM_PAGES; i++)
  {
    if (_mem_stat[i].proc != 0)
    {
      printf("%03d: ", i);
      printf("%05x-%05x - PID: %02d (idx %03d, nxt: %03d)\n",
             i << OFFSET_LEN,
             ((i + 1) << OFFSET_LEN) - 1,
             _mem_stat[i].proc,
             _mem_stat[i].index,
             _mem_stat[i].next);
      int j;
      for (j = i << OFFSET_LEN;
           j < ((i + 1) << OFFSET_LEN) - 1;
           j++)
      {

        if (_ram[j] != 0)
        {
          printf("\t%05x: %02x\n", j, _ram[j]);
        }
      }
    }
  }
}
