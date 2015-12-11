#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <math.h>
#include <time.h>

#include <net/net.h>

#include <ps3dm_msg.h>
#include <lv2_syscall.h>
#include <lv1_map.h>
#include <sysmodule/sysmodule.h>
#include <udp_printf.h>
#include <ppu-lv2.h>
#include <lv2/sysfs.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <lv2/process.h>
#include <sysutil/msg.h>
#include <sysutil/sysutil.h>
#include <tiny3d.h>
#include <libfont.h>
#include <io/pad.h>
#include <sys/memory.h>
#include <sys/process.h>
#include <storage.h>
#include <mm.h>
#include <dispmgr.h>

int is_firm_465(void)
{
    // TOC 4.65
   u64 toc;
   toc =lv2_peek(0x8000000000003000ULL);
   if(toc == 0x800000000034F960ULL)
   {
      return 1;
   }
   else
   {
      return 0;
   }
}

void util_qa(void);
void util_qa(void)
{
if(is_firm_465())
{
lv2_lv1_poke(0xfebd4, 0x380000002FA00000ULL);
lv2_lv1_poke(0x16fa60, 0x7F83E37860000000ULL); 
lv2_lv1_poke(0x16fa88, 0x386000015463063EULL);
lv2_lv1_poke(0x16fb00, 0x3BE000019BE10070ULL);
lv2_lv1_poke(0x16fb08, 0x386000002F830000ULL);
lv2_lv1_poke(0x16fb64, 0x2f80000048000050ULL);
lv2_poke(0x8000000000363260ull+0x810, 0x80000000000017a0ull);
lv2_poke(0x80000000000017a0ull, 0x80000000000017b0ull);
}
else if(is_firm_355())
{
lv2_lv1_poke(0xfdbb4, 0x380000002FA00000ULL);
lv2_lv1_poke(0x16f3b8, 0x7F83E37860000000ULL); 
lv2_lv1_poke(0x16f3e0, 0x386000015463063EULL);
lv2_lv1_poke(0x16f458, 0x3BE000019BE10070ULL);
lv2_lv1_poke(0x16f460, 0x386000002F830000ULL);
lv2_lv1_poke(0x16f4bc, 0x2f80000048000050ULL);
}
else if((!is_firm_465()) && (!is_firm_355()))
{
lv2_poke(0x80000000000017a0ull, 0x80000000000017b0ull);
for(uint64_t c=0x8000000000340000ULL;c<0x80000000007FFFFFULL;c+=8)
{
uint64_t q1;
uint64_t q2;
q1=lv2_peek(c);
q2=lv2_peek(c+8);
if((q1==0xCB376F5D5C4393A4) && (q2==0xBA5335900372C9D1))
{
lv2_poke(c+0x810, 0x80000000000017a0ull);
break;
}
}
for(uint64_t a=0xA000;a<0x1000000;a+=8)
{
uint64_t q1;
uint64_t q2;
q1=lv2_lv1_peek(a);
q2=lv2_lv1_peek(a+8);
if((q1==0xE81800082FA00000) && (q2==0x409E00107FC3F378))
{
lv2_lv1_poke(a, 0x380000002FA00000ULL);
break;
}
}
for(uint64_t b=0xA000;b<0x1000000;b+=8)
{
uint64_t q1;
uint64_t q2;
q1=lv2_lv1_peek(b);
q2=lv2_lv1_peek(b+8);
if((q1==0x7C7F1B78419E0020) && (q2==0x7C6607B4E8A285D0))
{
b+=0x40;
lv2_lv1_poke(b, 0x7F83E37860000000ULL);
lv2_lv1_poke(b+0x28, 0x386000015463063EULL);
lv2_lv1_poke(b+0xa0, 0x3BE000019BE10070ULL);
lv2_lv1_poke(b+0xa8, 0x386000002F830000ULL);
lv2_lv1_poke(b+0x104, 0x2f80000048000050ULL);
break;
}
}
}
toggle_qa_flag();
}

int main()
{
util_qa();
}
