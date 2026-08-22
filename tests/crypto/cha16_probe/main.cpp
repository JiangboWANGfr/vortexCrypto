// Host for the poly4.step.sg16 probe: generates random (h, r, m) trials, runs
// them through the instruction, and compares against the same reference the
// software Poly1305 uses -- four sequential block updates.
#include <vortex2.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "common.h"

#define CHECK(x) do { int _e=(x); if(_e){ std::printf("FATAL: %s = %d\n",#x,_e); std::exit(1);} } while(0)

static inline uint32_t rol32(uint32_t v,uint32_t n){ return (v<<n)|(v>>(32-n)); }
static void ref_dr(uint32_t x[16]) {
  auto qr=[&](int a,int b,int c,int d){
    x[a]+=x[b]; x[d]^=x[a]; x[d]=rol32(x[d],16);
    x[c]+=x[d]; x[b]^=x[c]; x[b]=rol32(x[b],12);
    x[a]+=x[b]; x[d]^=x[a]; x[d]=rol32(x[d],8);
    x[c]+=x[d]; x[b]^=x[c]; x[b]=rol32(x[b],7);
  };
  for(int g=0;g<4;++g) qr(g,g+4,g+8,g+12);
  for(int g=0;g<4;++g) qr(g,4+((g+1)&3),8+((g+2)&3),12+((g+3)&3));
}

int main(int argc, char** argv) {
  (void)argc; (void)argv;
  vx_device_h dev=nullptr;
  CHECK(vx_device_open(0,&dev));
  uint64_t nt=0, nc=0, isa=0;
  CHECK(vx_device_query(dev,VX_CAPS_NUM_THREADS,&nt));
  CHECK(vx_device_query(dev,VX_CAPS_NUM_CORES,&nc));
  CHECK(vx_device_query(dev,VX_CAPS_ISA_FLAGS,&isa));
  if ((isa & VX_ISA_EXT_SYM)==0 || nt < 16 || (nt % 16)) {
    std::printf("SKIPPED: needs EX_SYM and a multiple of 16 threads, has %lu\n",(unsigned long)nt);
    vx_device_release(dev); return 0;
  }

  const uint32_t trials = CHA16_TRIALS;
  std::vector<uint32_t> in((size_t)16*trials), exp((size_t)16*trials);
  uint32_t seed = 0x1234567u;
  auto rnd=[&]{ seed=seed*1664525u+1013904223u; return seed; };
  for (uint32_t t=0;t<trials;++t) {
    uint32_t x[16];
    for (int i=0;i<16;++i){ x[i]=rnd(); in[(size_t)16*t+i]=x[i]; }
    ref_dr(x);
    for (int i=0;i<16;++i) exp[(size_t)16*t+i]=x[i];
  }
  const uint64_t in_b=in.size()*4, out_b=exp.size()*4;
  vx_buffer_h ib=nullptr, ob=nullptr;
  CHECK(vx_buffer_create(dev,in_b,VX_MEM_READ_WRITE,&ib));
  CHECK(vx_buffer_create(dev,out_b,VX_MEM_READ_WRITE,&ob));
  uint64_t ia=0, oa=0;
  CHECK(vx_buffer_address(ib,&ia)); CHECK(vx_buffer_address(ob,&oa));

  vx_module_h mod=nullptr; vx_kernel_h kern=nullptr;
  CHECK(vx_module_load_file(dev,"kernel.vxbin",&mod));
  if (vx_module_get_kernel(mod,"cha16_probe",&kern)!=0) {
    std::printf("SKIPPED: kernel not built (needs SYM_CHACHA_SG16)\n");
    vx_device_release(dev); return 0;
  }

  kernel_arg_t ka; std::memset(&ka,0,sizeof(ka));
  ka.in=ia; ka.out=oa; ka.trials=trials;
  vx_launch_info_t li; std::memset(&li,0,sizeof(li));
  li.struct_size=sizeof(li); li.kernel=kern; li.args_host=&ka; li.args_size=sizeof(ka);
  li.ndim=1; li.grid_dim[0]=(uint32_t)nc; li.grid_dim[1]=1; li.grid_dim[2]=1;
  li.block_dim[0]=(uint32_t)nt; li.block_dim[1]=1; li.block_dim[2]=1;

  vx_queue_info_t qi={sizeof(qi),nullptr,VX_QUEUE_PRIORITY_NORMAL,0};
  vx_queue_h q=nullptr; CHECK(vx_queue_create(dev,&qi,&q));
  std::vector<uint32_t> got(exp.size(),0xDEADBEEFu);
  vx_event_h we=nullptr,le=nullptr,re=nullptr;
  CHECK(vx_enqueue_write(q,ib,0,in.data(),in_b,0,nullptr,&we));
  CHECK(vx_event_wait_value(we,1,VX_TIMEOUT_INFINITE));
  CHECK(vx_enqueue_launch(q,&li,0,nullptr,&le));
  CHECK(vx_enqueue_read(q,got.data(),ob,0,out_b,1,&le,&re));
  CHECK(vx_event_wait_value(re,1,VX_TIMEOUT_INFINITE));

  uint32_t bad=0;
  for (size_t i=0;i<exp.size();++i) {
    if (got[i]!=exp[i]) {
      if (bad<5) std::printf("  trial %zu word %zu: got 0x%08x want 0x%08x\n",i/16,i%16,got[i],exp[i]);
      ++bad;
    }
  }
  std::printf(bad ? "FAILED: %u/%zu words wrong\n" : "PASSED: %u errors, %zu words over %u trials\n",
              bad, exp.size(), trials);
  CHECK(vx_queue_release(q)); CHECK(vx_buffer_release(ib)); CHECK(vx_buffer_release(ob));
  CHECK(vx_device_release(dev));
  return bad!=0;
}
