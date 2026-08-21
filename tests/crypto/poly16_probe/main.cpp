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

static void ref_step16(uint32_t h[5], const uint32_t r[5], const uint32_t m[16]) {
  for (uint32_t b = 0; b < 4; ++b) {
    const uint32_t t0=m[4*b], t1=m[4*b+1], t2=m[4*b+2], t3=m[4*b+3];
    uint32_t a0=h[0]+(t0&0x3ffffffu), a1=h[1]+(((t0>>26)|(t1<<6))&0x3ffffffu);
    uint32_t a2=h[2]+(((t1>>20)|(t2<<12))&0x3ffffffu);
    uint32_t a3=h[3]+(((t2>>14)|(t3<<18))&0x3ffffffu);
    uint32_t a4=h[4]+((t3>>8)|(1u<<24));
    const uint64_t s1=(uint64_t)r[1]*5,s2=(uint64_t)r[2]*5,s3=(uint64_t)r[3]*5,s4=(uint64_t)r[4]*5;
    uint64_t d0=(uint64_t)a0*r[0]+(uint64_t)a1*s4+(uint64_t)a2*s3+(uint64_t)a3*s2+(uint64_t)a4*s1;
    uint64_t d1=(uint64_t)a0*r[1]+(uint64_t)a1*r[0]+(uint64_t)a2*s4+(uint64_t)a3*s3+(uint64_t)a4*s2;
    uint64_t d2=(uint64_t)a0*r[2]+(uint64_t)a1*r[1]+(uint64_t)a2*r[0]+(uint64_t)a3*s4+(uint64_t)a4*s3;
    uint64_t d3=(uint64_t)a0*r[3]+(uint64_t)a1*r[2]+(uint64_t)a2*r[1]+(uint64_t)a3*r[0]+(uint64_t)a4*s4;
    uint64_t d4=(uint64_t)a0*r[4]+(uint64_t)a1*r[3]+(uint64_t)a2*r[2]+(uint64_t)a3*r[1]+(uint64_t)a4*r[0];
    uint32_t c=(uint32_t)(d0>>26); h[0]=(uint32_t)d0&0x3ffffffu;
    d1+=c; c=(uint32_t)(d1>>26); h[1]=(uint32_t)d1&0x3ffffffu;
    d2+=c; c=(uint32_t)(d2>>26); h[2]=(uint32_t)d2&0x3ffffffu;
    d3+=c; c=(uint32_t)(d3>>26); h[3]=(uint32_t)d3&0x3ffffffu;
    d4+=c; c=(uint32_t)(d4>>26); h[4]=(uint32_t)d4&0x3ffffffu;
    h[0]+=c*5; c=h[0]>>26; h[0]&=0x3ffffffu; h[1]+=c;
  }
}

int main(int argc, char** argv) {
  (void)argc; (void)argv;
  vx_device_h dev=nullptr;
  CHECK(vx_device_open(0,&dev));
  uint64_t nt=0, nc=0, isa=0;
  CHECK(vx_device_query(dev,VX_CAPS_NUM_THREADS,&nt));
  CHECK(vx_device_query(dev,VX_CAPS_NUM_CORES,&nc));
  CHECK(vx_device_query(dev,VX_CAPS_ISA_FLAGS,&isa));
  if ((isa & VX_ISA_EXT_AUTH)==0 || nt < 16 || (nt % 16)) {
    std::printf("SKIPPED: needs EX_AUTH and a multiple of 16 threads, has %lu\n",(unsigned long)nt);
    vx_device_release(dev); return 0;
  }

  const uint32_t trials = POLY16_TRIALS;
  std::vector<uint32_t> in((size_t)POLY16_IN_WORDS*trials), exp((size_t)POLY16_OUT_WORDS*trials);
  uint32_t seed = 0x1234567u;
  auto rnd=[&]{ seed=seed*1664525u+1013904223u; return seed; };
  for (uint32_t t=0;t<trials;++t) {
    uint32_t* p=&in[(size_t)POLY16_IN_WORDS*t];
    uint32_t h[5], r[5], m[16];
    for (int i=0;i<5;++i){ h[i]=rnd()&0x3ffffffu; r[i]=rnd()&0x3ffffffu; p[i]=h[i]; p[5+i]=r[i]; }
    for (int i=0;i<16;++i){ m[i]=rnd(); p[10+i]=m[i]; }
    ref_step16(h,r,m);
    for (int i=0;i<5;++i) exp[(size_t)POLY16_OUT_WORDS*t+i]=h[i];
  }

  const uint64_t in_b=in.size()*4, out_b=exp.size()*4;
  vx_buffer_h ib=nullptr, ob=nullptr;
  CHECK(vx_buffer_create(dev,in_b,VX_MEM_READ_WRITE,&ib));
  CHECK(vx_buffer_create(dev,out_b,VX_MEM_READ_WRITE,&ob));
  uint64_t ia=0, oa=0;
  CHECK(vx_buffer_address(ib,&ia)); CHECK(vx_buffer_address(ob,&oa));

  vx_module_h mod=nullptr; vx_kernel_h kern=nullptr;
  CHECK(vx_module_load_file(dev,"kernel.vxbin",&mod));
  if (vx_module_get_kernel(mod,"poly16_probe",&kern)!=0) {
    std::printf("SKIPPED: kernel not built (needs AUTH_POLY_STEP16)\n");
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
      if (bad<5) std::printf("  trial %zu limb %zu: got 0x%08x want 0x%08x\n",i/5,i%5,got[i],exp[i]);
      ++bad;
    }
  }
  std::printf(bad ? "FAILED: %u/%zu limbs wrong\n" : "PASSED: %u errors, %zu limbs over %u trials\n",
              bad, exp.size(), trials);
  CHECK(vx_queue_release(q)); CHECK(vx_buffer_release(ib)); CHECK(vx_buffer_release(ob));
  CHECK(vx_device_release(dev));
  return bad!=0;
}
