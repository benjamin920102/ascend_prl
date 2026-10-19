#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
/* Scalar BLAKE3, 32-byte digest only. No SIMD, heap, threads, or host library
 * dependency. Chunk counters and parent/root flags follow the BLAKE3 spec. */
namespace pearl_b3 {
static const uint32_t iv[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
static const unsigned perm[16]={2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8};
inline uint32_t load(const uint8_t *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
inline uint32_t rotr(uint32_t v,unsigned n){return v>>n|v<<(32-n);}
inline void g(uint32_t *v,int a,int b,int c,int d,uint32_t x,uint32_t y){
 v[a]+=v[b]+x;v[d]=rotr(v[d]^v[a],16);v[c]+=v[d];v[b]=rotr(v[b]^v[c],12);
 v[a]+=v[b]+y;v[d]=rotr(v[d]^v[a],8);v[c]+=v[d];v[b]=rotr(v[b]^v[c],7);
}
struct Output{uint32_t cv[8],block[16];uint64_t counter;uint32_t len,flags;};
inline void compress(const Output &o,uint32_t out[8],bool root=false){
 uint32_t v[16],m[16],t[16];memcpy(v,o.cv,32);memcpy(v+8,iv,16);memcpy(m,o.block,64);
 uint64_t ctr=root?0:o.counter;v[12]=(uint32_t)ctr;v[13]=(uint32_t)(ctr>>32);v[14]=o.len;v[15]=o.flags|(root?8:0);
 for(int r=0;r<7;r++){
  g(v,0,4,8,12,m[0],m[1]);g(v,1,5,9,13,m[2],m[3]);g(v,2,6,10,14,m[4],m[5]);g(v,3,7,11,15,m[6],m[7]);
  g(v,0,5,10,15,m[8],m[9]);g(v,1,6,11,12,m[10],m[11]);g(v,2,7,8,13,m[12],m[13]);g(v,3,4,9,14,m[14],m[15]);
  for(int i=0;i<16;i++)t[i]=m[perm[i]];memcpy(m,t,64);
 }for(int i=0;i<8;i++)out[i]=v[i]^v[i+8];
}
inline Output parent(const uint32_t left[8],const uint32_t right[8],const uint32_t key[8],uint32_t flags){
 Output o;memcpy(o.cv,key,32);memcpy(o.block,left,32);memcpy(o.block+8,right,32);o.counter=0;o.len=64;o.flags=flags|4;return o;
}
inline void hash(const uint8_t *data,size_t len,const uint8_t *keyBytes,uint8_t out[32]){
 uint32_t key[8],flags=keyBytes?16:0,stack[64][8];unsigned depth=0;
 for(int i=0;i<8;i++)key[i]=keyBytes?load(keyBytes+4*i):iv[i];
 size_t chunks=(len+1023)/1024;if(!chunks)chunks=1;Output o={};
 for(size_t ch=0;ch<chunks;ch++){
  uint32_t cv[8];memcpy(cv,key,32);size_t clen=len-ch*1024;if(clen>1024)clen=1024;
  size_t blocks=(clen+63)/64;if(!blocks)blocks=1;
  for(size_t b=0;b<blocks;b++){
   uint8_t buf[64]={};size_t n=clen-b*64;if(n>64)n=64;
   if(n)memcpy(buf,data+ch*1024+b*64,n);
   memcpy(o.cv,cv,32);for(int i=0;i<16;i++)o.block[i]=load(buf+4*i);
   o.counter=ch;o.len=(uint32_t)n;o.flags=flags|(b==0?1:0)|(b+1==blocks?2:0);
   if(b+1<blocks)compress(o,cv);
  }
  if(ch+1<chunks){compress(o,cv);size_t total=ch+1;
   while(!(total&1)){o=parent(stack[--depth],cv,key,flags);compress(o,cv);total>>=1;}
   memcpy(stack[depth++],cv,32);
  }
 }
 while(depth){uint32_t cv[8];compress(o,cv);o=parent(stack[--depth],cv,key,flags);}
 uint32_t words[8];compress(o,words,true);for(int i=0;i<32;i++)out[i]=(uint8_t)(words[i/4]>>(8*(i%4)));
}
}
