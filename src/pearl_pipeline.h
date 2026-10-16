/* Shared host strip queue depth; independent of the cube/vec BUFS ring. */
#ifndef PEARL_PIPELINE_H
#define PEARL_PIPELINE_H
#ifndef PEARL_PIPE_DEPTH
#define PEARL_PIPE_DEPTH 4
#endif
#if PEARL_PIPE_DEPTH < 1
#error "PEARL_PIPE_DEPTH must be positive"
#endif
#endif
