#include <string.h>
#include <stdlib.h>

#include <list>
#include <vector>
#include <iostream>

#include <node.h>
#include <node_buffer.h>
#include <nan.h>

#include "../../deps/lz4/lib/lz4.h"
#include "../../deps/lz4/lib/lz4hc.h"

using namespace node;
using namespace v8;

//-----------------------------------------------------------------------------
// LZ4 Compress
//-----------------------------------------------------------------------------
// Simple functions

// {Buffer} input, {Buffer} output
NAN_METHOD(LZ4Compress) {
  NanScope();

  uint32_t alen = args.Length();
  if (alen < 2 && alen > 4) {
    NanThrowError(Exception::Error(NanNew<String>("Wrong number of arguments")));
    NanReturnUndefined();
  }

  if (!Buffer::HasInstance(args[0]) || !Buffer::HasInstance(args[1])) {
    NanThrowError(Exception::TypeError(NanNew<String>("Wrong arguments")));
    NanReturnUndefined();
  }
  Local<Object> input = args[0]->ToObject();
  Local<Object> output = args[1]->ToObject();

  Local<Integer> result;
  uint32_t sIdx = 0;
  uint32_t eIdx = Buffer::Length(output);
  switch (alen) {
  case 4:
    if (!args[3]->IsUint32()) {
      NanThrowError(Exception::TypeError(NanNew<String>("Invalid endIdx")));
      NanReturnUndefined();
    }
    if (!args[2]->IsUint32()) {
      NanThrowError(Exception::TypeError(NanNew<String>("Invalid startIdx")));
      NanReturnUndefined();
    }
    sIdx = args[2]->Uint32Value();
    eIdx = args[3]->Uint32Value();
    result = NanNew<Integer>(LZ4_compress_limitedOutput(Buffer::Data(input),
                                                        Buffer::Data(output) + sIdx,
                                                        Buffer::Length(input),
                                                        eIdx - sIdx)
                            );
    break;
  case 3:
    if (!args[2]->IsUint32()) {
      NanThrowError(Exception::TypeError(NanNew<String>("Invalid startIdx")));
      NanReturnUndefined();
    }
    sIdx = args[2]->Uint32Value();
  case 2:
    result = NanNew<Integer>(LZ4_compress(Buffer::Data(input),
                                          Buffer::Data(output) + sIdx,
                                          Buffer::Length(input))
                            );
  }

  NanReturnValue(result);
}

// {Buffer} input, {Buffer} output
NAN_METHOD(LZ4CompressHC) {
  NanScope();

  if (args.Length() != 2) {
    NanThrowError(Exception::Error(NanNew<String>("Wrong number of arguments")));
    NanReturnUndefined();
  }

  if (!Buffer::HasInstance(args[0]) || !Buffer::HasInstance(args[1])) {
    NanThrowError(Exception::TypeError(NanNew<String>("Wrong arguments")));
    NanReturnUndefined();
  }

  Local<Object> input = args[0]->ToObject();
  Local<Object> output = args[1]->ToObject();

  Local<Integer> result = NanNew<Integer>(LZ4_compressHC(Buffer::Data(input),
                                                         Buffer::Data(output),
                                                         Buffer::Length(input))
                                         );
  NanReturnValue(result);
}

// Advanced functions

// {Integer} Buffer size
NAN_METHOD(LZ4CompressBound) {
  NanScope();

  if (args.Length() != 1) {
    NanThrowError(Exception::Error(NanNew<String>("Wrong number of arguments")));
    NanReturnUndefined();
  }

  if (!args[0]->IsUint32()) {
    NanThrowError(Exception::TypeError(NanNew<String>("Wrong arguments")));
    NanReturnUndefined();
  }

  uint32_t size = args[0]->Uint32Value();

  NanReturnValue(
    NanNew<Integer>(LZ4_compressBound(size))
  );
}

// {Buffer} input, {Buffer} output, {Integer} maxOutputSize
NAN_METHOD(LZ4CompressLimited) {
  NanScope();

  if (args.Length() != 3) {
    NanThrowError(Exception::Error(NanNew<String>("Wrong number of arguments")));
    NanReturnUndefined();
  }

  if (!Buffer::HasInstance(args[0]) || !Buffer::HasInstance(args[1])) {
    NanThrowError(Exception::TypeError(NanNew<String>("Wrong arguments")));
    NanReturnUndefined();
  }

  if (!args[2]->IsUint32()) {
    NanThrowError(Exception::TypeError(NanNew<String>("Wrong arguments")));
    NanReturnUndefined();
  }

  Local<Object> input = args[0]->ToObject();
  Local<Object> output = args[1]->ToObject();
  uint32_t size = args[2]->Uint32Value();

  Local<Integer> result = NanNew<Integer>(LZ4_compress_limitedOutput(Buffer::Data(input),
                                                                     Buffer::Data(output),
                                                                     Buffer::Length(input),
                                                                     size)
                                         );
  NanReturnValue(result);
}

// {Buffer} input, {Buffer} output, {Integer} maxOutputSize
NAN_METHOD(LZ4CompressHCLimited) {
  NanScope();

  if (args.Length() != 3) {
    NanThrowError(Exception::Error(NanNew<String>("Wrong number of arguments")));
    NanReturnUndefined();
  }

  if (!Buffer::HasInstance(args[0]) || !Buffer::HasInstance(args[1])) {
    NanThrowError(Exception::TypeError(NanNew<String>("Wrong arguments")));
    NanReturnUndefined();
  }

  if (!args[2]->IsUint32()) {
    NanThrowError(Exception::TypeError(NanNew<String>("Wrong arguments")));
    NanReturnUndefined();
  }

  Local<Object> input = args[0]->ToObject();
  Local<Object> output = args[1]->ToObject();
  uint32_t size = args[2]->Uint32Value();

  Local<Integer> result = NanNew<Integer>(LZ4_compressHC_limitedOutput(Buffer::Data(input),
                                                                       Buffer::Data(output),
                                                                       Buffer::Length(input),
                                                                       size)
                                         );
  NanReturnValue(result);
}

//-----------------------------------------------------------------------------
// LZ4 Stream
//-----------------------------------------------------------------------------
// {Buffer} input
NAN_METHOD(LZ4Stream_create) {
  NanScope();

  if (args.Length() != 1) {
    NanThrowError(Exception::Error(NanNew<String>("Wrong number of arguments")));
    NanReturnUndefined();
  }

  if (!Buffer::HasInstance(args[0])) {
    NanThrowError(Exception::TypeError(NanNew<String>("Wrong arguments")));
    NanReturnUndefined();
  }

  Local<Object> input = args[0]->ToObject();

  void* p = LZ4_create( Buffer::Data(input) );

  if (p == NULL) {
    NanReturnUndefined();
  }

  Local<Object> handle = NanNewBufferHandle((char *) p, LZ4_sizeofStreamState());

  NanReturnValue(handle);
}

// {Buffer} lz4 data struct, {Buffer} input, {Buffer} output
NAN_METHOD(LZ4Stream_compress_continue) {
  NanScope();

  if (args.Length() != 3) {
    NanThrowError(Exception::Error(NanNew<String>("Wrong number of arguments")));
    NanReturnUndefined();
  }

  if (!Buffer::HasInstance(args[0]) || !Buffer::HasInstance(args[1]) || !Buffer::HasInstance(args[2])) {
    NanThrowError(Exception::TypeError(NanNew<String>("Wrong arguments")));
    NanReturnUndefined();
  }

  Local<Object> lz4ds = args[0]->ToObject();
  Local<Object> input = args[1]->ToObject();
  Local<Object> output = args[2]->ToObject();

  Local<Integer> result = NanNew<Integer>(LZ4_compress_continue(
                                            (LZ4_stream_t*) Buffer::Data(lz4ds),
                                            Buffer::Data(input),
                                            Buffer::Data(output),
                                            Buffer::Length(input))
                                         );
  NanReturnValue(result);
}

// {Buffer} input, {Buffer} lz4 data struct
NAN_METHOD(LZ4Stream_slideInputBuffer) {
  NanScope();

  if (args.Length() != 2) {
    NanThrowError(Exception::Error(NanNew<String>("Wrong number of arguments")));
    NanReturnUndefined();
  }

  if (!Buffer::HasInstance(args[0]) || !Buffer::HasInstance(args[1])) {
    NanThrowError(Exception::TypeError(NanNew<String>("Wrong arguments")));
    NanReturnUndefined();
  }

  Local<Object> lz4ds = args[0]->ToObject();
  Local<Object> input = args[1]->ToObject();

  // Pointer to the position into the input buffer where the next data block should go
  char* input_next_block = LZ4_slideInputBuffer( Buffer::Data(lz4ds) );
  char* input_current = (char *)Buffer::Data(input);

  // Return the position of the next block
  NanReturnValue(NanNew<Integer>((int)(input_next_block - input_current)));
}

// {Buffer} lz4 data struct
NAN_METHOD(LZ4Stream_free) {
  NanScope();

  if (args.Length() != 1) {
    NanThrowError(Exception::Error(NanNew<String>("Wrong number of arguments")));
    NanReturnUndefined();
  }

  if (!Buffer::HasInstance(args[0])) {
    NanThrowError(Exception::TypeError(NanNew<String>("Wrong arguments")));
    NanReturnUndefined();
  }

  Local<Object> lz4ds = args[0]->ToObject();
  int res = LZ4_freeStream( (LZ4_stream_t*) Buffer::Data(lz4ds) );

  NanReturnValue(NanNew<Integer>(res));
}

//-----------------------------------------------------------------------------
// LZ4 Uncompress
//-----------------------------------------------------------------------------
// {Buffer} input, {Buffer} output
NAN_METHOD(LZ4Uncompress) {
  NanScope();

  uint32_t alen = args.Length();
  if (alen < 2 && alen > 4) {
    NanThrowError(Exception::Error(NanNew<String>("Wrong number of arguments")));
    NanReturnUndefined();
  }

  if (!Buffer::HasInstance(args[0]) || !Buffer::HasInstance(args[1])) {
    NanThrowError(Exception::TypeError(NanNew<String>("Wrong arguments")));
    NanReturnUndefined();
  }
  Local<Object> input = args[0]->ToObject();
  Local<Object> output = args[1]->ToObject();

  Local<Integer> result;
  uint32_t sIdx = 0;
  uint32_t eIdx = Buffer::Length(input);
  switch (alen) {
  case 4:
    if (!args[3]->IsUint32()) {
      NanThrowError(Exception::TypeError(NanNew<String>("Invalid endIdx")));
      NanReturnUndefined();
    }
    if (!args[2]->IsUint32()) {
      NanThrowError(Exception::TypeError(NanNew<String>("Invalid startIdx")));
      NanReturnUndefined();
    }
    sIdx = args[2]->Uint32Value();
    eIdx = args[3]->Uint32Value();
    result = NanNew<Integer>(LZ4_decompress_safe(Buffer::Data(input) + sIdx,
                                                 Buffer::Data(output),
                                                 eIdx - sIdx,
                                                 Buffer::Length(output))
                            );
    break;
  case 3:
    if (!args[2]->IsInt32()) {
      NanThrowError(Exception::TypeError(NanNew<String>("Invalid startIdx")));
      NanReturnUndefined();
    }
    sIdx = args[2]->Uint32Value();
  case 2:
    result = NanNew<Integer>(LZ4_decompress_safe(Buffer::Data(input) + sIdx,
                                                 Buffer::Data(output),
                                                 eIdx - sIdx,
                                                 Buffer::Length(output))
                            );
  }

  NanReturnValue(result);
}

//-----------------------------------------------------------------------------
// LZ4 Compress_full
//-----------------------------------------------------------------------------
// {Buffer} input
NAN_METHOD(LZ4Compress_full) {
  NanScope();

  uint32_t alen = args.Length();
  if (alen != 1) {
    NanThrowError(Exception::Error(NanNew<String>("Wrong number of arguments")));
    NanReturnUndefined();
  }

  if (!Buffer::HasInstance(args[0])) {
    NanThrowError(Exception::TypeError(NanNew<String>("Wrong arguments")));
    NanReturnUndefined();
  }
  Local<Object> input = args[0]->ToObject();

  char* data = Buffer::Data(input);
  std::size_t size = Buffer::Length(input);
  int max = LZ4_compressBound(size);
  char* buf = new char[max];

  int count = LZ4_compress(data, buf, size);
  if (count < 0)
    NanThrowError(Exception::Error(NanNew<String>("Encoder failure")));

  NanReturnValue(NanBufferUse(buf, count));
}

//-----------------------------------------------------------------------------
// LZ4 Uncompress_full
//-----------------------------------------------------------------------------
// {Buffer} input
NAN_METHOD(LZ4Uncompress_full) {
  NanScope();

  uint32_t alen = args.Length();
  if (alen != 1) {
    NanThrowError(Exception::Error(NanNew<String>("Wrong number of arguments")));
    NanReturnUndefined();
  }

  if (!Buffer::HasInstance(args[0])) {
    NanThrowError(Exception::TypeError(NanNew<String>("Wrong arguments")));
    NanReturnUndefined();
  }
  Local<Object> input = args[0]->ToObject();

  std::list<std::vector<char>*> blocks;

  char* data = Buffer::Data(input);
  int size = Buffer::Length(input);

  int block_size = 1024;
  int chunk_size = LZ4_compressBound(block_size);
  int offset = 0;
  int total = 0;

  LZ4_streamDecode_t* stream = LZ4_createStreamDecode();
  while (offset < size) {
    std::vector<char>* buf = new std::vector<char>(block_size);
    int next = std::min(size - offset, chunk_size);
    int bytes = LZ4_decompress_safe_continue(stream, data + offset, &(*buf)[0], next, block_size);
    if (bytes < 0) {
      for (std::list<std::vector<char>*>::iterator itr = blocks.begin(); itr != blocks.end(); ++itr)
        delete *itr;
      NanThrowError(Exception::Error(NanNew<String>("Decoder failure")));
    }
    buf->resize(bytes);
    offset += chunk_size;
    total += bytes;
    blocks.push_back(buf);
    break;
  }
  LZ4_freeStreamDecode(stream);

  char* buf = new char[total];
  char* ptr = buf;
  for (std::list<std::vector<char>*>::iterator itr = blocks.begin(); itr != blocks.end(); ++itr) {
    std::copy((*itr)->begin(), (*itr)->end(), ptr);
    ptr += (*itr)->size();
    delete *itr;
  }
  NanReturnValue(NanNewBufferHandle(buf, total));
}

// {Buffer} input, {Buffer} output
NAN_METHOD(LZ4Uncompress_fast) {
  NanScope();

  if (args.Length() != 2) {
    NanThrowError(Exception::Error(NanNew<String>("Wrong number of arguments")));
    NanReturnUndefined();
  }

  if (!Buffer::HasInstance(args[0]) || !Buffer::HasInstance(args[1])) {
    NanThrowError(Exception::TypeError(NanNew<String>("Wrong arguments")));
    NanReturnUndefined();
  }

  Local<Object> input = args[0]->ToObject();
  Local<Object> output = args[1]->ToObject();

  Local<Integer> result = NanNew<Integer>(LZ4_decompress_fast(Buffer::Data(input),
                                                              Buffer::Data(output),
                                                              Buffer::Length(output))
                                         );
  NanReturnValue(result);
}

void init_lz4(Handle<Object> target) {
  NanScope();

  target->Set(NanNew<String>("compressBound"), NanNew<FunctionTemplate>(LZ4CompressBound)->GetFunction());
  target->Set(NanNew<String>("compress"), NanNew<FunctionTemplate>(LZ4Compress)->GetFunction());
  target->Set(NanNew<String>("compressLimited"), NanNew<FunctionTemplate>(LZ4CompressLimited)->GetFunction());

  target->Set(NanNew<String>("lz4s_create"), NanNew<FunctionTemplate>(LZ4Stream_create)->GetFunction());
  target->Set(NanNew<String>("lz4s_compress_continue"), NanNew<FunctionTemplate>(LZ4Stream_compress_continue)->GetFunction());
  target->Set(NanNew<String>("lz4s_slide_input"), NanNew<FunctionTemplate>(LZ4Stream_slideInputBuffer)->GetFunction());
  target->Set(NanNew<String>("lz4s_free"), NanNew<FunctionTemplate>(LZ4Stream_free)->GetFunction());

  target->Set(NanNew<String>("compressHC"), NanNew<FunctionTemplate>(LZ4CompressHC)->GetFunction());
  target->Set(NanNew<String>("compressHCLimited"), NanNew<FunctionTemplate>(LZ4CompressHCLimited)->GetFunction());
  target->Set(NanNew<String>("compress_full"), NanNew<FunctionTemplate>(LZ4Compress_full)->GetFunction());

  target->Set(NanNew<String>("uncompress"), NanNew<FunctionTemplate>(LZ4Uncompress)->GetFunction());
  target->Set(NanNew<String>("uncompress_fast"), NanNew<FunctionTemplate>(LZ4Uncompress_fast)->GetFunction());
  target->Set(NanNew<String>("uncompress_full"), NanNew<FunctionTemplate>(LZ4Uncompress_full)->GetFunction());
}

NODE_MODULE(lz4, init_lz4)
