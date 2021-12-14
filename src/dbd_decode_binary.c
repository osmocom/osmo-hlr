/* This function is blatantly copied from libdbi, from
 * https://sourceforge.net/p/libdbi/libdbi/ci/master/tree/src/dbd_helper.c
 * to save having to depend on the entire libdbi just for KI BLOB decoding.
 */

/*
 * libdbi - database independent abstraction layer for C.
 * Copyright (C) 2001-2003, David Parker and Mark Tobenkin.
 * http://libdbi.sourceforge.net
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * $Id: dbd_helper.c,v 1.44 2011/08/09 11:14:14 mhoenicka Exp $
 */

#include <sys/types.h>

size_t _dbd_decode_binary(const unsigned char *in, unsigned char *out){
  int i, e;
  unsigned char c;
  e = *(in++);
  i = 0;
  while( (c = *(in++))!=0 ){
    if( c==1 ){
      c = *(in++) - 1;
    }
    out[i++] = c + e;
  }
  return (size_t)i;
}
