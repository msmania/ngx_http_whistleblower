#include <ngx_core.h>

typedef struct ngx_chain_cursor_s {
  ngx_chain_t* chain;
  int pos;
} ngx_chain_cursor_t;

u_char get_char_at(const ngx_chain_cursor_t* cursor) {
  return cursor->chain->buf->pos[cursor->pos];
}

int move_next(ngx_chain_cursor_t* cursor) {
  u_char* range_start = cursor->chain->buf->pos;
  u_char* range_end = cursor->chain->buf->last;
  u_char* current_pos = range_start + cursor->pos;
  if (current_pos < range_end) {
    ++cursor->pos;
    return 1;
  }

  ngx_chain_t* next_buf = cursor->chain->next;
  if (!next_buf) {
    return 0; // We're at the very end.
  }

  cursor->chain = next_buf;
  cursor->pos = 0;
  return 1;
}

int search_chunked_strings(
    ngx_log_t* logger,
    ngx_chain_t *haystacks, const char* needle, ngx_chain_cursor_t* result) {
  int needle_len = strlen(needle);
  int* partial_match = calloc(needle_len, sizeof(int));
  ngx_chain_t* result_haystack_chain = NULL;
  int result_haystack_pos = -1;

  for (ngx_chain_t* p = haystacks; p && !partial_match[0]; p = p->next) {
    const u_char* haystack = p->buf->pos;
    int haystack_len = p->buf->last - p->buf->pos;
    for (int j = 0; j < needle_len && !partial_match[0]; ++j) {
      // j: remaining characters to match
      if (!partial_match[j]) {
        continue;
      }

      partial_match[j] = 0;

      const char* needle_search_start = needle + needle_len - j;
      int compare_len = j;
      if (compare_len > haystack_len) {
        compare_len = haystack_len;
      }
      if (!memcmp(needle_search_start, haystack, compare_len)) {
        int remaining = j - compare_len;
        if (!remaining) {
          result_haystack_chain = p;
          result_haystack_pos = compare_len;
        }
        ngx_log_debug5(NGX_LOG_DEBUG, logger, 0,
            "Matched: %p[%d..%d] == needle[%d..%d]\n",
            p->buf, 0, compare_len,
            needle_len - j, needle_len - j + compare_len);
        partial_match[remaining] = 1;
      }
    }

    for (int j = 0; j < haystack_len; ++j) {
      int compare_len = haystack_len - j;
      if (compare_len > needle_len) {
        compare_len = needle_len;
      }
      if (!memcmp(needle, haystack + j, compare_len)) {
        int remaining = needle_len - compare_len;
        if (!remaining) {
          result_haystack_chain = p;
          result_haystack_pos = j + compare_len;
        }
        ngx_log_debug5(NGX_LOG_DEBUG, logger, 0,
            "Matched: %p[%d..%d] == needle[%d..%d]\n",
            p->buf, j, j + compare_len,
            0, compare_len);
        partial_match[remaining] = 1;
      }
    }
  }

  int ok = partial_match[0] ? 1 : 0;
  free(partial_match);

  if (ok && result) {
    result->chain = result_haystack_chain;
    result->pos = result_haystack_pos;
  }
  return ok;
}

u_int32_t extract_field(
    ngx_log_t* logger, ngx_chain_t *in, const char* field_name) {
  ngx_chain_cursor_t cursor;
  if (!search_chunked_strings(logger, in, field_name, &cursor)) {
    return 0;
  }

  u_char c = get_char_at(&cursor);
  while (isspace(c)) {
    if (!move_next(&cursor)) {
      return 0;
    }
    c = get_char_at(&cursor);
  }

  if (get_char_at(&cursor) != ':') {
    return 0;
  }
  move_next(&cursor);

  c = get_char_at(&cursor);
  while (isspace(c)) {
    if (!move_next(&cursor)) {
      return 0;
    }
    c = get_char_at(&cursor);
  }

  if (get_char_at(&cursor) != '"') {
    return 0;
  }
  move_next(&cursor);

  u_int32_t chainId = 0;
  for (int i = 0; i < 4; ++i) {
    u_char c = get_char_at(&cursor);
    if (c >= '0' && c <= '9') {
      chainId = (chainId << 4) + (c - '0');
    }
    else if (c >= 'A' && c <= 'F') {
      chainId = (chainId << 4) + (c - 'A' + 10);
    }
    else if (c >= 'a' && c <= 'f') {
      chainId = (chainId << 4) + (c - 'a' + 10);
    }
    else {
      return 0;
    }
    move_next(&cursor);
  }

  if (get_char_at(&cursor) != '"') {
    return 0;
  }

  chainId = (((chainId & 0xff) << 8 ) | (chainId >> 8)) & 0xffff;
  return chainId;
}
