/* netstr.c */
long netstr_getlen_buf(buffer *b);
void netstr_read_buf(buffer *b, stralloc *sa);
long netstr_getlen(char *s);
void netstr_write_buf(buffer *b, const char *s, const unsigned int n);
void netstr_write_stralloc(stralloc *sa, const char *s, const unsigned int n);
