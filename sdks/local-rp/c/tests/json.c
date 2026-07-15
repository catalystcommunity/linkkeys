#include "json.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *p;
    const char *end;
} jcur;

static void skip_ws(jcur *c) {
    while (c->p < c->end && (*c->p == ' ' || *c->p == '\t' || *c->p == '\n' || *c->p == '\r')) c->p++;
}

static json_value *parse_value(jcur *c);

static void utf8_append(char **buf, size_t *len, size_t *cap, unsigned int cp) {
    char tmp[4];
    int n = 0;
    if (cp < 0x80) {
        tmp[0] = (char)cp;
        n = 1;
    } else if (cp < 0x800) {
        tmp[0] = (char)(0xC0 | (cp >> 6));
        tmp[1] = (char)(0x80 | (cp & 0x3F));
        n = 2;
    } else if (cp < 0x10000) {
        tmp[0] = (char)(0xE0 | (cp >> 12));
        tmp[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        tmp[2] = (char)(0x80 | (cp & 0x3F));
        n = 3;
    } else {
        tmp[0] = (char)(0xF0 | (cp >> 18));
        tmp[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        tmp[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        tmp[3] = (char)(0x80 | (cp & 0x3F));
        n = 4;
    }
    if (*len + (size_t)n + 1 > *cap) {
        *cap = (*cap == 0 ? 32 : *cap * 2) + (size_t)n;
        *buf = (char *)realloc(*buf, *cap);
    }
    memcpy(*buf + *len, tmp, (size_t)n);
    *len += (size_t)n;
}

static unsigned int hex4(const char *p) {
    unsigned int v = 0;
    for (int i = 0; i < 4; i++) {
        char ch = p[i];
        v <<= 4;
        if (ch >= '0' && ch <= '9') v |= (unsigned int)(ch - '0');
        else if (ch >= 'a' && ch <= 'f') v |= (unsigned int)(ch - 'a' + 10);
        else if (ch >= 'A' && ch <= 'F') v |= (unsigned int)(ch - 'A' + 10);
    }
    return v;
}

static char *parse_string_raw(jcur *c) {
    if (*c->p != '"') return NULL;
    c->p++;
    char *buf = NULL;
    size_t len = 0, cap = 0;
    while (c->p < c->end && *c->p != '"') {
        if (*c->p == '\\') {
            c->p++;
            if (c->p >= c->end) break;
            char e = *c->p;
            c->p++;
            switch (e) {
                case '"': utf8_append(&buf, &len, &cap, '"'); break;
                case '\\': utf8_append(&buf, &len, &cap, '\\'); break;
                case '/': utf8_append(&buf, &len, &cap, '/'); break;
                case 'b': utf8_append(&buf, &len, &cap, '\b'); break;
                case 'f': utf8_append(&buf, &len, &cap, '\f'); break;
                case 'n': utf8_append(&buf, &len, &cap, '\n'); break;
                case 'r': utf8_append(&buf, &len, &cap, '\r'); break;
                case 't': utf8_append(&buf, &len, &cap, '\t'); break;
                case 'u': {
                    if (c->end - c->p < 4) break;
                    unsigned int cp = hex4(c->p);
                    c->p += 4;
                    if (cp >= 0xD800 && cp <= 0xDBFF && c->end - c->p >= 6 && c->p[0] == '\\' &&
                        c->p[1] == 'u') {
                        unsigned int lo = hex4(c->p + 2);
                        if (lo >= 0xDC00 && lo <= 0xDFFF) {
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            c->p += 6;
                        }
                    }
                    utf8_append(&buf, &len, &cap, cp);
                    break;
                }
                default: break;
            }
        } else {
            utf8_append(&buf, &len, &cap, (unsigned char)*c->p);
            c->p++;
        }
    }
    if (c->p < c->end && *c->p == '"') c->p++;
    if (buf == NULL) {
        buf = (char *)malloc(1);
        buf[0] = '\0';
        return buf;
    }
    buf = (char *)realloc(buf, len + 1);
    buf[len] = '\0';
    return buf;
}

static json_value *new_value(json_type t) {
    json_value *v = (json_value *)calloc(1, sizeof(json_value));
    v->type = t;
    return v;
}

static json_value *parse_object(jcur *c) {
    c->p++; /* { */
    json_value *v = new_value(JSON_OBJECT);
    size_t cap = 0;
    skip_ws(c);
    if (c->p < c->end && *c->p == '}') {
        c->p++;
        return v;
    }
    while (c->p < c->end) {
        skip_ws(c);
        char *key = parse_string_raw(c);
        skip_ws(c);
        if (c->p < c->end && *c->p == ':') c->p++;
        skip_ws(c);
        json_value *val = parse_value(c);
        if (v->obj_len >= cap) {
            cap = cap == 0 ? 8 : cap * 2;
            v->keys = (char **)realloc(v->keys, cap * sizeof(char *));
            v->objs = (json_value *)realloc(v->objs, cap * sizeof(json_value));
        }
        v->keys[v->obj_len] = key;
        v->objs[v->obj_len] = *val;
        free(val);
        v->obj_len++;
        skip_ws(c);
        if (c->p < c->end && *c->p == ',') {
            c->p++;
            continue;
        }
        break;
    }
    skip_ws(c);
    if (c->p < c->end && *c->p == '}') c->p++;
    return v;
}

static json_value *parse_array(jcur *c) {
    c->p++; /* [ */
    json_value *v = new_value(JSON_ARRAY);
    size_t cap = 0;
    skip_ws(c);
    if (c->p < c->end && *c->p == ']') {
        c->p++;
        return v;
    }
    while (c->p < c->end) {
        skip_ws(c);
        json_value *item = parse_value(c);
        if (v->items_len >= cap) {
            cap = cap == 0 ? 8 : cap * 2;
            v->items = (json_value *)realloc(v->items, cap * sizeof(json_value));
        }
        v->items[v->items_len] = *item;
        free(item);
        v->items_len++;
        skip_ws(c);
        if (c->p < c->end && *c->p == ',') {
            c->p++;
            continue;
        }
        break;
    }
    skip_ws(c);
    if (c->p < c->end && *c->p == ']') c->p++;
    return v;
}

static json_value *parse_value(jcur *c) {
    skip_ws(c);
    if (c->p >= c->end) return new_value(JSON_NULL);
    char ch = *c->p;
    if (ch == '{') return parse_object(c);
    if (ch == '[') return parse_array(c);
    if (ch == '"') {
        json_value *v = new_value(JSON_STRING);
        v->str_val = parse_string_raw(c);
        return v;
    }
    if (strncmp(c->p, "true", 4) == 0) {
        c->p += 4;
        json_value *v = new_value(JSON_BOOL);
        v->bool_val = 1;
        return v;
    }
    if (strncmp(c->p, "false", 5) == 0) {
        c->p += 5;
        json_value *v = new_value(JSON_BOOL);
        v->bool_val = 0;
        return v;
    }
    if (strncmp(c->p, "null", 4) == 0) {
        c->p += 4;
        return new_value(JSON_NULL);
    }
    /* number */
    const char *start = c->p;
    if (*c->p == '-') c->p++;
    while (c->p < c->end && (isdigit((unsigned char)*c->p) || *c->p == '.' || *c->p == 'e' ||
                              *c->p == 'E' || *c->p == '+' || *c->p == '-')) {
        c->p++;
    }
    json_value *v = new_value(JSON_NUMBER);
    char buf[64];
    size_t n = (size_t)(c->p - start);
    if (n >= sizeof(buf)) n = sizeof(buf) - 1;
    memcpy(buf, start, n);
    buf[n] = '\0';
    v->num_val = atof(buf);
    return v;
}

json_value *json_parse_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "json_parse_file: cannot open %s\n", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)size + 1);
    size_t rd = fread(buf, 1, (size_t)size, f);
    fclose(f);
    buf[rd] = '\0';

    jcur c;
    c.p = buf;
    c.end = buf + rd;
    json_value *v = parse_value(&c);
    free(buf);
    return v;
}

static void json_free_fields(json_value *v) {
    if (v == NULL) return;
    switch (v->type) {
        case JSON_STRING:
            free(v->str_val);
            break;
        case JSON_ARRAY:
            for (size_t i = 0; i < v->items_len; i++) {
                /* items are stored inline (not heap pointers per-item),
                 * so free their owned sub-fields but not the struct. */
                json_free_fields(&v->items[i]);
            }
            free(v->items);
            break;
        case JSON_OBJECT:
            for (size_t i = 0; i < v->obj_len; i++) {
                free(v->keys[i]);
                json_free_fields(&v->objs[i]);
            }
            free(v->keys);
            free(v->objs);
            break;
        default:
            break;
    }
}

void json_free(json_value *v) {
    if (v == NULL) return;
    json_free_fields(v);
    free(v);
}

const json_value *json_get(const json_value *obj, const char *key) {
    if (obj == NULL || obj->type != JSON_OBJECT) return NULL;
    for (size_t i = 0; i < obj->obj_len; i++) {
        if (strcmp(obj->keys[i], key) == 0) return &obj->objs[i];
    }
    return NULL;
}

const char *json_str(const json_value *v) {
    if (v == NULL || v->type != JSON_STRING) return NULL;
    return v->str_val;
}

const json_value *json_at(const json_value *arr, size_t index) {
    if (arr == NULL || arr->type != JSON_ARRAY || index >= arr->items_len) return NULL;
    return &arr->items[index];
}

size_t json_len(const json_value *arr_or_obj) {
    if (arr_or_obj == NULL) return 0;
    if (arr_or_obj->type == JSON_ARRAY) return arr_or_obj->items_len;
    if (arr_or_obj->type == JSON_OBJECT) return arr_or_obj->obj_len;
    return 0;
}

int json_is_null_or_absent(const json_value *v) { return v == NULL || v->type == JSON_NULL; }

int json_bool(const json_value *v) { return v != NULL && v->type == JSON_BOOL && v->bool_val; }
