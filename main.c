#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <curl/curl.h>
#include "util.h"

#include <errno.h>
#include <unistd.h>
#include "jsmn.h"
#include <modbus.h>
#include <time.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/wait.h>
#include <signal.h>

enum {
    TCP,
    TCP_PI,
    RTU
};

typedef struct data_selection data_selection_t;
struct data_selection{
    char *name;
    uint8_t intg_part_size;
    uint8_t frac_part_size;
    data_selection_t *next;
};

typedef struct {
	uint16_t *data;
	uint16_t  count;
	data_selection_t **keys;
} shared_regs;

typedef struct {
	char *url;
	uint32_t period;
    data_selection_t list;
} cfg_struct;


void free_structure(data_selection_t *s)
{
  data_selection_t **del;
  while (s->next != NULL)
  {
    del = &(s->next);
    while ((*del)->next != NULL)
    {
      del = &((*del)->next);
    }
    free((*del)->name);
    free(*del);
    *del = NULL;
  }
}


/* Function realloc_it() is a wrapper function for standard realloc()
 * with one difference - it frees old memory pointer in case of realloc
 * failure. Thus, DO NOT use old data pointer in anyway after call to
 * realloc_it(). If your code has some kind of fallback algorithm if
 * memory can't be re-allocated - use standard realloc() instead.
 */
static inline void *realloc_it(void *ptrmem, size_t size) {
  void *p = realloc(ptrmem, size);
  if (!p) {
    free(ptrmem);
    fprintf(stderr, "realloc(): errno=%d\n", errno);
  }
  return p;
}

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}

int extract(const char *js, jsmntok_t *t, size_t count, void *data) {
  int i;
  int r = count;

  shared_regs *mb = (shared_regs*)data;

  if (mb->data == NULL) return EXIT_FAILURE;
  uint16_t index = 0;

      /* Assume the top-level element is an object */
  if (r < 1 || t[0].type != JSMN_OBJECT) {
    printf("Object expected\n");
    return 1;
  }

  /* Loop over all keys of the root object */
  for (i = 1; i < r; i++) {
  nextkey:;
    data_selection_t **current = mb->keys;
    while(*current != NULL)
    {
    
      if (jsoneq(js, &t[i], (*current)->name) == 0) {
        int64_t i_val = 0;
        if((*current)->frac_part_size)
        {
          double d_val = strtod(js + t[++i].start, NULL);
          d_val *= (double)(1 << (*current)->frac_part_size);
          i_val = (int64_t)(d_val + ((d_val < 0.0) ? -0.5 : 0.5));
        }
        else
        {
          i_val = strtol(js + t[++i].start, NULL, 10);
        }

        if(((*current)->intg_part_size + (*current)->frac_part_size) > 16)
            mb->data[index++] = (uint16_t)(i_val >> 16);

        mb->data[index++] = (uint16_t)i_val;

        if(index > mb->count) return EXIT_FAILURE;
        goto nextkey;
      }

      current = &((*current)->next);
    }

  }
  mb->count = index;
  return EXIT_SUCCESS;
}

int assign_values(const char *js, jsmntok_t *t, size_t count, void *data)
{
  int i;
  int r = count;

  cfg_struct *cfg = (cfg_struct *)data;
  data_selection_t *list = &(cfg->list);

      /* Assume the top-level element is an object */
  if (r < 1 || t[0].type != JSMN_OBJECT) {
    printf("Object expected\n");
    return 1;
  }

  /* Loop over all keys of the root object */
  for (i = 1; i < r; i++) {
    if (jsoneq(js, &t[i], "url") == 0) {
      cfg->url = strndup(js + t[i+1].start, t[i+1].end - t[i+1].start);
      i++;
    } else if (jsoneq(js, &t[i], "period") == 0) {
      cfg->period = strtol(js + t[i+1].start, NULL, 10);
      i++;
    } else if (t[i].type == JSMN_ARRAY)
    {
      data_selection_t **add = &(list->next);
      while(*add != NULL)
      {
        add = &((*add)->next);
      }
      *add = (data_selection_t *) malloc(sizeof(data_selection_t));
      (*add)->name = strndup(js + t[i-1].start, t[i-1].end - t[i-1].start);
      (*add)->intg_part_size = strtol(js + t[++i].start, NULL, 10);
      (*add)->frac_part_size = strtol(js + t[++i].start, NULL, 10);
      (*add)->next = NULL;
    }
  }
  return EXIT_SUCCESS;
}


int read_json( char *js, size_t jslen, void *cb_data, int callback(const char *js, jsmntok_t *t, size_t count, void *data))
{
    jsmn_parser p;
    jsmntok_t *tok;
    size_t tokcount = 2;

    /* Prepare parser */
    jsmn_init(&p);
    /* Allocate some tokens as a start */
    tok = malloc(sizeof(*tok) * tokcount);
    if (tok == NULL) {
    fprintf(stderr, "malloc(): errno=%d\n", errno);
    return EXIT_FAILURE;
    }

    again:
    int r = jsmn_parse(&p, js, jslen, tok, tokcount);
        if (r < 0) {
        if (r == JSMN_ERROR_NOMEM) {
            tokcount = tokcount * 2;
            tok = realloc_it(tok, sizeof(*tok) * tokcount);
            if (tok == NULL) {
            return EXIT_FAILURE;
            }
            goto again;
        }
        } else {
        callback(js, tok, p.toknext, cb_data);
        }
    free(tok);
    return EXIT_SUCCESS;
}


int create_structure(FILE *config, cfg_struct *data)
{
  int r;
  char *js = NULL;
  size_t jslen = 0;
  char buf[BUFSIZ];

  for (;;) {
        /* Read another chunk */
        r = fread(buf, 1, sizeof(buf), config);
        if (r < 0) {
          fprintf(stderr, "fread(): %d, errno=%d\n", r, errno);
          return 1;
        }
        if (r == 0) {
            return 0;
        }

        js = realloc_it(js, jslen + r + 1);
        if (js == NULL) {
          return 3;
        }
        strncpy(js + jslen, buf, r);
        jslen = jslen + r;

        read_json(js,jslen,(void *)data,&assign_values);

    }
}

int main(int argc, char *argv[]) {

  pid_t process;

  int s = -1;

  uint8_t mb_address = 1;

  modbus_t *ctx;
  modbus_mapping_t *mb_mapping;
  int rc;
  int use_backend;
  uint8_t *query;
  
  if (argc > 1) {
      if (strcmp(argv[1], "tcp") == 0) {
          use_backend = TCP;
      } else if (strcmp(argv[1], "tcppi") == 0) {
          use_backend = TCP_PI;
      } else if (strcmp(argv[1], "rtu") == 0) {
          use_backend = RTU;
      } else {
          printf("Usage:\n  %s [tcp|tcppi|rtu] - Modbus server for JSON web-api data retrieval\n\n", argv[0]);
          return -1;
      }
  } else {
      /* By default */
      use_backend = TCP;
  }

  cfg_struct cfg_data = {.url = NULL, .period = 3600, .list = {0} };

  FILE *cfg_file;
  cfg_file = fopen("config.json","r");
  create_structure(cfg_file,&cfg_data);
  fclose(cfg_file);

  if(cfg_data.url == NULL) return EXIT_FAILURE;
  if(cfg_data.list.next == NULL) return EXIT_FAILURE;

  pthread_mutex_t mutex;
  pthread_mutex_init(&mutex,NULL);


  shared_regs mbr;

  mbr.keys = &(cfg_data.list.next);
  mbr.count = 2048;		//whole 4096 page will be allocated anyways

  mbr.data = mmap(NULL,mbr.count*sizeof(uint16_t),PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
  if(mbr.data == NULL) return EXIT_FAILURE;

  process = fork();
  if(process < 0) return EXIT_FAILURE;

  if(process == 0) { // child - the slow stuff

    CURL *curl_handle;
    CURLcode res;

    struct MemoryStruct chunk;
    chunk.memory = malloc(1);  
    chunk.size = 0;

    curl_handle = curl_easy_init();
    if(curl_handle) {
      curl_easy_setopt(curl_handle, CURLOPT_URL, cfg_data.url);
      curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
      curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
      curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

      for (;;) {
            res = curl_easy_perform(curl_handle);
            if(res != CURLE_OK) {
              fprintf(stderr, "error: %s\n", curl_easy_strerror(res));
            } else {
              while(pthread_mutex_trylock(&mutex)); // blocking while accessed by the fast process
              read_json(chunk.memory,chunk.size,(void*)&mbr,&extract);
              pthread_mutex_unlock(&mutex);
              printf("Data successfuly fetched from JSON.\n");
            }
            sleep(cfg_data.period);
          }

          curl_easy_cleanup(curl_handle);
      }
      free(chunk.memory);
      free(cfg_data.url);
      free_structure(&(cfg_data.list));

    } else { // parent - the fast process

      if (use_backend == TCP) {
          ctx = modbus_new_tcp("127.0.0.1", 1502);
          query = malloc(MODBUS_TCP_MAX_ADU_LENGTH);
      } else if (use_backend == TCP_PI) {
          ctx = modbus_new_tcp_pi("::0", "1502");
          query = malloc(MODBUS_TCP_MAX_ADU_LENGTH);
      } else {
          ctx = modbus_new_rtu("/dev/ttyUSB0", 115200, 'N', 8, 1);
          modbus_set_slave(ctx, mb_address);
          query = malloc(MODBUS_RTU_MAX_ADU_LENGTH);
      }

      modbus_set_debug(ctx, FALSE);

      mb_mapping = modbus_mapping_new(0, 0, 0, mbr.count);
      if (mb_mapping == NULL) {
          fprintf(stderr, "Failed to allocate the mapping: %s\n",
                  modbus_strerror(errno));
          modbus_free(ctx);
          return -1;
      }

      if (use_backend == TCP) {
          s = modbus_tcp_listen(ctx, 1);
          modbus_tcp_accept(ctx, &s);
      } else if (use_backend == TCP_PI) {
          s = modbus_tcp_pi_listen(ctx, 1);
          modbus_tcp_pi_accept(ctx, &s);
      } else {
          rc = modbus_connect(ctx);
          if (rc == -1) {
              fprintf(stderr, "Unable to connect %s\n", modbus_strerror(errno));
              modbus_free(ctx);
              return -1;
          }
      }
      printf("Modbus connected.\n");

      for (;;) {
          do {
              rc = modbus_receive(ctx, query);
              /* Filtered queries return 0 */
          } while (rc == 0);
          /* The connection is not closed on errors which require on reply such as
             bad CRC in RTU. */
          if (rc == -1 && errno != EMBBADCRC) {
              /* Quit */
              break;
          }

          if(0 == pthread_mutex_trylock(&mutex)) { // skipping while accessed by the slow process
            memcpy(mb_mapping->tab_input_registers, mbr.data, mbr.count * sizeof(uint16_t));
            pthread_mutex_unlock(&mutex);
          }

          rc = modbus_reply(ctx, query, rc, mb_mapping);
          if (rc == -1) {
              break;
          }
      }
      printf("Quit the loop: %s\n", modbus_strerror(errno));

      if (use_backend == TCP) {
          if (s != -1) {
              close(s);
          }
      }
      modbus_mapping_free(mb_mapping);
      free(query);
      /* For RTU */
      modbus_close(ctx);
      modbus_free(ctx);

      kill(process, SIGTERM);
      printf("Waiting for child process.\n");
      wait(NULL);
  }
    
  munmap(mbr.data,mbr.count*sizeof(uint16_t));
  printf("Bye!\n");
  return EXIT_SUCCESS;
}
