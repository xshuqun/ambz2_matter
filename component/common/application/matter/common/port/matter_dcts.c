/**************************
* Matter DCT Related
**************************/
#include "platform_opts.h"
#include "platform/platform_stdlib.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "stddef.h"
#include "string.h"
#include "stdbool.h"
#include "dct.h"
#include "chip_porting.h"

#if CONFIG_ENABLE_DCT_ENCRYPTION
#include "mbedtls/aes.h"
#endif
/*
   module size is 4k, we set max module number as 12;
   if backup enabled, the total module number is 12 + 1*12 = 24, the size is 96k;
   if wear leveling enabled, the total module number is 12 + 2*12 + 3*12 = 36, the size is 288k"
*/
#define DCT_BEGIN_ADDR_MATTER   DCT_BEGIN_ADDR    /*!< DCT begin address of flash, ex: 0x100000 = 1M */
#define MODULE_NUM              13                /*!< max number of module */
#define VARIABLE_NAME_SIZE      32                /*!< max size of the variable name */
#define VARIABLE_VALUE_SIZE     64 + 4            /*!< max size of the variable value, +4 is required, else the max variable size we can store is 60 */
/*!< max number of variable in module = floor (4024 / (32 + 64)) = 41 */

#define DCT_BEGIN_ADDR_MATTER2  DCT_BEGIN_ADDR2
#define MODULE_NUM2             10
#define VARIABLE_NAME_SIZE2     32
#define VARIABLE_VALUE_SIZE2    400 + 4           /* +4 is required, else the max variable size we can store is 396 */
/*!< max number of variable in module = floor (4024 / (32 + 400)) = 9 */

#define ENABLE_BACKUP           0
#define ENABLE_WEAR_LEVELING    0

#define DCT_REGION_1 1
#define DCT_REGION_2 2

static char ns1[15], ns2[15];
static int is_dct_module1_open = 0;
static int is_dct_module2_open = 0;
static int global_val = 0;
static dct_handle_t matter_handle;
uint8_t matter_example_thread_init = 0;

//#define MATTER_DCT_DEBUG
//#define DCT_DEBUG
#ifdef MATTER_DCT_DEBUG
#define matter_debug printf
#else
#define matter_debug
#endif

#if CONFIG_ENABLE_DCT_ENCRYPTION
#if defined(MBEDTLS_CIPHER_MODE_CTR)
mbedtls_aes_context aes;

// key length 32 bytes for 256 bit encrypting, it can be 16 or 24 bytes for 128 and 192 bits encrypting mode
unsigned char key[] = {0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

int32_t dct_encrypt(unsigned char *input_to_encrypt, int input_len, unsigned char *encrypt_output)
{
    size_t nc_off = 0;

    unsigned char nonce_counter[16] = {0};
    unsigned char stream_block[16] = {0};

    return mbedtls_aes_crypt_ctr(&aes, input_len, &nc_off, nonce_counter, stream_block, input_to_encrypt, encrypt_output);
}

int32_t dct_decrypt(unsigned char *input_to_decrypt, int input_len, unsigned char *decrypt_output)
{
    size_t nc_off1 = 0;
    unsigned char nonce_counter1[16] = {0};
    unsigned char stream_block1[16] = {0};

    return mbedtls_aes_crypt_ctr(&aes, input_len, &nc_off1, nonce_counter1, stream_block1, input_to_decrypt, decrypt_output);
}

int32_t dct_set_encrypted_variable(dct_handle_t *dct_handle, char *variable_name, char *variable_value, uint16_t variable_value_length, uint8_t region)
{
    int32_t ret;
    char encrypted_data[VARIABLE_VALUE_SIZE2] = {0};

    // encrypt the variable value
    ret = dct_encrypt(variable_value, variable_value_length, encrypted_data);
    if (ret != 0) {
        return DCT_ERROR;
    }

    // store in dct
    if (region == DCT_REGION_1) {
        ret = dct_set_variable_new(dct_handle, variable_name, encrypted_data, variable_value_length);
    } else if (region == DCT_REGION_2) {
        ret = dct_set_variable_new2(dct_handle, variable_name, encrypted_data, variable_value_length);
    }

    return ret;
}

int32_t dct_get_encrypted_variable(dct_handle_t *dct_handle, char *variable_name, char *buffer, uint16_t *buffer_size, uint8_t region)
{
    int32_t ret;
    uint8_t encrypted_data[404] = {0};

    // get the encrypted value from dct
    if (region == DCT_REGION_1) {
        ret = dct_get_variable_new(dct_handle, variable_name, encrypted_data, buffer_size);
    } else if (region == DCT_REGION_2) {
        ret = dct_get_variable_new2(dct_handle, variable_name, encrypted_data, buffer_size);
    }

    if (ret != DCT_SUCCESS) {
        return ret;
    }

    // decrypt the encrypted value
    ret = dct_decrypt(encrypted_data, *buffer_size, buffer);
    if (ret != 0) {
        return DCT_ERROR;
    }

    return ret;
}

#else
#error "MBEDTLS_CIPHER_MODE_CTR must be enabled to perform DCT flash encryption"
#endif // MBEDTLS_CIPHER_MODE_CTR
#endif

static int32_t matter_close_dct_module(uint8_t region)
{
    int32_t ret;

    if (region == DCT_REGION_1) {
        if (!is_dct_module1_open) {
            return DCT_SUCCESS;
        }
        //matter_debug("close dct region1\n");
        ret = dct_close_module(&matter_handle);
        if (ret == DCT_SUCCESS) {
            is_dct_module1_open = 0;
        }
    } else if (region == DCT_REGION_2) {
        if (!is_dct_module2_open) {
            return DCT_SUCCESS;
        }
        //matter_debug("close dct region2\n");
        ret = dct_close_module2(&matter_handle);
        if (ret == DCT_SUCCESS) {
            is_dct_module2_open = 0;
        }
    }

    return ret;
}

static int32_t matter_open_dct_module(uint8_t region)
{
    int32_t ret;
    int module_num;
    char *endptr = NULL, *ns = NULL;

    if (region == DCT_REGION_1) {
        if (is_dct_module1_open) {
            return DCT_SUCCESS;
        }
        if (is_dct_module2_open) {
            matter_close_dct_module(DCT_REGION_2);
        }

        ns = ns1;
        module_num = MODULE_NUM;
    } else if (region == DCT_REGION_2) {
        if (is_dct_module2_open) {
            return DCT_SUCCESS;
        }
        if (is_dct_module1_open) {
            matter_close_dct_module(DCT_REGION_1);
        }
        ns = ns2;
        module_num = MODULE_NUM2;
    }

    if (ns[0] == '\0') {
        if (global_val = 0) {
            snprintf(ns, 15, "matter_kvs%d_%d", region, global_val + 1);
        } else {
            global_val++;
            snprintf(ns, 15, "matter_kvs%d_%d", region, global_val);
        }
    } else {
        global_val++;
        snprintf(ns, 15, "matter_kvs%d_%d", region, global_val);
    }

    if (region == DCT_REGION_1) {
        matter_debug("open dct region1 for %s\n", ns1);
        ret = dct_open_module(&matter_handle, ns);
        if (ret == DCT_SUCCESS) {
            is_dct_module1_open = 1;
        }
    } else if (region == DCT_REGION_2) {
        matter_debug("open dct region2 for %s\n", ns2);
        ret = dct_open_module2(&matter_handle, ns);
        if (ret == DCT_SUCCESS) {
            is_dct_module2_open = 1;
        }
    }

    return ret;
}

#include "utility.h"
#include <flash_api.h>
#include <device_lock.h>
s32 initPref(void)
{
    s32 ret;

#if 0//def MATTER_DCT_DEBUG
    uint8_t *read_buf = NULL;

    read_buf = rtw_malloc(4096);
    if (!read_buf)
    {
        printf("[MATTER_DCT] malloc failed\n");
        return;
    }

    for (size_t i = 0; i < MODULE_NUM; i++) {
        memset(read_check, 0, BUFFER_SIZE);
        device_mutex_lock(RT_DEV_LOCK_FLASH);
        flash_stream_read(flash, DCT_BEGIN_ADDR_MATTER + (i*4096), 4096, read_buf);
        device_mutex_unlock(RT_DEV_LOCK_FLASH);
        printf("\n0x%X: ", DCT_BEGIN_ADDR_MATTER + (i*4096));
        dump_bytes
    }

    rtw_free(read_buf);
#endif

    ret = dct_init(DCT_BEGIN_ADDR_MATTER, MODULE_NUM, VARIABLE_NAME_SIZE, VARIABLE_VALUE_SIZE, ENABLE_BACKUP, ENABLE_WEAR_LEVELING);
    if (ret != DCT_SUCCESS) {
        printf("dct_init failed with error: %d\n", ret);
    } else {
        printf("dct_init success\n");
    }

    ret = dct_init2(DCT_BEGIN_ADDR_MATTER2, MODULE_NUM2, VARIABLE_NAME_SIZE2, VARIABLE_VALUE_SIZE2, ENABLE_BACKUP, ENABLE_WEAR_LEVELING);
    if (ret != DCT_SUCCESS) {
        printf("dct_init2 failed with error: %d\n", ret);
    } else {
        printf("dct_init2 success\n");
    }

#if CONFIG_ENABLE_DCT_ENCRYPTION
    // Initialize mbedtls aes context and set encryption key
    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_enc(&aes, key, 256) != 0) {
        return DCT_ERROR;
    }
#endif

    return ret;
}

s32 deinitPref(void)
{
    s32 ret;
    ret = dct_format(DCT_BEGIN_ADDR_MATTER, MODULE_NUM, VARIABLE_NAME_SIZE, VARIABLE_VALUE_SIZE, ENABLE_BACKUP, ENABLE_WEAR_LEVELING);
    if (ret != DCT_SUCCESS) {
        printf("dct_format failed with error: %d\n", ret);
    } else {
        printf("dct_format success\n");
    }

    ret = dct_format2(DCT_BEGIN_ADDR_MATTER2, MODULE_NUM2, VARIABLE_NAME_SIZE2, VARIABLE_VALUE_SIZE2, ENABLE_BACKUP, ENABLE_WEAR_LEVELING);
    if (ret != DCT_SUCCESS) {
        printf("dct_format2 failed with error: %d\n", ret);
    } else {
        printf("dct_format2 success\n");
    }

#if CONFIG_ENABLE_DCT_ENCRYPTION
    // free aes context
    mbedtls_aes_free(&aes);
#endif

    return ret;
}

s32 registerPref()
{
    s32 ret;
    char ns[15];

    for (size_t i = 0; i < MODULE_NUM; i++) {
        snprintf(ns, 15, "matter_kvs1_%d", i + 1);
        ret = dct_register_module(ns);
        if (ret != DCT_SUCCESS) {
            goto exit;
        } else {
            printf("dct_register_module %s success\n", ns);
        }
    }

exit:
    if (ret != DCT_SUCCESS) {
        printf("DCT1 modules registration failed");
    }
    return ret;
}

s32 registerPref2()
{
    s32 ret;
    char ns[15];

    for (size_t i = 0; i < MODULE_NUM2; i++) {
        snprintf(ns, 15, "matter_kvs2_%d", i + 1);
        ret = dct_register_module2(ns);
        if (ret != DCT_SUCCESS) {
            goto exit;
        } else {
            printf("dct_register_module2 %s success\n", ns);
        }
    }

exit:
    if (ret != DCT_SUCCESS) {
        printf("DCT2 modules registration failed");
    }
    return ret;
}

s32 clearPref()
{
    s32 ret;
    char ns[15];

    for (size_t i = 0; i < MODULE_NUM; i++) {
        snprintf(ns, 15, "matter_kvs1_%d", i + 1);
        ret = dct_unregister_module(ns);
        if (ret != DCT_SUCCESS) {
            goto exit;
        } else {
            printf("dct_unregister_module %s success\n", ns);
        }
    }

exit:
    if (ret != DCT_SUCCESS) {
        printf("DCT1 modules unregistration failed");
    }
    return ret;
}

s32 clearPref2()
{
    s32 ret;
    char ns[15];

    for (size_t i = 0; i < MODULE_NUM2; i++) {
        snprintf(ns, 15, "matter_kvs2_%d", i + 1);
        ret = dct_unregister_module2(ns);
        if (ret != DCT_SUCCESS) {
            goto exit;
        } else {
            printf("dct_unregister_module2 %s success\n", ns);
        }
    }

exit:
    if (ret != DCT_SUCCESS) {
        printf("DCT2 modules unregistration failed");
    }
    return ret;
}

s32 deleteKey(const char *domain, const char *key)
{
    s32 ret;
    char ns[15];
    int module_num = 1;

    matter_debug("%s: %s\n", __FUNCTION__, key);

    global_val = 0;

    while (module_num <= MODULE_NUM) {
        ret = matter_open_dct_module(DCT_REGION_1);
        if (ret == DCT_SUCCESS) {
            ret = dct_delete_variable(&matter_handle, key);
            if (ret == DCT_SUCCESS) {
                goto exit;
            } else {
                matter_debug("%s : delete region (%s) failed: %d\n", __FUNCTION__, key, ret);
                matter_close_dct_module(DCT_REGION_1);
            }
        } else {
            printf("%s : matter_open_dct_module failed with error: %d\n", __FUNCTION__, ret);
            goto exit;
        }
        module_num++;
    }

    module_num = 1;
    global_val = 0;

    while (module_num <= MODULE_NUM2) {
        ret = matter_open_dct_module(DCT_REGION_2);
        if (ret == DCT_SUCCESS) {
            ret = dct_delete_variable2(&matter_handle, key);
            if (ret == DCT_SUCCESS) {
                goto exit;
            } else {
                matter_debug("%s : delete region2 (%s) failed: %d\n", __FUNCTION__, key, ret);
                matter_close_dct_module(DCT_REGION_2);
            }
        } else {
            printf("%s : matter_open_dct_module2 failed with error: %d\n", __FUNCTION__, ret);
            goto exit;
        }
        module_num++;
    }

exit:
    return ret;
}

bool checkExist(const char *domain, const char *key)
{
    s32 ret;
    uint16_t len = 0;
    u8 *str = malloc(sizeof(u8) * VARIABLE_VALUE_SIZE2); // use the bigger buffer size
    int module_num = 1;

    matter_debug("%s: %s\n", __FUNCTION__, key);

    global_val = 0;
    while (module_num <= MODULE_NUM) {
        ret = matter_open_dct_module(DCT_REGION_1);
        if (ret == DCT_SUCCESS) {
            len = sizeof(u32);
            ret = dct_get_variable_new(&matter_handle, key, (char *)str, &len);
            if (ret == DCT_SUCCESS) {
                printf("checkExist(u32) key=%s found.\n", key);
                goto exit;
            } else {
                len = sizeof(u64);
                ret = dct_get_variable_new(&matter_handle, key, (char *)str, &len);
                if (ret == DCT_SUCCESS) {
                    printf("checkExist(u64) key=%s found.\n", key);
                    goto exit;
                } else {
                    matter_close_dct_module(DCT_REGION_1);
                }
            }
        } else {
            printf("%s : matter_open_dct_module failed with error: %d\n", __FUNCTION__, ret);
        }
        module_num++;
    }

    module_num = 1;
    global_val = 0;

    while (module_num <= MODULE_NUM2) {
        ret = matter_open_dct_module(DCT_REGION_2);
        if (ret == DCT_SUCCESS) {
            len = VARIABLE_VALUE_SIZE2;
            ret = dct_get_variable_new2(&matter_handle, key, (char *)str, &len);
            if (ret == DCT_SUCCESS) {
                printf("checkExist2 key=%s found.\n", key);
                goto exit;
            } else {
                matter_close_dct_module(DCT_REGION_2);
            }
        } else {
            printf("%s : matter_open_dct_module2 failed with error: %d\n", __FUNCTION__, ret);
        }
        module_num++;
    }

exit:
    free(str);
    if (matter_example_thread_init == 0) {
        matter_close_dct_module(DCT_REGION_1);
        matter_close_dct_module(DCT_REGION_2);
    }
    return (ret == DCT_SUCCESS) ? true : false;
}

s32 setPref_new(const char *domain, const char *key, u8 *value, size_t byteCount)
{
    s32 ret;
    int module_num = 1;

    matter_debug("%s: %s\n", __FUNCTION__, key);

    global_val = 0;
    if (byteCount <= 64) {
        while (module_num <= MODULE_NUM) {
            ret = matter_open_dct_module(DCT_REGION_1);
            if (ret == DCT_SUCCESS) {
                if (dct_remain_variable(&matter_handle) > 0) {
                    ret = dct_set_variable_new(&matter_handle, key, (char *)value, (uint16_t)byteCount);
                    if (ret != DCT_SUCCESS) {
                        printf("%s : dct_set_variable_new(%s) failed with error: %d\n", __FUNCTION__, key, ret);
                        matter_close_dct_module(DCT_REGION_1);
                        goto exit;
                    } else {
                        matter_debug("%s: set (%s) in %s\n", __FUNCTION__, key, ns1);
                        goto exit;
                    }
                } else {
                    matter_close_dct_module(DCT_REGION_1);
                }
            } else {
                printf("%s : matter_open_dct_module failed with error: %d\n", __FUNCTION__, ret);
                goto exit;
            }
            module_num++;
        }
    } else {
        while (module_num <= MODULE_NUM2) {
            ret = matter_open_dct_module(DCT_REGION_2);
            if (ret == DCT_SUCCESS) {
                if (dct_remain_variable2(&matter_handle) > 0) {
                    ret = dct_set_variable_new2(&matter_handle, key, (char *)value, (uint16_t)byteCount);
                    if (ret != DCT_SUCCESS) {
                        printf("%s : dct_set_variable_new2(%s) failed with error: %d\n", __FUNCTION__, key, ret);
                        matter_close_dct_module(DCT_REGION_2);
                        goto exit;
                    } else {
                        matter_debug("%s: set (%s) in %s\n", __FUNCTION__, key, ns2);
                        goto exit;
                    }
                } else {
                    matter_close_dct_module(DCT_REGION_2);
                }
            } else {
                printf("%s : matter_open_dct_module2 failed with error: %d\n", __FUNCTION__, ret);
                goto exit;
            }
            module_num++;
        }
    }

exit:
    if (matter_example_thread_init == 0) {
        matter_close_dct_module(DCT_REGION_1);
        matter_close_dct_module(DCT_REGION_2);
    }
    return ret;
}

s32 getPref_bool_new(const char *domain, const char *key, u8 *val)
{
    s32 ret;
    uint16_t len = sizeof(u8);
    int module_num;

    matter_debug("%s: %s\n", __FUNCTION__, key);

    module_num = 1;
    global_val = 0;

    while (module_num <= MODULE_NUM) {
        ret = matter_open_dct_module(DCT_REGION_1);
        if (ret == DCT_SUCCESS) {
            ret = dct_get_variable_new(&matter_handle, key, (char *)val, &len);
            if (ret != DCT_SUCCESS) {
                matter_debug("%s : get region (%s) failed: %d\n", __FUNCTION__, key, ret);
                matter_close_dct_module(DCT_REGION_1);
            } else {
                matter_debug("%s : get region (%s) from %s\n", __FUNCTION__, key, ns1);
                goto exit;
            }
        } else {
            printf("%s : matter_open_dct_module failed with error: %d\n", __FUNCTION__, ret);
            goto exit;
        }
        module_num++;
    }

    module_num = 1;
    global_val = 0;

    while (module_num <= MODULE_NUM2) {
        ret = matter_open_dct_module(DCT_REGION_2);
        if (ret == DCT_SUCCESS) {
            ret = dct_get_variable_new2(&matter_handle, key, (char *)val, &len);
            if (ret != DCT_SUCCESS) {
                matter_debug("%s : get region2 (%s) failed: %d\n", __FUNCTION__, key, ret);
                matter_close_dct_module(DCT_REGION_2);
            } else {
                goto exit;
            }
        } else {
            printf("%s : matter_open_dct_module2 failed with error: %d\n", __FUNCTION__, ret);
            goto exit;
        }
        module_num++;
    }

exit:
    if (matter_example_thread_init == 0) {
        matter_close_dct_module(DCT_REGION_1);
        matter_close_dct_module(DCT_REGION_2);
    }
    return ret;
}

s32 getPref_u32_new(const char *domain, const char *key, u32 *val)
{
    s32 ret;
    uint16_t len = sizeof(u32);
    int module_num;

    matter_debug("%s: %s\n", __FUNCTION__, key);

    module_num = 1;
    global_val = 0;

    while (module_num <= MODULE_NUM) {
        ret = matter_open_dct_module(DCT_REGION_1);
        if (ret == DCT_SUCCESS) {
            ret = dct_get_variable_new(&matter_handle, key, (char *)val, &len);
            if (ret != DCT_SUCCESS) {
                matter_debug("%s : get region (%s) failed: %d\n", __FUNCTION__, key, ret);
                matter_close_dct_module(DCT_REGION_1);
            } else {
                matter_debug("%s : get region (%s) from %s\n", __FUNCTION__, key, ns1);
                goto exit;
            }
        } else {
            printf("%s : matter_open_dct_module failed with error: %d\n", __FUNCTION__, ret);
            goto exit;
        }
        module_num++;
    }

    module_num = 1;
    global_val = 0;

    while (module_num <= MODULE_NUM2) {
        ret = matter_open_dct_module(DCT_REGION_2);
        if (ret == DCT_SUCCESS) {
            ret = dct_get_variable_new2(&matter_handle, key, (char *)val, &len);
            if (ret != DCT_SUCCESS) {
                matter_debug("%s : get region2 (%s) failed: %d\n", __FUNCTION__, key, ret);
                matter_close_dct_module(DCT_REGION_2);
            } else {
                goto exit;
            }
        } else {
            printf("%s : matter_open_dct_module2 failed with error: %d\n", __FUNCTION__, ret);
            goto exit;
        }
        module_num++;
    }

exit:
    if (matter_example_thread_init == 0) {
        matter_close_dct_module(DCT_REGION_1);
        matter_close_dct_module(DCT_REGION_2);
    }
    return ret;
}

s32 getPref_u64_new(const char *domain, const char *key, u64 *val)
{
    s32 ret;
    uint16_t len = sizeof(u64);
    int module_num;

    matter_debug("%s: %s\n", __FUNCTION__, key);

    module_num = 1;
    global_val = 0;

    while (module_num <= MODULE_NUM) {
        ret = matter_open_dct_module(DCT_REGION_1);
        if (ret == DCT_SUCCESS) {
            ret = dct_get_variable_new(&matter_handle, key, (char *)val, &len);
            if (ret != DCT_SUCCESS) {
                matter_debug("%s : get region (%s) failed: %d\n", __FUNCTION__, key, ret);
                matter_close_dct_module(DCT_REGION_1);
            } else {
                matter_debug("%s : get region (%s) from %s\n", __FUNCTION__, key, ns1);
                goto exit;
            }
        } else {
            printf("%s : matter_open_dct_module failed with error: %d\n", __FUNCTION__, ret);
            goto exit;
        }
        module_num++;
    }

    module_num = 1;
    global_val = 0;

    while (module_num <= MODULE_NUM2) {
        ret = matter_open_dct_module(DCT_REGION_2);
        if (ret == DCT_SUCCESS) {
            ret = dct_get_variable_new2(&matter_handle, key, (char *)val, &len);
            if (ret != DCT_SUCCESS) {
                matter_debug("%s : get region2 (%s) failed: %d\n", __FUNCTION__, key, ret);
                matter_close_dct_module(DCT_REGION_2);
            } else {
                matter_debug("%s : get region (%s) from %s\n", __FUNCTION__, key, ns1);
                goto exit;
            }
        } else {
            printf("%s : matter_open_dct_module2 failed with error: %d\n", __FUNCTION__, ret);
            goto exit;
        }
        module_num++;
    }

exit:
    return ret;
}

s32 getPref_str_new(const char *domain, const char *key, char *buf, size_t bufSize, size_t *outLen)
{
    s32 ret;
    int module_num;

    matter_debug("%s: %s\n", __FUNCTION__, key);

    module_num = 1;
    global_val = 0;

    while (module_num <= MODULE_NUM) {
        ret = matter_open_dct_module(DCT_REGION_1);
        if (ret == DCT_SUCCESS) {
            ret = dct_get_variable_new(&matter_handle, key, buf, &bufSize);
            if (ret != DCT_SUCCESS) {
                matter_debug("%s : get region1 (%s) failed: %d\n", __FUNCTION__, key, ret);
                matter_close_dct_module(DCT_REGION_1);
            } else {
                matter_debug("%s : get region (%s) from %s\n", __FUNCTION__, key, ns1);
                *outLen = bufSize;
                goto exit;
            }
        } else {
            printf("%s : matter_open_dct_module failed with error: %d\n", __FUNCTION__, ret);
            goto exit;
        }
        module_num++;
    }

    module_num = 1;
    global_val = 0;

    while (module_num <= MODULE_NUM2) {
        ret = matter_open_dct_module(DCT_REGION_2);
        if (ret == DCT_SUCCESS) {
            ret = dct_get_variable_new2(&matter_handle, key, buf, &bufSize);
            if (ret != DCT_SUCCESS) {
                matter_debug("%s : get region2 (%s) failed: %d\n", __FUNCTION__, key, ret);
                matter_close_dct_module(DCT_REGION_2);
            } else {
                *outLen = bufSize;
                goto exit;
            }
        } else {
            printf("%s : matter_open_dct_module2 failed with error: %d\n", __FUNCTION__, ret);
            goto exit;
        }
        module_num++;
    }

exit:
    if (matter_example_thread_init == 0) {
        matter_close_dct_module(DCT_REGION_1);
        matter_close_dct_module(DCT_REGION_2);
    }
    return ret;
}

s32 getPref_bin_new(const char *domain, const char *key, u8 *buf, size_t bufSize, size_t *outLen)
{
    s32 ret;
    int module_num;

    matter_debug("%s: %s\n", __FUNCTION__, key);

    module_num = 1;
    global_val = 0;

    while (module_num <= MODULE_NUM) {
        ret = matter_open_dct_module(DCT_REGION_1);
        if (ret == DCT_SUCCESS) {
            ret = dct_get_variable_new(&matter_handle, key, (char *)buf, &bufSize);
            if (ret != DCT_SUCCESS) {
                matter_debug("%s : get region (%s) failed: %d\n", __FUNCTION__, key, ret);
                matter_close_dct_module(DCT_REGION_1);
            } else {
                matter_debug("%s : get region (%s) from %s\n", __FUNCTION__, key, ns1);
                *outLen = bufSize;
                goto exit;
            }
        } else {
            printf("%s : matter_open_dct_module failed with error: %d\n", __FUNCTION__, ret);
            goto exit;
        }
        module_num++;
    }

    module_num = 1;
    global_val = 0;

    while (module_num <= MODULE_NUM2) {
        ret = matter_open_dct_module(DCT_REGION_2);
        if (ret == DCT_SUCCESS) {
            ret = dct_get_variable_new2(&matter_handle, key, (char *)buf, &bufSize);
            if (ret != DCT_SUCCESS) {
                matter_debug("%s : get region2 (%s) failed: %d\n", __FUNCTION__, key, ret);
                matter_close_dct_module(DCT_REGION_2);
            } else {
                *outLen = bufSize;
                goto exit;
            }
        } else {
            printf("%s : matter_open_dct_module2 failed with error: %d\n", __FUNCTION__, ret);
            goto exit;
        }
        module_num++;
    }

exit:
    if (matter_example_thread_init == 0) {
        matter_close_dct_module(DCT_REGION_1);
        matter_close_dct_module(DCT_REGION_2);
    }
    return ret;
}

#if defined(DCT_DEBUG)
void check_dct1_remainder(void)
{
    int32_t remain;
    s32 ret = -1;
    int module_num = 1;

    // Loop over DCT1 modules
    while (module_num <= MODULE_NUM) {
        ret = matter_dct_open_module(DCT_REGION_1);
        if (ret != DCT_SUCCESS) {
            printf("%s : dct_open_module(%s) failed with error: %d\n", __FUNCTION__, ns, ret);
            matter_dct_close_module(DCT_REGION_1);
            return;
        }
        remain += dct_remain_variable(&matter_handle);
        matter_dct_close_module(DCT_REGION_1);
    }
    printf("dct region 1 remaining variables: %d\n", remain);
}

void check_dct2_remainder(void)
{
    
    int32_t remain;
    s32 ret = -1;
    int module_num = 1;

    // Loop over DCT2 modules
    while (module_num <= MODULE_NUM2) {
        ret = matter_dct_open_module(DCT_REGION_2);
        if (ret != DCT_SUCCESS) {
            printf("%s : dct_open_module2(%s) failed with error: %d\n", __FUNCTION__, ns, ret);
            matter_dct_close_module(DCT_REGION_2);
            return;
        }
        remain += dct_remain_variable2(&matter_handle);
        matter_dct_close_module(DCT_REGION_2);
    }
    printf("dct region 2 remaining variables: %d\n", remain);
}
#endif

#ifdef __cplusplus
}
#endif
