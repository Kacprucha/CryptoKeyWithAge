#include "tusb.h"

/* =====================================================================
 * DEVICE DESCRIPTOR
 * ===================================================================== */
static const tusb_desc_device_t desc_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,

    .bDeviceClass       = TUSB_CLASS_MISC,
    .bDeviceSubClass    = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol    = MISC_PROTOCOL_IAD,

    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor           = 0x2E8A,   /* Raspberry Pi */
    .idProduct          = 0x000A,   /* Pico CDC */
    .bcdDevice          = 0x0100,
    .iManufacturer      = 0x01,
    .iProduct           = 0x02,
    .iSerialNumber      = 0x03,
    .bNumConfigurations = 0x01
};

uint8_t const *tud_descriptor_device_cb(void) {
    return (uint8_t const *) &desc_device;
}

/* =====================================================================
 * CONFIGURATION DESCRIPTOR
 * ===================================================================== */

/* Numery endpointów */
#define EPNUM_CDC_NOTIF   0x81   /* IN  – powiadomienia CDC */
#define EPNUM_CDC_OUT     0x02   /* OUT – dane host → Pico  */
#define EPNUM_CDC_IN      0x82   /* IN  – dane Pico → host  */

#define CONFIG_TOTAL_LEN  (TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN)

static const uint8_t desc_configuration[] = {
    TUD_CONFIG_DESCRIPTOR(
        1,                  /* bConfigurationValue */
        2,                  /* bNumInterfaces: control + data */
        0,                  /* iConfiguration */
        CONFIG_TOTAL_LEN,
        0x00,               /* bmAttributes: bus powered */
        100                 /* bMaxPower: 100 mA */
    ),

    /* CDC: interfejs 0 = control, interfejs 1 = data */
    TUD_CDC_DESCRIPTOR(
        0,                  /* interfejs startowy (control = 0, data = 1) */
        4,                  /* iInterface string index */
        EPNUM_CDC_NOTIF,    /* endpoint powiadomień (IN) */
        8,                  /* rozmiar endpointu powiadomień */
        EPNUM_CDC_OUT,      /* endpoint danych OUT */
        EPNUM_CDC_IN,       /* endpoint danych IN */
        64                  /* rozmiar endpointów danych */
    )
};

uint8_t const *tud_descriptor_configuration_cb(uint8_t index) {
    (void) index;
    return desc_configuration;
}

/* =====================================================================
 * STRING DESCRIPTORS
 * ===================================================================== */

static const char *string_desc_arr[] = {
    (const char[]) { 0x09, 0x04 },  /* 0: język angielski (0x0409) */
    "Raspberry Pi",                  /* 1: Manufacturer */
    "CryptoKey Device",              /* 2: Product */
    "123456",                        /* 3: Serial (statyczny na razie) */
    "CryptoKey CDC",                 /* 4: CDC Interface */
};

static uint16_t desc_str[32];

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void) langid;

    uint8_t chr_count;

    if (index == 0) {
        memcpy(&desc_str[1], string_desc_arr[0], 2);
        chr_count = 1;
    } else {
        if (index >= sizeof(string_desc_arr) / sizeof(string_desc_arr[0]))
            return NULL;

        const char *str = string_desc_arr[index];
        chr_count = (uint8_t) strlen(str);
        if (chr_count > 31) chr_count = 31;

        /* Konwersja ASCII → UTF-16LE */
        for (uint8_t i = 0; i < chr_count; i++) {
            desc_str[1 + i] = str[i];
        }
    }

    desc_str[0] = (uint16_t) ((TUSB_DESC_STRING << 8) | (2 * chr_count + 2));

    return desc_str;
}