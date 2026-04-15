#ifndef ATCA_CONFIG_H
#define ATCA_CONFIG_H

/* Interfejs komunikacji */
#define ATCA_HAL_I2C

/* Obsługiwane urządzenia */
#define ATCA_ATECC608_SUPPORT

/* Timing – wymagane przez atca_iface.c */
#define ATCA_POST_DELAY_MSEC 25u

/* Wyłącz heap – używany statycznych buforów na MCU */
#define ATCA_NO_HEAP

/* Wyłączenie printf/debug output */
#ifndef ATCA_PRINTF
/* świadomie zostawiam niezdefiniowane */
#endif

/* Rozmiar bufora I/O */
#define ATCA_PACKET_SIZE 180

#endif /* ATCA_CONFIG_H */