#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <errno.h>

#include <csp/csp.h>
#include <csp/csp_interface.h>

#define TYPE_SERVER 1
#define TYPE_CLIENT 2
#define CLIENT_NODE_ID 1
#define SERVER_NODE_ID 2
#define DYNAMIC_NODE_ID 3
#define PORT        10
#define BUF_SIZE    250

pthread_t rx_thread;
int rx_channel, tx_channel;

int csp_fifo_tx(csp_iface_t *ifc, csp_packet_t *packet, uint32_t timeout);

csp_iface_t csp_if_fifo = {
    .name = "fifo",
    .nexthop = csp_fifo_tx,
    .mtu = BUF_SIZE,
};

int csp_fifo_tx(csp_iface_t *ifc, csp_packet_t *packet, uint32_t timeout) {
    /* Write packet to fifo */
    if (write(tx_channel, &packet->length, packet->length + sizeof(uint32_t) + sizeof(uint16_t)) < 0)
        printf("Failed to write frame\r\n");
    csp_buffer_free(packet);
    return CSP_ERR_NONE;
}

void * fifo_rx(void * parameters) {
    csp_packet_t *buf = csp_buffer_get(BUF_SIZE);
    /* Wait for packet on fifo */
    while (read(rx_channel, &buf->length, BUF_SIZE) > 0) {
        csp_new_packet(buf, &csp_if_fifo, NULL);
        buf = csp_buffer_get(BUF_SIZE);
    }

    return NULL;
}

/* Build a packet with a null terminated payload */
csp_packet_t *new_packet(char *data) {
    size_t len = strlen(data);

    csp_packet_t *packet = csp_buffer_get(len);
    if (!packet) {
        return NULL;
    }

    memcpy((char *) packet->data, data, len);
    packet->length = len;

    return packet;
}

int iscommand(csp_packet_t *packet, char *cmd) {
    size_t len = strlen(cmd);

    if (packet->length != len) {
        return 0;
    }

    if (memcmp(packet->data, cmd, len) != 0) {
        return 0;
    }

    return 1;
}

int command(csp_socket_t *sock, int target, char *command, char *expected) {
    csp_packet_t *packet, *reply_packet;
    packet = new_packet(command);
    if (!packet) {
        return -1;
    }

    if (csp_sendto(CSP_PRIO_NORM, target, PORT, PORT, CSP_SO_CONN_LESS, packet, 1000) != CSP_ERR_NONE) {
        printf("Failed send\n");
        return -1;
    }

    reply_packet = csp_recvfrom(sock, 1000);
    if (!reply_packet) {
        printf("Reply without packet\n");
        return -1;
    }
    if (!iscommand(reply_packet, expected)) {
        printf("Expected %s, got %s\n", expected, reply_packet->data);
        return -1;
    }
    csp_buffer_free(reply_packet);
    return 0;
}

int main(int argc, char **argv) {

    int me, other, type;
    char *rx_channel_name, *tx_channel_name;
    int ret = 0;
    csp_socket_t *sock;
    csp_packet_t *packet, *reply_packet;

    /* Run as either server or client */
    if (argc != 2) {
        printf("usage: %s <server/client>\r\n", argv[0]);
        return -1;
    }

    /* Set type */
    if (strcmp(argv[1], "server") == 0) {
        me = SERVER_NODE_ID;
        other = CLIENT_NODE_ID;
        tx_channel_name = "server_to_client";
        rx_channel_name = "client_to_server";
        type = TYPE_SERVER;
    } else if (strcmp(argv[1], "client") == 0) {
        me = CLIENT_NODE_ID;
        other = SERVER_NODE_ID;
        tx_channel_name = "client_to_server";
        rx_channel_name = "server_to_client";
        type = TYPE_CLIENT;
    } else {
        printf("Invalid type. Must be either 'server' or 'client'\r\n");
        return -1;
    }

    /* Init CSP and CSP buffer system */
    if (csp_init(me) != CSP_ERR_NONE || csp_buffer_init(10, 300) != CSP_ERR_NONE) {
        printf("Failed to init CSP\r\n");
        return -1;
    }

    ret = mkfifo(rx_channel_name, S_IRUSR | S_IWUSR);
    if (-1 == ret && EEXIST != errno) {
        perror("could not mkfifo for rx");
        return -1;
    }
    ret = mkfifo(tx_channel_name, S_IWUSR | S_IRUSR);
    if (-1 == ret && EEXIST != errno) {
        perror("could not mkfifo for tx");
        return -1;
    }

    tx_channel = open(tx_channel_name, O_RDWR);
    if (tx_channel < 0) {
        printf("Failed to open TX channel\r\n");
        return -1;
    }

    rx_channel = open(rx_channel_name, O_RDWR);
    if (rx_channel < 0) {
        printf("Failed to open RX channel\r\n");
        return -1;
    }

    /* Start fifo RX task */
	pthread_create(&rx_thread, NULL, fifo_rx, NULL);

    /* Set default route and start router */
    csp_route_set(CSP_DEFAULT_ROUTE, &csp_if_fifo, CSP_NODE_MAC);
    csp_route_start_task(0, 0);
    sock = csp_socket(CSP_SO_CONN_LESS);
    csp_bind(sock, PORT);

    if (type == TYPE_SERVER) {
        while (true) {
        /* Process incoming packet */

            packet = csp_recvfrom(sock, 1000);
            if (packet) {
                printf("Received: %s\r\n", packet->data);
                if (iscommand(packet, "ping")) {
                    reply_packet = new_packet("pong");
                    if (!reply_packet) {
                        return -1;
                    }
                    csp_sendto(CSP_PRIO_NORM, other, PORT, PORT, CSP_SO_CONN_LESS, reply_packet, 1000);

                }
                if (iscommand(packet, "enable")) {
                    if (csp_enable_dynamic_address(DYNAMIC_NODE_ID) == CSP_ERR_NONE) {
                        reply_packet = new_packet("ok");
                    } else {
                        reply_packet = new_packet("error");
                    }
                    if (!reply_packet) {
                        return -1;
                    }
                    csp_sendto(CSP_PRIO_NORM, other, PORT, PORT, CSP_SO_CONN_LESS, reply_packet, 1000);

                }
                if (iscommand(packet, "disable")) {
                    if (csp_disable_dynamic_address() == CSP_ERR_NONE) {
                        reply_packet = new_packet("ok");
                    } else {
                        reply_packet = new_packet("error");
                    }                    
                    if (!reply_packet) {
                        return -1;
                    }
                    csp_sendto(CSP_PRIO_NORM, other, PORT, PORT, CSP_SO_CONN_LESS, reply_packet, 1000);

                }
                csp_buffer_free(packet);
            }

        }
    } else {
        /* Test echo: send ping, get pong */
        printf("Test CSP Echo: ");
        if (command(sock, SERVER_NODE_ID, "ping", "pong") != 0) {
            return -1;
        }
        printf("OK\n");

        /* Test dynamic timeout: send ping to dynamic address, get nothing */
        printf("Test Dynamic ping timeout: ");
        packet = new_packet("ping");
        if (!packet) {
            return -1;
        }

        if (csp_sendto(CSP_PRIO_NORM, DYNAMIC_NODE_ID, PORT, PORT, CSP_SO_CONN_LESS, packet, 1000) != CSP_ERR_NONE) {
            printf("Failed send\n");
            return -1;
        }

        reply_packet = csp_recvfrom(sock, 1000);
        if (reply_packet) {
            printf("Unexpected reply\n");
            return -1;
        }
        printf("OK\n");

        /* Test dynamic ping: enable dynamic address, get ping reply */
        printf("Test Enable Dynamic Address: ");
        if (command(sock, SERVER_NODE_ID, "enable", "ok") != 0) {
            return -1;
        }
        printf("OK\n");

        printf("Test Dynamic Address Ping: ");
        if (command(sock, DYNAMIC_NODE_ID, "ping", "pong") != 0) {
            return -1;
        }
        printf("OK\n");

        /* Test disblae dynamic ping: disable dynamic address, dont get ping reply */
        printf("Test disable Dynamic Address: ");
        if (command(sock, SERVER_NODE_ID, "disable", "ok") != 0) {
            return -1;
        }
        printf("OK\n");

        printf("Test Dynamic Address Ping: ");
        packet = new_packet("ping");
        if (!packet) {
            return -1;
        }

        if (csp_sendto(CSP_PRIO_NORM, DYNAMIC_NODE_ID, PORT, PORT, CSP_SO_CONN_LESS, packet, 1000) != CSP_ERR_NONE) {
            printf("Failed send\n");
            return -1;
        }

        reply_packet = csp_recvfrom(sock, 1000);
        if (reply_packet) {
            printf("Unexpected reply\n");
            return -1;
        }
        printf("OK\n");

    }

    close(rx_channel);
    close(tx_channel);

    return 0;
}
