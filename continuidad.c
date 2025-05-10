#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <mosquitto.h>
#include <jansson.h>

#define MAX_COMMAND_LENGTH 100
#define TARGET_IP "8.8.8.8"
#define WAN_INTERFACE "wan"
#define PHY_INTERFACE "phy0-sta0"
#define BROKER_ADDRESS "mqtts.mosquitto.kube.cablevision-labs.com.ar"
#define BROKER_PORT 8883
#define TOPIC "test/#"
#define GWR_TOPIC "rgw/mac/"
#define ADD_REGISTER_SSID_TOPIC "/registra/ssid"
#define CMD_BUFFER_SIZE 512

// Función para ejecutar comandos en la terminal
char* execute_command(const char* command) {
    FILE* fp = popen(command, "r");
    if (fp == NULL) {
        printf("Error opening pipe!\n");
        return NULL;
    }

    static char buffer[1024];
    fgets(buffer, sizeof(buffer), fp);
    pclose(fp);

    return buffer;
}

// Función para obtener la pérdida de paquetes en una interfaz
int get_packet_loss(const char* interface) {
    char command[MAX_COMMAND_LENGTH];
    snprintf(command, sizeof(command), "ping -I %s -c 10 %s | grep 'packet loss' | cut -d' ' -f6 | cut -d'%%' -f1", interface, TARGET_IP);
    char* result_str = execute_command(command);
    if (result_str == NULL) {
        return -1;
    }

    return atoi(result_str);
}

// Función para obtener la métrica de una interfaz
int get_interface_metric(const char* interface) {
    char command[MAX_COMMAND_LENGTH];
    snprintf(command, sizeof(command), "ip route show dev %s | grep -o 'metric [0-9]*' | cut -d' ' -f2", interface);
    char* result_str = execute_command(command);
    if (result_str == NULL) {
        return -1;
    }

    return atoi(result_str);
}

// Función para cambiar la métrica de una interfaz
void change_interface_metric(const char* interface, int metric) {
    char command[MAX_COMMAND_LENGTH];
    snprintf(command, sizeof(command), "ip route del default dev %s", interface);
    system(command);
    snprintf(command, sizeof(command), "ip route add default dev %s metric %d", interface, metric);
    system(command);
}

// Función para obtener la dirección MAC del router
char* get_mac_address() {
    static char mac[18];
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd == -1) {
        perror("Socket error");
        return NULL;
    }

    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        snprintf(mac, sizeof(mac), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
                 (unsigned char)ifr.ifr_hwaddr.sa_data[0],
                 (unsigned char)ifr.ifr_hwaddr.sa_data[1],
                 (unsigned char)ifr.ifr_hwaddr.sa_data[2],
                 (unsigned char)ifr.ifr_hwaddr.sa_data[3],
                 (unsigned char)ifr.ifr_hwaddr.sa_data[4],
                 (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
    } else {
        perror("ioctl error");
        close(fd);
        return NULL;
    }

    close(fd);
    return mac;
}

// Callback cuando se conecta al broker MQTT
void on_connect(struct mosquitto *mosq, void *userdata, int rc) {
    if (rc != 0) {
        fprintf(stderr, "Error: %s\n", mosquitto_strerror(rc));
        exit(1);
    }

    printf("Conectado al broker MQTT\n");

    char *mac_address = get_mac_address();
    if (mac_address == NULL) {
        fprintf(stderr, "No se pudo obtener la dirección MAC del router\n");
        return;
    }

    char *macTopic1 = malloc(strlen(GWR_TOPIC) + strlen(mac_address) + strlen(ADD_REGISTER_SSID_TOPIC) + 1);
    sprintf(macTopic1, "%s%s%s", GWR_TOPIC, mac_address, ADD_REGISTER_SSID_TOPIC);

    printf("Suscribiéndose al tópico: %s\n", macTopic1);
    mosquitto_subscribe(mosq, NULL, macTopic1, 0);

    char *macTopic2 = malloc(strlen(GWR_TOPIC) + strlen(mac_address) + 1);
    sprintf(macTopic2, "%s%s", GWR_TOPIC, mac_address);

    printf("Publicando la dirección MAC al tópico: %s\n", macTopic2);
    mosquitto_publish(mosq, NULL, macTopic2, strlen(mac_address), mac_address, 0, false);

    free(macTopic1);
    free(macTopic2);
}

// Callback cuando se recibe un mensaje MQTT
void on_message(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *msg) {
    printf("Mensaje recibido: %s en el tópico %s\n", (char *)msg->payload, msg->topic);

    json_error_t error;
    json_t *parsed_json = json_loads((char *)msg->payload, 0, &error);
    if (!parsed_json) {
        fprintf(stderr, "Error al parsear el JSON: %s\n", error.text);
        return;
    }

    json_t *ssid = json_object_get(parsed_json, "ssid");
    json_t *password = json_object_get(parsed_json, "password");

    if (!ssid || !password) {
        fprintf(stderr, "JSON incompleto: falta ssid o password\n");
        json_decref(parsed_json);
        return;
    }

    // Usar UCI para configurar la interfaz WiFi
    char uci_cmd[CMD_BUFFER_SIZE];
    int n = snprintf(uci_cmd, sizeof(uci_cmd),
        "uci set wireless.sta.ssid='%s'; "
        "uci set wireless.sta.encryption='psk2'; "
        "uci set wireless.sta.key='%s'; "
        "uci commit wireless; "
        "/etc/init.d/network restart",
        json_string_value(ssid), json_string_value(password));

    if (n >= sizeof(uci_cmd)) {
        fprintf(stderr, "Error: el comando UCI es demasiado largo.\n");
        json_decref(parsed_json);
        return;
    }

    int ret = system(uci_cmd);
    if (ret != 0) {
        fprintf(stderr, "Error al ejecutar comandos UCI\n");
    }

    json_decref(parsed_json);
}

// Evento de desconexión, realiza la reconexión
void on_disconnect(struct mosquitto *mosq, void *userdata, int rc) {
    printf("Desconectado del broker MQTT: %d\n", rc);
    if (rc != 0) {
        printf("Intentando reconectar...\n");
        mosquitto_reconnect(mosq);
    }
}

// Programa principal
int main() {
    struct mosquitto *mosq;
    int rc;

    mosquitto_lib_init();

    mosq = mosquitto_new(NULL, true, NULL);
    if (!mosq) {
        fprintf(stderr, "Error: Out of memory.\n");
        return 1;
    }

    mosquitto_connect_callback_set(mosq, on_connect);
    mosquitto_message_callback_set(mosq, on_message);
    mosquitto_disconnect_callback_set(mosq, on_disconnect);

    mosquitto_tls_opts_set(mosq, 1, "tlsv1.2", NULL);
    rc = mosquitto_tls_set(mosq, "/etc/ssl/certs/ca-certificates.crt", NULL, NULL, NULL, NULL);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Error setting TLS options: %s\n", mosquitto_strerror(rc));
        return 1;
    }

    rc = mosquitto_connect(mosq, BROKER_ADDRESS, BROKER_PORT, 60);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Unable to connect to broker: %s\n", mosquitto_strerror(rc));
        return 1;
    }

    printf("Connecting to MQTT broker...\n");

    // Inicia un hilo separado para monitorear las interfaces
    if (fork() == 0) {
        while (1) {
            int wan_loss = get_packet_loss(WAN_INTERFACE);
            int phy_loss = get_packet_loss(PHY_INTERFACE);

            if (wan_loss > phy_loss) {
                int wan_metric = get_interface_metric(WAN_INTERFACE);
                int phy_metric = get_interface_metric(PHY_INTERFACE);
                if (phy_metric > wan_metric) {
                    change_interface_metric(WAN_INTERFACE, phy_metric - 1);
                    change_interface_metric(PHY_INTERFACE, wan_metric + 1);
                }
            } else {
                int wan_metric = get_interface_metric(WAN_INTERFACE);
                int phy_metric = get_interface_metric(PHY_INTERFACE);
                if (wan_metric > phy_metric) {
                    change_interface_metric(PHY_INTERFACE, wan_metric - 1);
                    change_interface_metric(WAN_INTERFACE, phy_metric + 1);
                }
            }

            sleep(5);
        }
    }

    mosquitto_loop_forever(mosq, -1, 1);

    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();

    return 0;
}

