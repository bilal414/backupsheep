#define _GNU_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/*
 * A deliberately small, no-secret DNS policy proxy for strict egress mode.
 *
 * It never forwards a client packet verbatim. Only one exact, reviewed IN A or
 * AAAA question is accepted. It sends only a two-byte immutable-name index and
 * A/AAAA selector over a local authenticated socket to the separate forwarder.
 * This parser has no upstream DNS access, so parser compromise cannot turn a
 * worker-controlled packet into an arbitrary DNS exfiltration channel.
 */

#define DNS_HEADER_SIZE 12U
#define DNS_MAX_PACKET 65535U
#define DNS_MAX_NAME 253U
#define DNS_MAX_ALLOWED_NAMES 66U
#define DNS_PROXY_UID 10021U
#define DNS_PROXY_GID 10021U
#define DNS_FORWARDER_UID 10022U
#define DNS_FORWARDER_GID 10022U
#define DNS_PROXY_PORT 1053U

struct dns_question {
    char name[DNS_MAX_NAME + 1U];
    uint16_t qtype;
};

static char allowed_names[DNS_MAX_ALLOWED_NAMES][DNS_MAX_NAME + 1U];
static size_t allowed_name_count;
static const char *forwarder_socket_path;

static uint16_t read_u16(const unsigned char *buffer) {
    return (uint16_t)(((uint16_t)buffer[0] << 8U) | (uint16_t)buffer[1]);
}

static void write_u16(unsigned char *buffer, uint16_t value) {
    buffer[0] = (unsigned char)(value >> 8U);
    buffer[1] = (unsigned char)(value & 0xffU);
}

static int set_socket_timeouts(int descriptor) {
    const struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    return setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                      sizeof(timeout)) == 0 &&
                   setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                              sizeof(timeout)) == 0
               ? 0
               : -1;
}

static int valid_name_character(unsigned char value) {
    return isalnum(value) || value == '-' || value == '_';
}

static int validate_configured_name(const char *name) {
    size_t total = strlen(name);
    size_t label_length = 0U;

    if (total == 0U || total > DNS_MAX_NAME || name[0] == '.' ||
        name[total - 1U] == '.') {
        return -1;
    }
    for (size_t index = 0U; index < total; ++index) {
        unsigned char value = (unsigned char)name[index];
        if (value == '.') {
            if (label_length == 0U || label_length > 63U ||
                name[index - 1U] == '-') {
                return -1;
            }
            label_length = 0U;
            continue;
        }
        if (!valid_name_character(value) ||
            (label_length == 0U && value == '-')) {
            return -1;
        }
        ++label_length;
    }
    return label_length > 0U && label_length <= 63U && name[total - 1U] != '-'
               ? 0
               : -1;
}

static int load_allowed_names(const char *csv) {
    char copy[4097U];
    char *cursor = NULL;
    char *token = NULL;

    if (strlen(csv) == 0U || strlen(csv) >= sizeof(copy) || csv[0] == ',' ||
        csv[strlen(csv) - 1U] == ',' || strstr(csv, ",,") != NULL) {
        return -1;
    }
    memcpy(copy, csv, strlen(csv) + 1U);
    for (token = strtok_r(copy, ",", &cursor); token != NULL;
         token = strtok_r(NULL, ",", &cursor)) {
        if (allowed_name_count >= DNS_MAX_ALLOWED_NAMES ||
            validate_configured_name(token) != 0) {
            return -1;
        }
        for (size_t index = 0U; token[index] != '\0'; ++index) {
            token[index] = (char)tolower((unsigned char)token[index]);
        }
        for (size_t prior = 0U; prior < allowed_name_count; ++prior) {
            if (strcmp(allowed_names[prior], token) == 0) {
                return -1;
            }
        }
        memcpy(allowed_names[allowed_name_count], token, strlen(token) + 1U);
        ++allowed_name_count;
    }
    return allowed_name_count > 0U ? 0 : -1;
}

static int decode_question(const unsigned char *packet, size_t packet_length,
                           struct dns_question *question) {
    size_t cursor = DNS_HEADER_SIZE;
    size_t name_length = 0U;
    int first_label = 1;

    if (packet_length < DNS_HEADER_SIZE || read_u16(packet + 4U) != 1U) {
        return -1;
    }
    while (cursor < packet_length) {
        unsigned int label_length = packet[cursor++];
        if (label_length == 0U) {
            break;
        }
        if ((label_length & 0xc0U) != 0U || label_length > 63U ||
            cursor + label_length > packet_length) {
            return -1;
        }
        if (!first_label) {
            if (name_length >= DNS_MAX_NAME) {
                return -1;
            }
            question->name[name_length++] = '.';
        }
        first_label = 0;
        for (unsigned int index = 0U; index < label_length; ++index) {
            unsigned char value = packet[cursor++];
            if (!valid_name_character(value) ||
                (index == 0U && value == '-') ||
                (index + 1U == label_length && value == '-')) {
                return -1;
            }
            if (name_length >= DNS_MAX_NAME) {
                return -1;
            }
            question->name[name_length++] =
                (char)tolower((unsigned char)value);
        }
    }
    if (first_label || cursor + 4U > packet_length) {
        return -1;
    }
    question->name[name_length] = '\0';
    question->qtype = read_u16(packet + cursor);
    if (read_u16(packet + cursor + 2U) != 1U) {
        return -1;
    }
    return 0;
}

static int allowed_name_index(const char *name) {
    for (size_t index = 0U; index < allowed_name_count; ++index) {
        if (strcmp(allowed_names[index], name) == 0) {
            return (int)index;
        }
    }
    return -1;
}

static int encode_question(const struct dns_question *question,
                           unsigned char *output, size_t output_size,
                           size_t *written) {
    const char *label = question->name;
    size_t cursor = DNS_HEADER_SIZE;

    while (*label != '\0') {
        const char *dot = strchr(label, '.');
        size_t label_length = dot == NULL ? strlen(label) : (size_t)(dot - label);
        if (label_length == 0U || label_length > 63U ||
            cursor + 1U + label_length + 1U + 4U > output_size) {
            return -1;
        }
        output[cursor++] = (unsigned char)label_length;
        memcpy(output + cursor, label, label_length);
        cursor += label_length;
        if (dot == NULL) {
            break;
        }
        label = dot + 1;
    }
    output[cursor++] = 0U;
    write_u16(output + cursor, question->qtype);
    cursor += 2U;
    write_u16(output + cursor, 1U);
    cursor += 2U;
    *written = cursor;
    return 0;
}

static size_t build_error_response(const unsigned char *request,
                                   const struct dns_question *question,
                                   uint16_t response_code,
                                   unsigned char *response,
                                   size_t response_size) {
    size_t written = DNS_HEADER_SIZE;
    uint16_t request_flags = 0U;

    if (response_size < DNS_HEADER_SIZE) {
        return 0U;
    }
    memset(response, 0, DNS_HEADER_SIZE);
    memcpy(response, request, 2U);
    request_flags = read_u16(request + 2U);
    write_u16(response + 2U,
              (uint16_t)(0x8080U | (request_flags & 0x0100U) | response_code));
    if (question != NULL) {
        write_u16(response + 4U, 1U);
        if (encode_question(question, response, response_size, &written) != 0) {
            return 0U;
        }
    }
    return written;
}

static int write_all(int descriptor, const unsigned char *buffer, size_t length) {
    size_t written = 0U;
    while (written < length) {
        ssize_t result = write(descriptor, buffer + written, length - written);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return -1;
        }
        written += (size_t)result;
    }
    return 0;
}

static int read_all(int descriptor, unsigned char *buffer, size_t length) {
    size_t received = 0U;
    while (received < length) {
        ssize_t result = read(descriptor, buffer + received, length - received);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return -1;
        }
        received += (size_t)result;
    }
    return 0;
}

static int response_matches(const unsigned char *response, size_t response_length,
                            const struct dns_question *question) {
    struct dns_question response_question;
    uint16_t flags;

    if (response_length < DNS_HEADER_SIZE) {
        return 0;
    }
    flags = read_u16(response + 2U);
    if ((flags & 0x8000U) == 0U || (flags & 0x7800U) != 0U ||
        decode_question(response, response_length, &response_question) != 0) {
        return 0;
    }
    return response_question.qtype == question->qtype &&
           strcmp(response_question.name, question->name) == 0;
}

static int query_forwarder(const char *path, const struct dns_question *question,
                           unsigned char *response, size_t *response_length) {
    struct sockaddr_un forwarder;
    unsigned char request[2U];
    struct ucred peer;
    socklen_t peer_length = sizeof(peer);
    int name_index = allowed_name_index(question->name);
    int descriptor;
    ssize_t received;

    if (name_index < 0 || name_index > UINT8_MAX || strlen(path) == 0U ||
        strlen(path) >= sizeof(forwarder.sun_path)) {
        return -1;
    }
    memset(&forwarder, 0, sizeof(forwarder));
    forwarder.sun_family = AF_UNIX;
    memcpy(forwarder.sun_path, path, strlen(path) + 1U);
    descriptor = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (descriptor < 0 || set_socket_timeouts(descriptor) != 0 ||
        connect(descriptor, (const struct sockaddr *)&forwarder,
                sizeof(forwarder)) != 0 ||
        getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &peer, &peer_length) != 0 ||
        peer_length != sizeof(peer) || peer.uid != DNS_FORWARDER_UID ||
        peer.gid != DNS_FORWARDER_GID || peer.pid <= 0) {
        if (descriptor >= 0) {
            close(descriptor);
        }
        return -1;
    }
    request[0] = (unsigned char)name_index;
    request[1] = (unsigned char)question->qtype;
    if (send(descriptor, request, sizeof(request), MSG_NOSIGNAL) !=
        (ssize_t)sizeof(request)) {
        close(descriptor);
        return -1;
    }
    do {
        received = recv(descriptor, response, DNS_MAX_PACKET, 0);
    } while (received < 0 && errno == EINTR);
    close(descriptor);
    if (received < (ssize_t)DNS_HEADER_SIZE ||
        !response_matches(response, (size_t)received, question)) {
        return -1;
    }
    *response_length = (size_t)received;
    return 0;
}

static size_t process_query(const char *forwarder_path,
                            const unsigned char *request, size_t request_length,
                            unsigned char *response) {
    struct dns_question question;
    size_t canonical_question_length = 0U;
    size_t response_length = 0U;
    uint16_t flags;

    if (request_length < DNS_HEADER_SIZE) {
        return 0U;
    }
    flags = read_u16(request + 2U);
    if ((flags & 0x8000U) != 0U || (flags & 0x7800U) != 0U ||
        read_u16(request + 6U) != 0U || read_u16(request + 8U) != 0U ||
        decode_question(request, request_length, &question) != 0) {
        return build_error_response(request, NULL, 1U, response, DNS_MAX_PACKET);
    }
    if ((question.qtype != 1U && question.qtype != 28U) ||
        allowed_name_index(question.name) < 0) {
        return build_error_response(request, &question, 5U, response,
                                    DNS_MAX_PACKET);
    }
    if (query_forwarder(forwarder_path, &question, response,
                        &response_length) != 0) {
        return build_error_response(request, &question, 2U, response,
                                    DNS_MAX_PACKET);
    }
    /*
     * Docker's embedded resolver may apply DNS 0x20 case randomization even
     * though the forwarder supplied a lowercase canonical question. Replace
     * the already-validated, uncompressed response question with the proxy's
     * immutable lowercase form before returning it to the workload. The wire
     * length is unchanged, so any answer compression pointers remain valid.
     */
    if (encode_question(&question, response, response_length,
                        &canonical_question_length) != 0) {
        return build_error_response(request, &question, 2U, response,
                                    DNS_MAX_PACKET);
    }
    memcpy(response, request, 2U); /* restore only the workload's local ID */
    return response_length;
}

static int create_listener(int type) {
    struct sockaddr_in local = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PROXY_PORT),
    };
    int descriptor = socket(AF_INET, type | SOCK_CLOEXEC, 0);

    if (descriptor < 0 ||
        inet_pton(AF_INET, "127.0.0.1", &local.sin_addr) != 1 ||
        bind(descriptor, (const struct sockaddr *)&local, sizeof(local)) != 0 ||
        (type == SOCK_STREAM && listen(descriptor, 16) != 0)) {
        if (descriptor >= 0) {
            close(descriptor);
        }
        return -1;
    }
    return descriptor;
}

static int publish_ready(const char *path) {
    struct stat status;
    char value[128U];
    int descriptor = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    int length;

    if (descriptor < 0 || fstat(descriptor, &status) != 0 ||
        !S_ISREG(status.st_mode) || status.st_uid != DNS_PROXY_UID ||
        status.st_gid != DNS_PROXY_GID || (status.st_mode & 07777U) != 0644U ||
        status.st_nlink != 1U) {
        if (descriptor >= 0) {
            close(descriptor);
        }
        return -1;
    }
    length = snprintf(value, sizeof(value), "status=ready\npid=%ld\n",
                      (long)getpid());
    if (length <= 0 || (size_t)length >= sizeof(value) ||
        write_all(descriptor, (const unsigned char *)value, (size_t)length) != 0 ||
        fsync(descriptor) != 0 || close(descriptor) != 0) {
        return -1;
    }
    return 0;
}

static void handle_udp(int listener) {
    static unsigned char request[DNS_MAX_PACKET];
    static unsigned char response[DNS_MAX_PACKET];
    struct sockaddr_storage client;
    socklen_t client_length = sizeof(client);
    ssize_t received = recvfrom(listener, request, sizeof(request), 0,
                                (struct sockaddr *)&client, &client_length);
    size_t response_length;

    if (received <= 0) {
        return;
    }
    response_length = process_query(forwarder_socket_path, request,
                                    (size_t)received, response);
    if (response_length > 0U) {
        (void)sendto(listener, response, response_length, 0,
                     (const struct sockaddr *)&client, client_length);
    }
}

static void handle_tcp(int listener) {
    static unsigned char request[DNS_MAX_PACKET];
    static unsigned char response[DNS_MAX_PACKET];
    unsigned char length_prefix[2U];
    int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    uint16_t request_length;
    size_t response_length;

    if (client < 0) {
        return;
    }
    if (set_socket_timeouts(client) != 0 ||
        read_all(client, length_prefix, sizeof(length_prefix)) != 0) {
        close(client);
        return;
    }
    request_length = read_u16(length_prefix);
    if (request_length < DNS_HEADER_SIZE ||
        read_all(client, request, request_length) != 0) {
        close(client);
        return;
    }
    response_length = process_query(forwarder_socket_path, request,
                                    request_length, response);
    if (response_length > 0U && response_length <= UINT16_MAX) {
        write_u16(length_prefix, (uint16_t)response_length);
        (void)write_all(client, length_prefix, sizeof(length_prefix));
        (void)write_all(client, response, response_length);
    }
    close(client);
}

int main(int argc, char **argv) {
    int udp_listener;
    int tcp_listener;
    struct pollfd readers[2U];
    struct stat forwarder_status;

    if (argc != 4 || getuid() != DNS_PROXY_UID || geteuid() != DNS_PROXY_UID ||
        getgid() != DNS_PROXY_GID || getegid() != DNS_PROXY_GID ||
        load_allowed_names(argv[1]) != 0 ||
        lstat(argv[3], &forwarder_status) != 0 ||
        !S_ISSOCK(forwarder_status.st_mode) ||
        forwarder_status.st_uid != DNS_FORWARDER_UID ||
        forwarder_status.st_gid != DNS_FORWARDER_GID ||
        (forwarder_status.st_mode & 07777U) != 0622U ||
        forwarder_status.st_nlink != 1U ||
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        return 64;
    }
    forwarder_socket_path = argv[3];
    signal(SIGPIPE, SIG_IGN);
    udp_listener = create_listener(SOCK_DGRAM);
    tcp_listener = create_listener(SOCK_STREAM);
    if (udp_listener < 0 || tcp_listener < 0 || publish_ready(argv[2]) != 0) {
        if (udp_listener >= 0) {
            close(udp_listener);
        }
        if (tcp_listener >= 0) {
            close(tcp_listener);
        }
        return 70;
    }
    readers[0].fd = udp_listener;
    readers[0].events = POLLIN;
    readers[1].fd = tcp_listener;
    readers[1].events = POLLIN;
    for (;;) {
        readers[0].revents = 0;
        readers[1].revents = 0;
        if (poll(readers, 2U, -1) < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 71;
        }
        if ((readers[0].revents & POLLIN) != 0) {
            handle_udp(udp_listener);
        }
        if ((readers[1].revents & POLLIN) != 0) {
            handle_tcp(tcp_listener);
        }
    }
}
