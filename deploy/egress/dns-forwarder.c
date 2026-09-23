#define _GNU_SOURCE

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/*
 * Upstream half of the strict DNS boundary.
 *
 * This process never parses a workload DNS packet or a workload-controlled name.
 * Its local peer supplies exactly two bytes: an index into the immutable startup
 * name table and an A/AAAA selector. The peer UID is authenticated with SO_PEERCRED.
 * Only this process may reach Docker's embedded resolver.
 */

#define DNS_HEADER_SIZE 12U
#define DNS_MAX_PACKET 65535U
#define DNS_MAX_NAME 253U
#define DNS_MAX_ALLOWED_NAMES 66U
#define DNS_FORWARDER_UID 10022U
#define DNS_FORWARDER_GID 10022U
#define DNS_PROXY_UID 10021U
#define DNS_PROXY_GID 10021U
#define DNS_UPSTREAM_PORT 53U

struct dns_question {
    char name[DNS_MAX_NAME + 1U];
    uint16_t qtype;
};

static char allowed_names[DNS_MAX_ALLOWED_NAMES][DNS_MAX_NAME + 1U];
static size_t allowed_name_count;

static uint16_t read_u16(const unsigned char *buffer) {
    return (uint16_t)(((uint16_t)buffer[0] << 8U) | (uint16_t)buffer[1]);
}

static void write_u16(unsigned char *buffer, uint16_t value) {
    buffer[0] = (unsigned char)(value >> 8U);
    buffer[1] = (unsigned char)(value & 0xffU);
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
    size_t csv_length = strlen(csv);

    if (csv_length == 0U || csv_length >= sizeof(copy) || csv[0] == ',' ||
        csv[csv_length - 1U] == ',' || strstr(csv, ",,") != NULL) {
        return -1;
    }
    memcpy(copy, csv, csv_length + 1U);
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

static int random_u16(uint16_t *value) {
    ssize_t result;
    do {
        result = getrandom(value, sizeof(*value), 0);
    } while (result < 0 && errno == EINTR);
    return result == (ssize_t)sizeof(*value) ? 0 : -1;
}

static int build_canonical_query(const struct dns_question *question,
                                 uint16_t upstream_id,
                                 unsigned char *output, size_t output_size,
                                 size_t *written) {
    if (output_size < DNS_HEADER_SIZE) {
        return -1;
    }
    memset(output, 0, DNS_HEADER_SIZE);
    write_u16(output, upstream_id);
    write_u16(output + 2U, 0x0100U);
    write_u16(output + 4U, 1U);
    return encode_question(question, output, output_size, written);
}

static int connect_upstream(int type) {
    struct sockaddr_in upstream = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_UPSTREAM_PORT),
    };
    int descriptor = socket(AF_INET, type | SOCK_CLOEXEC, 0);

    if (descriptor < 0 ||
        inet_pton(AF_INET, "127.0.0.11", &upstream.sin_addr) != 1 ||
        set_socket_timeouts(descriptor) != 0 ||
        connect(descriptor, (const struct sockaddr *)&upstream,
                sizeof(upstream)) != 0) {
        if (descriptor >= 0) {
            close(descriptor);
        }
        return -1;
    }
    return descriptor;
}

static int response_header_matches(const unsigned char *response,
                                   size_t response_length,
                                   uint16_t upstream_id) {
    uint16_t flags;
    if (response_length < DNS_HEADER_SIZE || read_u16(response) != upstream_id) {
        return 0;
    }
    flags = read_u16(response + 2U);
    return (flags & 0x8000U) != 0U && (flags & 0x7800U) == 0U &&
           read_u16(response + 4U) == 1U;
}

static int forward_udp(const unsigned char *query, size_t query_length,
                       uint16_t upstream_id, unsigned char *response,
                       size_t *response_length) {
    int upstream = connect_upstream(SOCK_DGRAM);
    ssize_t received;

    if (upstream < 0 || write_all(upstream, query, query_length) != 0) {
        if (upstream >= 0) {
            close(upstream);
        }
        return -1;
    }
    do {
        received = recv(upstream, response, DNS_MAX_PACKET, 0);
    } while (received < 0 && errno == EINTR);
    close(upstream);
    if (received < (ssize_t)DNS_HEADER_SIZE ||
        !response_header_matches(response, (size_t)received, upstream_id)) {
        return -1;
    }
    *response_length = (size_t)received;
    return 0;
}

static int forward_tcp(const unsigned char *query, size_t query_length,
                       uint16_t upstream_id, unsigned char *response,
                       size_t *response_length) {
    int upstream = connect_upstream(SOCK_STREAM);
    unsigned char length_prefix[2U];
    uint16_t received_length;

    if (upstream < 0 || query_length > UINT16_MAX) {
        if (upstream >= 0) {
            close(upstream);
        }
        return -1;
    }
    write_u16(length_prefix, (uint16_t)query_length);
    if (write_all(upstream, length_prefix, sizeof(length_prefix)) != 0 ||
        write_all(upstream, query, query_length) != 0 ||
        read_all(upstream, length_prefix, sizeof(length_prefix)) != 0) {
        close(upstream);
        return -1;
    }
    received_length = read_u16(length_prefix);
    if (received_length < DNS_HEADER_SIZE ||
        read_all(upstream, response, received_length) != 0) {
        close(upstream);
        return -1;
    }
    close(upstream);
    if (!response_header_matches(response, received_length, upstream_id)) {
        return -1;
    }
    *response_length = received_length;
    return 0;
}

static int resolve_index(unsigned char name_index, unsigned char qtype_byte,
                         unsigned char *response, size_t *response_length) {
    struct dns_question question;
    unsigned char query[DNS_HEADER_SIZE + DNS_MAX_NAME + 6U];
    size_t query_length = 0U;
    uint16_t upstream_id;

    if ((size_t)name_index >= allowed_name_count ||
        (qtype_byte != 1U && qtype_byte != 28U)) {
        return -1;
    }
    memset(&question, 0, sizeof(question));
    memcpy(question.name, allowed_names[name_index],
           strlen(allowed_names[name_index]) + 1U);
    question.qtype = qtype_byte;
    if (random_u16(&upstream_id) != 0 ||
        build_canonical_query(&question, upstream_id, query, sizeof(query),
                              &query_length) != 0 ||
        forward_udp(query, query_length, upstream_id, response,
                    response_length) != 0) {
        return -1;
    }
    if ((read_u16(response + 2U) & 0x0200U) != 0U &&
        forward_tcp(query, query_length, upstream_id, response,
                    response_length) != 0) {
        return -1;
    }
    return 0;
}

static int create_listener(const char *path) {
    struct sockaddr_un local;
    struct stat status;
    int descriptor;

    if (strlen(path) == 0U || strlen(path) >= sizeof(local.sun_path) ||
        lstat(path, &status) == 0 || errno != ENOENT) {
        return -1;
    }
    memset(&local, 0, sizeof(local));
    local.sun_family = AF_UNIX;
    memcpy(local.sun_path, path, strlen(path) + 1U);
    descriptor = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (descriptor < 0 ||
        bind(descriptor, (const struct sockaddr *)&local, sizeof(local)) != 0 ||
        chmod(path, 0622U) != 0 || lstat(path, &status) != 0 ||
        !S_ISSOCK(status.st_mode) || status.st_uid != DNS_FORWARDER_UID ||
        status.st_gid != DNS_FORWARDER_GID ||
        (status.st_mode & 07777U) != 0622U || status.st_nlink != 1U ||
        listen(descriptor, 16) != 0) {
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
        !S_ISREG(status.st_mode) || status.st_uid != DNS_FORWARDER_UID ||
        status.st_gid != DNS_FORWARDER_GID || (status.st_mode & 07777U) != 0644U ||
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

static void handle_client(int listener) {
    unsigned char request[3U];
    static unsigned char response[DNS_MAX_PACKET];
    struct ucred peer;
    socklen_t peer_length = sizeof(peer);
    int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    ssize_t received;
    size_t response_length = 0U;

    if (client < 0) {
        return;
    }
    if (set_socket_timeouts(client) != 0 ||
        getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &peer_length) != 0 ||
        peer_length != sizeof(peer) || peer.uid != DNS_PROXY_UID ||
        peer.gid != DNS_PROXY_GID || peer.pid <= 0) {
        close(client);
        return;
    }
    do {
        received = recv(client, request, sizeof(request), 0);
    } while (received < 0 && errno == EINTR);
    if (received == 2 &&
        resolve_index(request[0], request[1], response, &response_length) == 0) {
        (void)send(client, response, response_length, MSG_NOSIGNAL);
    }
    close(client);
}

int main(int argc, char **argv) {
    int listener;

    if (argc != 4 || getuid() != DNS_FORWARDER_UID ||
        geteuid() != DNS_FORWARDER_UID || getgid() != DNS_FORWARDER_GID ||
        getegid() != DNS_FORWARDER_GID || load_allowed_names(argv[1]) != 0 ||
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        return 64;
    }
    signal(SIGPIPE, SIG_IGN);
    listener = create_listener(argv[2]);
    if (listener < 0 || publish_ready(argv[3]) != 0) {
        if (listener >= 0) {
            close(listener);
        }
        return 70;
    }
    for (;;) {
        handle_client(listener);
    }
}
