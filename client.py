import os
import socket
import struct
import select
import time

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2

def checksum(source_string):
    csum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0

    while count < count_to:
        this_val = (source_string[count + 1] << 8) + source_string[count]
        csum = csum + this_val
        csum = csum & 0xffffffff
        count = count + 2

    if count_to < len(source_string):
        csum = csum + source_string[len(source_string) - 1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
    pid = os.getpid() & 0xFFFF
    my_checksum = 0
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, pid, 1)
    data = struct.pack("d", time.time())
    my_checksum = checksum(header + data)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), pid, 1)
    return header + data

def traceroute(destination, timeout=TIMEOUT, max_hops=MAX_HOPS, tries=TRIES):
    print(f"\nTraceroute para {destination} ({socket.gethostbyname(destination)}), {max_hops} saltos máximos:\n")

    try:
        dest_addr = socket.gethostbyname(destination)
    except socket.gaierror as e:
        print(f"Erro: {e.strerror}. Não foi possível resolver o host {destination}.")
        return

    rtts = []
    
    for ttl in range(1, max_hops + 1):
        print(f"{ttl:2} ", end="")

        reached = False 
        for attempt in range(tries):
            try:
                icmp = socket.getprotobyname("icmp")
                my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
                my_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
                my_socket.settimeout(timeout)

                packet = build_packet()
                my_socket.sendto(packet, (dest_addr, 0))
                start_time = time.time()

                ready = select.select([my_socket], [], [], timeout)
                if ready[0] == []:
                    print("  *        *        *    Request timed out.")
                    continue

                recv_packet, addr = my_socket.recvfrom(1024)
                time_received = time.time()
                icmp_header = recv_packet[20:28]
                types, code, checksum, packet_id, sequence = struct.unpack("bbHHh", icmp_header)

                try:
                    host_name = socket.gethostbyaddr(addr[0])[0]
                except socket.herror:
                    host_name = addr[0]

                if types == 11:
                    bytes_recvd = struct.calcsize("d")
                    time_sent = struct.unpack("d", recv_packet[28:28 + bytes_recvd])[0]
                    rtt = int((time_received - time_sent) * 1000)
                    print(f"rtt={rtt:3} ms  {addr[0]} ({host_name}), code: {types}")
                    rtts.append(rtt)
                elif types == 3:
                    print(f"Destino inacessível ({addr[0]}), code: {types}")
                    return
                elif types == 0:
                    bytes_recvd = struct.calcsize("d")
                    time_sent = struct.unpack("d", recv_packet[28:28 + bytes_recvd])[0]
                    rtt = int((time_received - time_sent) * 1000)
                    print(f"rtt={rtt:3} ms  {addr[0]} ({host_name}), code: {types}")
                    reached = True
                    break
            except socket.error as e:
                print(f"Erro no salto {ttl}: {e}")
            finally:
                my_socket.close()

        if reached:
            print(f"\nDestino {host_name} ({addr[0]}) alcançado!")
            print("\nResumo do Traceroute:")
            print(f"RTT Total: {sum(rtts)} ms")
            print(f"RTT Máximo: {max(rtts)} ms")
            print(f"RTT Mínimo: {min(rtts)} ms")
            return

    print("Destino não alcançado no número máximo de saltos.")

if __name__ == '__main__':
    traceroute("facebook.com")
