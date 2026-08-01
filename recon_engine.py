import socket
import subprocess
import threading
import xml.etree.ElementTree as ET
from queue import Queue, Empty
import time

# Use a threading Event instead of a bare global — safer for concurrent runs
_stop_event = threading.Event()
STOP_SCAN = False  # Keep for backward compatibility

def stop():
    global STOP_SCAN
    STOP_SCAN = True
    _stop_event.set()

def reset():
    global STOP_SCAN
    STOP_SCAN = False
    _stop_event.clear()

def get_banner(target, port):
    """
    Grab service banner from an open port.
    Returns a short string identifying the service.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((target, port))

        # Send appropriate probe depending on port
        if port in (80, 8080, 8000, 8443):
            s.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
        elif port == 21:
            pass  # FTP sends banner automatically
        elif port == 22:
            pass  # SSH sends banner automatically
        elif port == 25:
            pass  # SMTP sends banner automatically
        else:
            s.send(b"\r\n")

        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()

        # Extract first meaningful line
        first_line = banner.split("\n")[0].strip()
        return first_line[:80] if first_line else "Open"

    except Exception:
        return "Open"

def scan_port(target, port, results, throttle, grab_banner=True):
    if _stop_event.is_set():
        return

    try:
        if throttle > 0:
            time.sleep(throttle)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            result = s.connect_ex((target, port))

        if result == 0:
            if grab_banner:
                banner = get_banner(target, port)
                results.append(f"[+] {port} | {banner}")
            else:
                results.append(f"[+] {port}")

    except Exception:
        pass

def threader(target, port_queue, results, throttle, grab_banner):
    while True:
        if _stop_event.is_set():
            break
        try:
            port = port_queue.get_nowait()
        except Empty:
            break
        scan_port(target, port, results, throttle, grab_banner)
        port_queue.task_done()

def detect_filtered_ports(target, ports):
    filtered_ports = []

    port_list = sorted(
        {
            int(port)
            for port in ports
            if str(port).isdigit()
        }
    )

    if not port_list:
        return filtered_ports

    port_argument = ",".join(
        str(port)
        for port in port_list
    )

    command = [
        "nmap",
        "-Pn",
        "-sS",
        "-T4",
        "--max-retries",
        "1",
        "--reason",
        "-p",
        port_argument,
        "-oX",
        "-",
        target,
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )

        if not completed.stdout.strip():
            return filtered_ports

        root = ET.fromstring(
            completed.stdout
        )

        for port_node in root.findall(
            ".//ports/port"
        ):
            state_node = port_node.find(
                "state"
            )

            if state_node is None:
                continue

            state = state_node.get(
                "state",
                "",
            ).lower()

            if state != "filtered":
                continue

            port_id = port_node.get(
                "portid",
                "",
            )

            if port_id.isdigit():
                filtered_ports.append(
                    int(port_id)
                )

    except (
        FileNotFoundError,
        subprocess.TimeoutExpired,
        ET.ParseError,
        OSError,
    ):
        return []

    return sorted(
        set(filtered_ports)
    )

def start_recon_sequence(target, full_scan=False, throttle=0.01, grab_banner=True, thread_count=150):
    """
    Main scan function.
    Returns a list of result strings.
    [+] lines = open ports
    [-] lines = info/closed
    [!] lines = warnings/errors
    """
    reset()

    results = []
    port_queue = Queue()

    # Top 1000 common ports for standard scan
    TOP_1000 = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
        8443, 8888, 9000, 9090, 9200, 27017, 6379, 5432, 1433, 4444,
        8000, 8081, 8082, 9001, 9002, 1080, 1194, 500, 4500, 179,
        389, 636, 88, 464, 593, 49152, 49153, 49154, 49155, 49156,
        2049, 111, 512, 513, 514, 873, 2121, 3000, 4000, 5000,
        5001, 6000, 6001, 7000, 7001, 8008, 8009, 8080, 8443, 8888,
        9100, 9200, 9300, 10000, 10001, 11211, 27017, 28017, 5984,
        6379, 7474, 8983, 9042, 50070, 50075, 2181, 2888, 3888,
        7077, 8085, 9083, 16010, 50090, 60010, 60000, 4040, 8020,
        9000, 49, 7, 9, 11, 13, 15, 17, 18, 19, 20, 37, 39,
        42, 43, 69, 70, 79, 109, 115, 117, 119, 123, 137,
        138, 161, 162, 177, 194, 199, 201, 209, 213, 220,
        259, 264, 311, 312, 350, 351, 383, 384, 387, 399,
        427, 443, 444, 458, 497, 500, 512, 543, 544, 546,
        547, 548, 554, 563, 587, 591, 631, 666, 901, 953,
        1000, 1001, 1002, 1024, 1025, 1026, 1027, 1028, 1029, 1030,
        1099, 1100, 1110, 1111, 1119, 1125, 1200, 1201, 1211, 1212,
        1214, 1220, 1234, 1241, 1300, 1311, 1352, 1433, 1434, 1500,
        1503, 1512, 1521, 1524, 1527, 1533, 1589, 1645, 1646, 1701,
        1720, 1723, 1755, 1761, 1863, 1900, 1935, 1998, 2000, 2001,
        2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2020,
        2021, 2030, 2065, 2068, 2100, 2103, 2105, 2106, 2107, 2111,
        2119, 2121, 2200, 2222, 2251, 2260, 2301, 2381, 2382, 2383,
        2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601,
        2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717,
        2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920,
        2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011,
        3013, 3017, 3030, 3052, 3071, 3077, 3128, 3168, 3211, 3217,
        3220, 3222, 3260, 3268, 3269, 3283, 3300, 3301, 3306, 3322,
        3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372,
        3389, 3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580,
        3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809,
        3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889,
        3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000,
        4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126,
        4129, 4224, 4242, 4321, 4343, 4443, 4444, 4445, 4446, 4449,
        4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002,
        5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061,
        5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221,
        5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431,
        5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631,
        5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5810,
        5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901,
        5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925,
        5950, 5952, 5959, 5960, 5961, 5962, 5987, 5988, 5989, 5998,
        5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009,
        6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346,
        6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646,
        6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789,
        6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007,
        7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435,
        7443, 7496, 7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800,
        7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007,
        8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080,
        8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090,
        8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222,
        8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443,
        8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873, 8888,
        8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040,
        9050, 9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102,
        9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415, 9418, 9485,
        9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666,
        9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968,
        9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010,
        10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616,
        10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967,
        12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000,
        14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742,
        16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993,
        17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315, 19350,
        19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828,
        21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000,
        27352, 27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951,
        31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774,
        32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783,
        32784, 32785, 33354, 33899, 34571, 34572, 34573, 35500, 38292,
        40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100,
        48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159,
        49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999,
        50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636,
        50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328,
        55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080,
        60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000,
        65129, 65389
    ]

    priority_state_ports = [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        111,
        135,
        139,
        143,
        443,
        445,
        993,
        995,
        3306,
        3389,
        5432,
        5900,
        6379,
        8080,
        8443,
        10000,
        20000,
    ]

    if full_scan:
        ports = range(1, 65536)
        state_check_ports = priority_state_ports

        results.append(
            "[*] Full scan mode — 65,535 ports"
        )
    else:
        ports = sorted(
            set(TOP_1000)
        )

        state_check_ports = ports

        results.append(
            f"[*] Standard scan — top {len(ports)} unique ports"
        )

    results.append(f"[*] Target: {target}")
    results.append(f"[*] Threads: {thread_count} | Throttle: {throttle}s")

    for port in ports:
        port_queue.put(port)

    effective_thread_count = (
        min(thread_count, 75)
        if full_scan
        else thread_count
    )

    threads = []

    for _ in range(
        min(effective_thread_count, port_queue.qsize())
    ):
        t = threading.Thread(
            target=threader,
            args=(
                target,
                port_queue,
                results,
                throttle,
                grab_banner,
            ),
            daemon=True,
        )

        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    if not _stop_event.is_set():
        priority_ports = [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            111,
            135,
            139,
            143,
            443,
            445,
            993,
            995,
            3306,
            3389,
            5432,
            5900,
            6379,
            8080,
            8443,
            10000,
            20000,
        ]

        detected_ports = set()

        for line in results:
            if not line.startswith("[+]"):
                continue

            try:
                detected_port = int(
                    line.split()[1]
                )
                detected_ports.add(detected_port)
            except Exception:
                continue

        for port in priority_ports:
            if port in detected_ports:
                continue

            for _ in range(2):
                try:
                    with socket.socket(
                        socket.AF_INET,
                        socket.SOCK_STREAM,
                    ) as verify_socket:
                        verify_socket.settimeout(2.0)

                        verify_result = verify_socket.connect_ex(
                            (target, port)
                        )

                    if verify_result == 0:
                        if grab_banner:
                            banner = get_banner(
                                target,
                                port,
                            )

                            results.append(
                                f"[+] {port} | {banner}"
                            )
                        else:
                            results.append(
                                f"[+] {port}"
                            )

                        detected_ports.add(port)
                        break

                except Exception:
                    continue

        results.append(
            "[*] Verifying filtered port states..."
        )

        filtered_ports = detect_filtered_ports(
            target,
            state_check_ports,
        )

        filtered_ports = [
            port
            for port in filtered_ports
            if port not in detected_ports
        ]

        for port in filtered_ports:
            results.append(
                f"[?] {port} | FILTERED"
            )

        if filtered_ports:
            results.append(
                "[*] Filtered ports may indicate a firewall, ACL, "
                "IDS/IPS, or dynamic access control such as port knocking."
            )

    if _stop_event.is_set():
        results.append(
            "[!] SCAN TERMINATED BY USER"
        )
    elif not any(
        line.startswith("[+]")
        for line in results
    ):
        results.append(
            "[-] No open ports found in scanned range."
        )

    info_lines = [
        line
        for line in results
        if (
            line.startswith("[*]")
            or line.startswith("[-]")
            or line.startswith("[!]")
        )
    ]

    open_lines = sorted(
        [
            line
            for line in results
            if line.startswith("[+]")
        ],
        key=lambda line: int(
            line.split()[1]
        ),
    )

    filtered_lines = sorted(
        [
            line
            for line in results
            if line.startswith("[?]")
        ],
        key=lambda line: int(
            line.split()[1]
        ),
    )

    return (
        info_lines
        + open_lines
        + filtered_lines
    )
