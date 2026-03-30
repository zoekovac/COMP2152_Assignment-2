"""
Author: ZOE KOVAC
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

# Import the required modules
import socket
import threading
import sqlite3
import os
import platform
import datetime

# Print Python version and OS name (Step iii)
print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# The common_ports dictionary stores common port numbers as keys and their associated service names as values
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

# NetworkTool parent class
class NetworkTool:
    def __init__(self, target):
        self.__target = ""
        self.target = target

    # Q1: How does PortScanner reuse code from NetworkTool?
    # PortScanner reuses code from NetworkTool through inheritance (parent and child classes).
    # It automatically grabs data through the Parent class such as the target variable and its methods without having to
    # rewrite them in the child class.

    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value != "":
            self.__target = value
        else:
            print("Error: Target cannot be empty")

    def __del__(self):
        print("NetworkTool instance destroyed")

# Q3: What is the benefit of using @property and @target.setter?
# Using @property and @target.setter lets us control how the target value is used and changed.
# Instead of using the variable directly, we can check or modify it safely through these methods.
# This helps protect the data and prevents errors from occurring.

# Create the PortScanner child class that inherits from NetworkTool
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    # Q4: What would happen without try-except here?
    # Without try-except, any socket error could stop the program or crash a scanning thread.
    # That would make the scanner less reliable.
    # Using try-except allows the program to handle errors safely and continue scanning other ports.

    def scan_port(self, port):

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))

            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            service_name = common_ports.get(port, "Unknown")

            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")

        finally:
            if sock:
                sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # We use threading so multiple ports can be scanned at the same time instead of waiting for one scan to finish
    # before starting the next. This makes the scanner much faster.

    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

# Create save_results(target, results) function
def save_results(target, results):
    connection = None
    try:
        connection = sqlite3.connect("scan_history.db")
        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )
        """)

        for port, status, service in results:
            cursor.execute("""
                INSERT INTO scans (target, port, status, service, scan_date)
                VALUES (?, ?, ?, ?, ?)
            """, (target, port, status, service, str(datetime.datetime.now())))

        connection.commit()

    except sqlite3.Error as error:
        print(f"Database error: {error}")

    finally:
        if connection is not None:
            connection.close()

# Create load_past_scans() function
def load_past_scans():
    connection = None
    try:
        if not os.path.exists("scan_history.db"):
            print("No past scans found.")
            return

        connection = sqlite3.connect("scan_history.db")
        cursor = connection.cursor()
        cursor.execute("SELECT target, port, status, service, scan_date FROM scans")
        rows = cursor.fetchall()

        if not rows:
            print("No past scans found.")
            return

        for target, port, status, service, scan_date in rows:
            print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")

    except sqlite3.Error:
        print("No past scans found.")

    finally:
        if connection is not None:
            connection.close()

# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    pass

    # Get user input with try-except
    target = input("Enter target IP address: ").strip()
    if target == "":
        target = "127.0.0.1"

    try:
        start_port = int(input("Enter starting port (1-1024): "))
        end_port = int(input("Enter ending port (1-1024): "))

        if start_port < 1 or start_port > 1024 or end_port < 1 or end_port > 1024:
            print("Port must be between 1 and 1024.")
        elif end_port < start_port:
            print("End port must be greater tgit branchhan or equal to start port.")
        else:

            # After valid input
            scanner = PortScanner(target)
            print(f"Scanning {target} from port {start_port} to {end_port}...")
            scanner.scan_range(start_port, end_port)

            open_ports = scanner.get_open_ports()

            print(f"--- Scan Results for {target} ---")
            for port, status, service in open_ports:
                print(f"Port {port}: {status} ({service})")
            print("------")
            print(f"Total open ports found: {len(open_ports)}")

            save_results(target, scanner.scan_results)

            history_choice = input("Would you like to see past scan history? (yes/no): ").strip().lower()
            if history_choice == "yes":
                load_past_scans()

    except ValueError:
        print("Invalid input. Please enter a valid integer.")

# Q5: New Feature Proposal
# One useful new feature would be exporting scan results to a text, or CSV/Excel (spreadsheet) file.
# This would make it easier for users to save, review, and share their scan data later.
# For example, a user could easily save and see which ports are open through the file. The file could easily be shared
# amongst team members etc.

# Diagram: See diagram_101107123.png in the repository root
