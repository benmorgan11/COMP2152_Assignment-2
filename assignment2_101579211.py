"""
Author: Ben Morgan
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

# TODO: Import the required modules (Step ii)
# socket, threading, sqlite3, os, platform, datetime

import socket
import threading
import sqlite3
import os
import platform
import datetime

# TODO: Print Python version and OS name (Step iii)

print("Python Version:", platform.python_version())
print("Operating System:", os.name)

# TODO: Create the common_ports dictionary (Step iv)
# Add a 1-line comment above it explaining what it stores
# This dictionary stores common port numbers and their serviice names
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


# TODO: Create the NetworkTool parent class (Step v)
# - Constructor: takes target, stores as private self.__target
# - @property getter for target
# - @target.setter with empty string validation
# - Destructor: prints "NetworkTool instance destroyed"

class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # TODO: Your 2-4 sentence answer here... (Part 2, Q3)
    # Using @property and @target.setter lets the program control how the target value is accessed and changed.
    # Instead of directly changing the variable, we can check if the value is valid first.
    # Here, it prevents the user (me) from setting a empty target, which would cause problems later.

    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# TODO: Your 2-4 sentence answer here... (Part 2, Q1)
# PortScanner reuses code by inheriting from NetworkTool rather than rewriting everything again.
# A example is, it uses super().__init__(target) to set up the target value from the parent class.
# It also uses the target property from NetworkTool, so it doesn't need to state that logic again.

# TODO: Create the PortScanner child class that inherits from NetworkTool (Step vi)
# - Constructor: call super().__init__(target), initialize self.scan_results = [], self.lock = threading.Lock()
# - Destructor: print "PortScanner instance destroyed", call super().__del__()
#
# - scan_port(self, port):
#     Q4: What would happen without try-except here?
#     TODO: Your 2-4 sentence answer here... (Part 2, Q4)
#
#     - try-except with socket operations
#     - Create socket, set timeout, connect_ex
#     - Determine Open/Closed status
#     - Look up service name from common_ports (use "Unknown" if not found)
#     - Acquire lock, append (port, status, service_name) tuple, release lock
#     - Close socket in finally block
#     - Catch socket.error, print error message
#
# - get_open_ports(self):
#     - Use list comprehension to return only "Open" results
#
#     Q2: Why do we use threading instead of scanning one port at a time?
#     TODO: Your 2-4 sentence answer here... (Part 2, Q2)
#
# - scan_range(self, start_port, end_port):
#     - Create threads list
#     - Create Thread for each port targeting scan_port
#     - Start all threads (one loop)
#     - Join all threads (separate loop)

class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # TODO: Your 2-4 sentence answer here... (Part 2, Q4)
        # Without try-except, the program might crash if theres a connection error and/or the target is unreachable.
        # This means that one bad port scan could stop the whole program.
        # Using try-except lets the program to handle the error and keep scanning the rest of the ports.

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))

            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            if port in common_ports:
                service_name = common_ports[port]
            else:
                service_name = "Unknown"

            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")

        finally:
            try:
                sock.close()
            except:
                pass

    def get_open_ports(self):
        return [item for item in self.scan_results if item[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # TODO: Your 2-4 sentence answer here... (Part 2, Q2)
    # Threading lets the program scan multiple ports at the same time instead of one at a time.
    # If 1024 ports were scanned without threading, it would take a really long time to finish.
    # Using threads makes the scan much faster and more efficient overall.

    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join()


# TODO: Create save_results(target, results) function (Step vii)
# - Connect to scan_history.db
# - CREATE TABLE IF NOT EXISTS scans (id, target, port, status, service, scan_date)
# - INSERT each result with datetime.datetime.now()
# - Commit, close
# - Wrap in try-except for sqlite3.Error

def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("""
                       CREATE TABLE IF NOT EXISTS scans
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY
                           AUTOINCREMENT,
                           target
                           TEXT,
                           port
                           INTEGER,
                           status
                           TEXT,
                           service
                           TEXT,
                           scan_date
                           TEXT
                       )""")

        for result in results:
            port = result[0]
            status = result[1]
            service = result[2]

            date_now = str(datetime.datetime.now())

            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, date_now)
            )

        conn.commit()
        conn.close()

    except sqlite3.Error as e:
        print(f"Database error: {e}")


# TODO: Create load_past_scans() function (Step viii)
# - Connect to scan_history.db
# - SELECT all from scans
# - Print each row in readable format
# - Handle missing table/db: print "No past scans found."
# - Close connection

def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()

        if len(rows) == 0:
            print("No past scans found.")
        else:
            for row in rows:
                print("[" + str(row[5]) + "] " + str(row[1]) + " : Port " + str(row[2]) + " (" + str(
                    row[4]) + ") - " + str(row[3]))

        conn.close()

    except:
        print("No past scans found.")


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    target = input("Enter target IP (default 127.0.0.1): ")
    if target == "":
        target = "127.0.0.1"

    try:
        start_port = int(input("Enter start port (1-1024): "))
        end_port = int(input("Enter end port (1-1024): "))

        if start_port < 1 or start_port > 1024 or end_port < 1 or end_port > 1024:
            print("Port must be between 1 and 1024.")
        elif end_port < start_port:
            print("End port must be greater than or equal to start port.")
        else:

            # TODO: After valid input (Step x)
            # - Create PortScanner object
            # - Print "Scanning {target} from port {start} to {end}..."
            # - Call scan_range()
            # - Call get_open_ports() and print results
            # - Print total open ports found
            # - Call save_results()
            # - Ask "Would you like to see past scan history? (yes/no): "
            # - If "yes", call load_past_scans()

            scanner = PortScanner(target)

            print(f"Scanning {target} from port {start_port} to {end_port}...")

            scanner.scan_range(start_port, end_port)

            open_ports = scanner.get_open_ports()

            print(f"--- Scan Results for {target} ---")
            for item in open_ports:
                print(f"Port {item[0]}: {item[1]} ({item[2]})")

            print("------")
            print(f"Total open ports found: {len(open_ports)}")

            save_results(target, scanner.scan_results)

            answer = input("Would you like to see past scan history? (yes/no): ")
            if answer.lower() == "yes":
                load_past_scans()

    except ValueError:
        print("Invalid input. Please enter a valid integer.")

# Q5: New Feature Proposal
# TODO: Your 2-3 sentence description here... (Part 2, Q5)
# One feature I would probably add would be a way to filter results after the scan, like only showing open ports or specific services.
# This could probably be done with list comprehension to make a filtered list based on whatever the user wants.
# It would make the output alot easier to read, especially if your scanning a lot of ports.


# Diagram: See diagram_101579211.png in the repository root
