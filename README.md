# ICT Innovation Project IDS Campus Based

## Requirements

- Python 3.10 or later
- The Python packages listed in `requirements.txt`
- For live packet capture on Windows, Npcap and permission to capture packets

Install the Python dependencies from the project directory:

```powershell
python -m pip install -r requirements.txt
```

## Run a demo

In the first PowerShell terminal, start the backend and generate sample alerts:

```powershell
python main.py --demo
```

Demo mode does not start packet capture, so it does not need a network interface
or packet-capture privileges. Keep this terminal running.

In a second terminal, start a static web server from the project directory:

```powershell
python -m http.server 8000
```

Open [http://localhost:8000/index.html](http://localhost:8000/index.html) in a
browser. The dashboard reads data from the backend at `http://localhost:5000`.
The History and Notification links use the same backend.

## Run live monitoring

First, list the network interfaces Scapy can see:

```powershell
python find_interfaces.py
```

Then start the backend with the exact interface name shown by that command
(for example, replace `Wi-Fi` if your adapter has a different name):

```powershell
python main.py --interface "Wi-Fi"
```

Start the static web server in a second terminal as shown above, then open the
dashboard. Live packet capture may require running PowerShell with elevated
permissions and installing Npcap.

## Tests

Run the unit tests from the project directory:

```powershell
python -m unittest -v
```

`test_ids.py` and `test_detection_engine.py` are test files; they are run by
`unittest` and are not website pages. `pyshark/sniffpack2.py` is a separate,
optional capture implementation; the dashboard backend uses Scapy instead.
To run the optional PyShark script, install Wireshark/TShark and make sure
`TSHARK_PATH` in that script points to the installed `tshark.exe`. It also
requires the PyShark package listed in `requirements.txt`.
