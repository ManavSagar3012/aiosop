# IoT Security Assessment

## Procedures

### Step 1: Hardware & Physical Interface Testing
- Identify and test physical debug ports, such as UART, JTAG, and SWD.
- Attempt to gain shell access or extract firmware directly from the hardware.
- Audit the security of external storage interfaces (e.g., SD cards, USB ports).

### Step 2: Firmware Analysis & Extraction
- Extract firmware from the device or update packages using binwalk and other tools.
- Perform static analysis of the firmware filesystem for hardcoded credentials and secrets.
- Identify and reverse engineer custom binaries to discover vulnerabilities.

### Step 3: Network & Protocol Assessment
- Monitor and analyze network traffic between the device, local network, and cloud.
- Test for insecure communication protocols (e.g., Telnet, unencrypted HTTP).
- Audit custom industrial or consumer protocols for injection and logic flaws.

### Step 4: Companion App & Cloud API Security
- Perform security assessments of mobile applications that control the device.
- Audit cloud APIs for Broken Object Level Authorization (BOLA) and insecure authentication.
- Test the integration between the device, mobile app, and cloud backend for consistency.
