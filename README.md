# XDDOS PRIME
##⚠️ GitHub is Deleting Clones and Forks of this Repo we recommand download and reupload for usage thank you
**High-performance multi-threaded UDP flood tool for network stress testing.**

By **TEAM XDDOS** — **XDMEOW** (Shadow) & **XDCAT** (Vansh)

---

## ⚠️ DISCLAIMER

> **This tool is strictly for EDUCATIONAL PURPOSES ONLY.**
>
> Use this tool ONLY on networks and systems you OWN or have EXPLICIT WRITTEN AUTHORIZATION to test.
> Unauthorized use against any system is ILLEGAL and may result in criminal prosecution.
> The authors take NO responsibility for any misuse of this tool.

---

## What Does It Do?

XDDOS PRIME is a raw UDP packet flooder that stress-tests network infrastructure by sending massive volumes of UDP traffic to a target.

### How It Works

1. **Creates multiple threads** — each thread opens its own socket and floods independently
2. **Crafts raw IP/UDP packets** — builds packets from scratch with custom headers
3. **Spoofs source IPs** — generates random source addresses using a high-quality PRNG (CMWC), making traffic appear to come from millions of different hosts
4. **Blasts at full speed** — with throttle set to `0`, each thread sends packets as fast as the CPU and network allow
5. **Reports stats in real-time** — shows packets-per-second (PPS) and total packets sent

### Socket Modes

| Mode | Requires | Spoofing | Performance |
|------|----------|----------|-------------|
| `RAW` | Root/sudo | ✅ Full IP spoofing | Maximum |
| `DGRAM` | No root | ❌ Real source IP | High |

The tool tries `SOCK_RAW` first (needs root). If that fails, it falls back to `SOCK_DGRAM` automatically.

### Technical Specs

- **PRNG**: Complementary Multiply-With-Carry (period ~2^131086)
- **Payload**: 512 bytes random data per packet
- **TTL**: 255 (max hop count)
- **Checksum**: Proper IP header checksum calculation
- **Threading**: POSIX threads (one socket per thread, no lock contention)

---

## Building

### Requirements
- **OS**: Linux — Ubuntu 22.04 LTS (recommended)
- **Compiler**: GCC
- **Build tool**: Make
- **Libraries**: pthreads (included in glibc)

### Install Dependencies (Ubuntu 22.04)

```bash
# Update package list
sudo apt update

# Install GCC, Make, and essential build tools
sudo apt install -y build-essential gcc make
```

> `build-essential` installs everything you need — GCC, G++, Make, and libc dev headers (includes pthreads).

### Compile

```bash
# Clone the repo
git clone https://github.com/team-xddos/XDDOS-Prime.git
cd XDDOS-Prime

# Quick build (outputs ./rawudp in project root)
make quick

# Or compile manually
gcc -Wall -Wextra -O2 -std=c11 src/rawudp.c -o rawudp -lpthread
```

### Verify

```bash
# Check it compiled correctly
./rawudp
# Should print the XDDOS PRIME banner and usage info
```

---

## Usage

```bash
./rawudp <IP> <PORT> <throttle> <threads> <duration>
```

| Argument | Description | Example |
|----------|-------------|---------|
| `IP` | Target IP address | `192.168.1.1` |
| `PORT` | Target UDP port | `80` |
| `throttle` | Delay between packets in μs (`0` = no delay, max speed) | `0` |
| `threads` | Number of concurrent flooding threads | `16` |
| `duration` | How long to run in seconds | `60` |

### Example

```bash
sudo ./rawudp 192.168.1.100 80 0 16 60
```

This floods `192.168.1.100` on port `80` using 16 threads for 60 seconds at maximum speed with root privileges (RAW mode + IP spoofing).

---

## 🚀 Deploy & Run (GitHub Codespaces)

The easiest way to run this is on **GitHub Codespaces** — free cloud Linux environments with practically unmetered network capacity. A single Codespace can push **~4 Gbps**.

### Step-by-Step

#### 1. Create a Fresh GitHub Account
- Go to [github.com](https://github.com) and sign up
- Verify your email

#### 2. Create a New Repository
- Click **"New repository"**
- Name it anything (e.g. `network-testing`)
- Set to **Private** (recommended) or Public
- Click **"Create repository"**

#### 3. Open a Codespace
- In your repo, click the green **"<> Code"** button
- Switch to the **"Codespaces"** tab
- Click **"Create codespace on main"**
- Wait for the environment to spin up (takes ~30 seconds)

#### 4. Upload the Binary
- In the Codespace file explorer (left panel), **right-click → Upload Files**
- Upload your compiled `rawudp` binary
- Or drag and drop it into the explorer

#### 5. Make It Executable & Run

Open the terminal in Codespace and run:

```bash
# Make it executable
chmod +x rawudp

# Run it (Codespaces have root-like access)
./rawudp <TARGET_IP> <TARGET_PORT> 0 16 60
```

### 💡 Tips

- **More threads = more traffic**: Scale threads based on CPU cores (Codespace default is 2-core, use 8-16 threads)
- **Multiple Codespaces**: You can open several Codespaces across accounts for parallel capacity
- **No throttle**: Always set throttle to `0` for maximum output
- **Codespace limits**: Free tier gives 60 hours/month per account

---

## Project Structure

```
xddos-prime/
├── src/
│   └── rawudp.c        # Main source code
├── Makefile             # Build system
└── README.md            # This file
```

---

## Credits

**TEAM XDDOS**
- **XDMEOW** — Shadow
- **XDCAT** — Vansh
