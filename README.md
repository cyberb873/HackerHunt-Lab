# HackerHunt-Lab

A safe, intentionally vulnerable lab for API and reconnaissance practice.

## Features

- Passive reconnaissance modules (WHOIS, DNS, crt.sh, etc.)
- Active scanning modules (port scanning, crawling)
- Vulnerability detection (XSS, SQLi error detection)
- Modular and extensible design

## Usage

Run the tool with:

```bash
python3 hackerhunt_lab.py --target example.com --modules all


# Commands 

`python
import argparse


## 2. Set Up Argument Parser

Add code to define the expected command-line arguments:

```python
def main():
    parser = argparse.ArgumentParser(description="HackerHunt-Lab: API and reconnaissance tool")

    # Add --target argument (required)
    parser.add_argument(
        '--target',
        type=str,
        required=True,
        help='Target domain or IP address to scan'
    )

    # Add --modules argument (optional, default to 'all')
    parser.add_argument(
        '--modules',
        type=str,
        default='all',
        help='Comma-separated list of modules to run (e.g., whois,dns,xss) or "all"'
    )

    args = parser.parse_args()

    target = args.target
    modules = args.modules.split(',')

    # Example: print parsed arguments
    print(f"Target: {target}")
    print(f"Modules to run: {modules}")

    # TODO: Add your tool logic here to run selected modules on the target

if __name__ == "__main__":
    main()
```

---

## 3. How This Works

- When you run:

```bash
python3 hackerhunt_lab.py --target example.com --modules whois,dns
```

- The script will parse:

  - `target` as `"example.com"`
  - `modules` as `["whois", "dns"]`



## 4. Extend for More Commands

You can add more arguments similarly, for example:

```python
parser.add_argument(
    '--verbose',
    action='store_true',
    help='Enable verbose output'
)
```

---

## 5. Example Full Minimal Script

```python
import argparse

def main():
    parser = argparse.ArgumentParser(description="HackerHunt-Lab: API and reconnaissance tool")

    parser.add_argument('--target', type=str, required=True, help='Target domain or IP address to scan')
    parser.add_argument('--modules', type=str, default='all', help='Comma-separated list of modules to run (e.g., whois,dns,xss) or "all"')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')

    args = parser.parse_args()

    target = args.target
    modules = args.modules.split(',')
    verbose = args.verbose

    if verbose:
        print(f"Running HackerHunt-Lab on target: {target}")
        print(f"Modules selected: {modules}")

    # Your scanning logic here

if __name__ == "__main__":
    main()
```



