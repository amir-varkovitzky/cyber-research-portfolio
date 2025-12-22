# Miscellaneous Security Scripts

A collection of standalone scripts demonstrating various security concepts and cryptographic principles.

## Tools

### 1. Brute Force Password Cracker Analysis
A demonstration tool that analyzes the performance and feasibility of brute-force attacks against common hash algorithms (SHA1, SHA256).

It does not crack external hashes but instead runs a predefined suite of tests against generated hashes to demonstrate:
- Time complexity differences between algorithms.
- The exponential impact of password length and character set complexity.

**File:** `brute_force.py`
**Usage:**
```bash
python3 brute_force.py
```
**Output:**
The script will output a performance analysis report, showing time taken and attempts per second for various configurations (digits, lowercase, alphanumeric).

## Requirements
- Python 3.x
- Standard libraries (`hashlib`, `itertools`, `string`)
