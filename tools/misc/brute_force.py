#!/usr/bin/env python3
"""
Brute Force Password Cracker
Implements a brute force attack on hashed passwords with timing information.
"""

import hashlib
import itertools
import string
import time
from typing import Callable, List, Tuple


def hash_password(password: str, algorithm: str) -> str:
    """Hash a password using the specified algorithm."""
    if algorithm == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(password.encode()).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def brute_force_crack(
    target_hash: str, algorithm: str, charset: str, password_length: int
) -> Tuple[str | None, int, float]:
    """
    Attempt to crack a password hash using brute force.

    Args:
        target_hash: The hash to crack
        algorithm: The hashing algorithm used ('sha256' or 'sha1')
        charset: The character set to use for password generation
        password_length: The length of the password

    Returns:
        Tuple of (password, attempts, time_taken)
        - password: The cracked password or None if not found
        - attempts: Number of attempts made
        - time_taken: Time taken in seconds
    """
    start_time = time.time()
    attempts = 0

    # Generate all possible combinations
    for combination in itertools.product(charset, repeat=password_length):
        attempts += 1
        password = "".join(combination)
        hashed = hash_password(password, algorithm)

        if hashed == target_hash:
            time_taken = time.time() - start_time
            return password, attempts, time_taken

        # Progress indicator for longer operations (every 10000 attempts)
        # if attempts % 10000 == 0:
        #     elapsed = time.time() - start_time
        # print(f"  Progress: {attempts:,} attempts in {elapsed:.2f}s...")

    time_taken = time.time() - start_time
    return None, attempts, time_taken


def test_configuration(
    algorithm: str,
    charset: str,
    password_length: int,
    charset_name: str,
    test_password: str | None = None,
) -> None:
    """
    Test a specific configuration and report results.

    Args:
        algorithm: The hashing algorithm to use
        charset: The character set for password generation
        password_length: Length of the password
        charset_name: Descriptive name for the charset
        test_password: Specific password to test (randomly chosen if None)
    """
    print(f"\n{'=' * 70}")
    print(f"Testing: {algorithm.upper()} | {charset_name} | Length: {password_length}")
    print(f"{'=' * 70}")

    # Choose a test password (use middle of search space for average case)
    if test_password is None:
        # For average case, select a password from middle of search space
        total_combinations = len(charset) ** password_length
        middle_index = total_combinations // 2

        # Generate the password at the middle index
        test_password = ""
        remaining = middle_index
        base = len(charset)
        for _ in range(password_length):
            test_password = charset[remaining % base] + test_password
            remaining //= base

    print(f"Target password: {test_password}")

    # Create the hash
    target_hash = hash_password(test_password, algorithm)
    print(f"Target hash: {target_hash}")

    # Calculate total possible combinations
    total_combinations = len(charset) ** password_length
    print(f"Total possible combinations: {total_combinations:,}")

    # Attempt to crack
    print("\nCracking in progress...")
    cracked_password, attempts, time_taken = brute_force_crack(
        target_hash, algorithm, charset, password_length
    )

    # Report results
    print(f"\n{'=' * 70}")
    print(f"RESULTS:")
    print(f"{'=' * 70}")
    if cracked_password:
        print(f"✓ Password cracked: {cracked_password}")
        print(f"  Attempts: {attempts:,}")
        print(f"  Time taken: {time_taken:.4f} seconds")
        print(f"  Attempts per second: {attempts / time_taken:,.0f}")
        print(f"  Percentage searched: {(attempts / total_combinations) * 100:.2f}%")
    else:
        print(f"✗ Password not found")
        print(f"  Attempts: {attempts:,}")
        print(f"  Time taken: {time_taken:.4f} seconds")


def main():
    """Main function to run all test configurations."""
    print("=" * 70)
    print("BRUTE FORCE PASSWORD CRACKER - PERFORMANCE ANALYSIS")
    print("=" * 70)
    print("\nThis tool demonstrates the time complexity of brute force attacks")
    print("on different password configurations and hashing algorithms.")

    # Define character sets
    lowercase = string.ascii_lowercase  # a-z
    digits = string.digits  # 0-9
    alphanumeric = string.ascii_lowercase + string.digits  # a-z, 0-9

    # Test configurations
    configurations = [
        # (algorithm, charset, length, charset_name, test_password)
        ("sha256", lowercase, 4, "4 lowercase characters", None),
        ("sha1", lowercase, 4, "4 lowercase characters", None),
        ("sha256", lowercase, 5, "5 lowercase characters", None),
        ("sha1", lowercase, 5, "5 lowercase characters", None),
        ("sha256", digits, 6, "6 digits", None),
        ("sha1", digits, 6, "6 digits", None),
        ("sha256", digits, 7, "7 digits", None),
        ("sha1", digits, 7, "7 digits", None),
        ("sha256", digits, 8, "8 digits", None),
        ("sha1", digits, 8, "8 digits", None),
        ("sha256", lowercase, 6, "6 lowercase characters", None),
        ("sha1", lowercase, 6, "6 lowercase characters", None),
        ("sha256", alphanumeric, 5, "5 alphanumeric characters", None),
        ("sha1", alphanumeric, 5, "5 alphanumeric characters", None),
    ]

    # Run tests
    for config in configurations:
        algorithm, charset, length, charset_name, test_password = config
        try:
            test_configuration(algorithm, charset, length, charset_name, test_password)
        except KeyboardInterrupt:
            print("\n\nTest interrupted by user.")
            break
        except Exception as e:
            print(f"\nError during test: {e}")
            continue

    print("\n" + "=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)
    print("\nKey Observations:")
    print("- Time increases exponentially with password length")
    print("- Larger character sets dramatically increase crack time")
    print("- SHA256 and SHA1 have similar brute force timing")
    print("- Average case requires searching ~50% of keyspace")
    print("\nSecurity Recommendation:")
    print("- Use passwords with at least 12+ characters")
    print("- Mix uppercase, lowercase, digits, and special characters")
    print("- Consider using password managers for complex passwords")


if __name__ == "__main__":
    main()
