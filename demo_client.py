import time
import base64
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from totp import generate_totp, verify_totp, generate_secret, ReplayProtector, verify_totp_with_replay_protection


def print_banner():
    print("\n" + "=" * 50)
    print("      TOTP Demo Client")
    print("=" * 50)


def demo_standalone():
    print_banner()
    print("\n[Mode: Standalone Demo]\n")
    
    secret = generate_secret(20)
    secret_b32 = base64.b32encode(secret).decode().rstrip('=')
    
    print(f"Secret Key (Base32): {secret_b32}")
    print(f"OTPAuth URI: otpauth://totp/TOTP-Demo:demo?secret={secret_b32}&issuer=TOTP-Demo")
    print("\nRealtime OTP (Ctrl+C to stop)...\n")
    
    try:
        last_otp = ""
        while True:
            current_time = int(time.time())
            otp = generate_totp(secret, timestamp=current_time, digits=6)
            remaining = 30 - (current_time % 30)
            bar = "#" * remaining + "-" * (30 - remaining)
            
            if otp != last_otp:
                print()
                last_otp = otp
            
            print(f"\r  OTP: {otp}  |  {bar}  |  {remaining:2d}s  ", end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nDemo finished.")


def demo_ga_compatible():
    print_banner()
    print("\n[Mode: Google Authenticator Compatible]")
    print("[Replay Attack Protection: ENABLED]\n")
    
    print("1. Create new secret\n2. Enter existing secret (Base32)")
    choice = input("\nChoice (1/2): ").strip()
    
    if choice == "2":
        secret_b32 = input("Enter Secret Key (Base32): ").strip().upper()
        padding = (8 - len(secret_b32) % 8) % 8
        try:
            secret = base64.b32decode(secret_b32 + "=" * padding)
        except Exception as e:
            print(f"Error: {e}")
            return
    else:
        secret = generate_secret(20)
        secret_b32 = base64.b32encode(secret).decode().rstrip('=')
    
    print("\n" + "=" * 50)
    print(f"Secret Key: {secret_b32}")
    print(f"OTPAuth URI: otpauth://totp/TOTP-Demo:demo?secret={secret_b32}&issuer=TOTP-Demo")
    print("=" * 50)
    
    replay_protector = ReplayProtector(ttl_seconds=90)
    
    input("\nPress Enter when added to Google Authenticator...")
    print("\nDEMO (Ctrl+C to verify)")
    
    try:
        while True:
            current_time = int(time.time())
            server_otp = generate_totp(secret, timestamp=current_time, digits=6)
            remaining = 30 - (current_time % 30)
            bar = "#" * remaining + "-" * (30 - remaining)
            print(f"\r  Server OTP: {server_otp}  |  {bar}  |  {remaining:2d}s  ", end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n")
        
        while True:
            otp_input = input("\nEnter OTP from GA (or 'q' to quit): ").strip()
            if otp_input.lower() == 'q':
                break
            
            current_time = int(time.time())
            server_otp = generate_totp(secret, timestamp=current_time, digits=6)
            
            is_valid, error = verify_totp_with_replay_protection(
                protector=replay_protector,
                user_id="demo_user",
                secret=secret,
                otp=otp_input,
                timestamp=current_time,
                digits=6,
                window=1
            )
            
            print(f"  Server: {server_otp}, Your: {otp_input}")
            if is_valid:
                print("  Result: ✅ VALID")
            elif error == "replay":
                print("  Result: ⚠️  REPLAY ATTACK DETECTED! This OTP was already used.")
            else:
                print("  Result: ❌ INVALID")
        
        print("\nDemo finished.")


def main():
    print_banner()
    print("\n1. Standalone (realtime OTP display)")
    print("2. Google Authenticator Compatible")
    print("3. Exit")
    
    choice = input("\nChoice (1/2/3): ").strip()
    
    if choice == "1":
        demo_standalone()
    elif choice == "2":
        demo_ga_compatible()
    else:
        print("\nGoodbye!")


if __name__ == "__main__":
    main()
