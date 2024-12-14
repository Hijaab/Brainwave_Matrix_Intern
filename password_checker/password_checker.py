
#!/usr/bin/env python3

import re
from colorama import Fore, Style, init
import pyfiglet
import random
import string

# Initialize colorama for colored text
init(autoreset=True)

# Function to check the strength of a password
def password_strength(password):
    length = len(password)
    complexity = 0
    suggestions = []

    # Check password length
    if length >= 8:
        complexity += 1
    else:
        suggestions.append("🔸 " + Fore.YELLOW + "Make your password at least 8 characters long.")
    
    # Check for lowercase letters
    if re.search(r"[a-z]", password):
        complexity += 1
    else:
        suggestions.append("🔸 " + Fore.YELLOW + "Include at least one lowercase letter.")
    
    # Check for uppercase letters
    if re.search(r"[A-Z]", password):
        complexity += 1
    else:
        suggestions.append("🔸 " + Fore.YELLOW + "Include at least one uppercase letter.")
    
    # Check for digits
    if re.search(r"\d", password):
        complexity += 1
    else:
        suggestions.append("🔸 " + Fore.YELLOW + "Include at least one digit.")
    
    # Check for special characters
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        complexity += 1
    else:
        suggestions.append("🔸 " + Fore.YELLOW + "Include at least one special character (e.g., !, @, #, $, etc.).")
    
    # Check for repeated characters
    if re.search(r"(.)\1{2,}", password):
        complexity -= 1
        suggestions.append("🔸 " + Fore.YELLOW + "Avoid sequences of the same character (e.g., 'aaa').")
    
    # Determine password strength based on complexity
    if complexity <= 0:
        strength = "Very Weak"
        color = Fore.RED
        emoji = "🔴"
    elif complexity == 1:
        strength = "Weak"
        color = Fore.RED
        emoji = "🟠"
    elif complexity == 2:
        strength = "Moderate"
        color = Fore.YELLOW
        emoji = "🟡"
    elif complexity == 3:
        strength = "Strong"
        color = Fore.GREEN
        emoji = "🟢"
    elif complexity == 4:
        strength = "Very Strong"
        color = Fore.GREEN
        emoji = "🟢"
    else:
        strength = "Excellent"
        color = Fore.CYAN
        emoji = "🔵"
    
    # Visual strength bar
    bar = "[" + ("█" * complexity).ljust(5, "-") + "]"
    return f"{color}Password Strength: {strength} {emoji} {bar}", suggestions

# Function to generate a random password
def generate_password(length=12):
    if length < 8:
        return None, Fore.RED + "Password length must be at least 8 characters."
    
    # Define the pool of characters for the password
    characters = string.ascii_letters + string.digits + "!@#$%^&*(),.?\":{}|<>"
    return ''.join(random.choice(characters) for _ in range(length)), None

# Main program logic
def main():
    # Display the tool name with ASCII art
    tool_name = "PassCheck"
    ascii_art = pyfiglet.figlet_format(tool_name, font="slant")
    print(f"{Fore.GREEN}{Style.BRIGHT}{ascii_art}")

    print(f"{Fore.RED}V-1.0\n")
    print(f"{Fore.BLUE}Created by {Style.BRIGHT}@Hijaab{Style.RESET_ALL}{Fore.GREEN}.\n")
    
    while True:
        # Display the menu
        print(Fore.CYAN + "Menu:")
        print("1. Check Password Strength")
        print("2. Generate a Secure Password")
        print("3. Quit")
        choice = input(Fore.GREEN + "Select an option: " + Style.RESET_ALL)
        
        if choice == "1":
            # Check password strength
            user_password = input(Fore.GREEN + "🔑 Enter your password to check its strength: " + Style.RESET_ALL)
            print()  
            strength, suggestions = password_strength(user_password)
            print(strength + "\n")  
            
            if suggestions:
                print("Suggestions to improve your password:")
                for suggestion in suggestions:
                    print(suggestion)
            else:
                print(Fore.GREEN + "✅ Your password is strong enough.")
            print()
        
        elif choice == "2":
            # Generate a random password
            try:
                length = int(input(Fore.GREEN + "Enter desired password length (minimum 8): " + Style.RESET_ALL))
                password, error = generate_password(length)
                if error:
                    print(error)
                else:
                    print(Fore.CYAN + f"Generated Password: {password}")
            except ValueError:
                print(Fore.RED + "Invalid input. Please enter a number.")
            print()
        
        elif choice == "3":
            # Exit the program
            print(Fore.CYAN + "Goodbye! 👋")
            break
        
        else:
            # Handle invalid menu choice
            print(Fore.RED + "Invalid choice. Please select a valid option.\n")

# Run the main function
if __name__ == "__main__":
    main()
