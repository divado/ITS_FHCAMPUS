#!/usr/bin/env python3

def greet(name):
    """Returns a greeting message"""
    return f"Hello, {name}!"

def main():
    """Main function"""
    name = input("Enter your name: ")
    print(greet(name))

if __name__ == "__main__":
    main()
    