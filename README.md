# Password Breach Checker

This Python 2.7 script checks a password against a provided breach list by hashing it with SHA-1

## Usage

* File: Select which file to read breached hashes from. I suggest the list from [Have I Been Pwned](https://haveibeenpwned.com/Passwords "Named link title")
* GO!: Start looking for a breach
* STOP!: Stop looking for a breach
* Password: Password to be hashed then checked
* Breaches: Number of times password is in breach list
* Brute: Search every single hash in list
* Sorted: Split the list alphabetically using Splits as the number of times the list is cut in half
* Splits: Number of times to split list in half
* Threads: Number of threads to be parsing the breach list concurently
* All: Search every item in list, rather than return immediately once a single match has been found


