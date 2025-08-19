**Reference:** [CheapSSLWeb – What is SHA-256 and How it Works](https://cheapsslweb.com/blog/what-is-sha-256-algorithm-how-it-works/)

for a more 
[Detailed explanation](https://www.youtube.com/watch?v=f9EbD6iY9zI)


## SHA-256 Overview

**SHA-256 (Secure Hash Algorithm 256-bit)** is a cryptographic hash function. It takes **input data of any size** and outputs a **fixed-length 256-bit value** (usually displayed in hexadecimal). This output is often called a **hash** or **digest**, and it acts like a **digital fingerprint** for the data.

Key properties of SHA-256:

* **Collision resistance**: Two different inputs are extremely unlikely to produce the same hash.
* **Preimage resistance**: Given a hash, it’s practically impossible to reverse-engineer the original input.
* **Deterministic**: The same input always produces the same hash.

These features make SHA-256 ideal for **verifying data integrity**, securing passwords (though with additional techniques like PBKDF2), digital signatures, and other cryptographic protocols.

---

## How SHA-256 Works (Step by Step)

SHA-256 processes input in **512-bit blocks**, performing a sequence of operations to generate the final 256-bit hash.
![SHA-256 Padding](./images/image-1.png)

---

### 1. Data Preprocessing (Padding)

Before processing, the input must be a multiple of **512 bits**.

**Steps:**

1. Append a single `1` bit to the message.
2. Append enough `0` bits to make the total length **64 bits short of a multiple of 512**.
3. Append a 64-bit representation of the **original message length** at the end.

**Why?**
This ensures that the data can be divided into **fixed-size blocks**, which is required for the next stages of hashing. Think of it as **cutting raw material into standard-sized blocks** before manufacturing.
![alt text](./images/image-2.png)


---

### 2. Message Expansion

Each 512-bit block is first split into **16 words of 32 bits**.

Then, these 16 words are **expanded into 64 words** using **logical operations** (shifts, rotations, XORs).

Why?
This process mixes the input bits and ensures that **each bit of the original message influences many bits of the hash**, providing **diffusion** — a key property in cryptography.

---

### 3. Message Compression (64 Rounds)

Each 512-bit block (now expanded to 64 words) goes through **64 rounds of computation**.

**In each round:**

1. **Round constant** – A unique 32-bit number for this round, which introduces extra complexity.
2. **Message schedule value** – Combines the current word with previous words to feed the round.
3. **Working variable update** – Eight 32-bit variables (labeled a–h) are updated using bitwise operations and modular additions.

**Why?**
This step ensures that **even a single-bit change in the input produces a completely different hash**, a property called **avalanche effect**.


---

### 4. Final Hash Computation

After 64 rounds, the **eight working variables** are combined to form the **final 256-bit hash**.

**Why?**
This final output is the **unique fingerprint of the original input**, which is **irreversible** and suitable for verifying data integrity or storing secure digests.


it is not safe because of attacks like: 

Hash extension attack
https://www.youtube.com/watch?v=03quPNadUzY
