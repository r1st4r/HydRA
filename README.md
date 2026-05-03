# HydRA

HydRA is a novel **dynamic hybrid remote attestation** solution. It combines both **interactive remote attestation** and **non-interactive remote attestation**, supporting public verifiability, evidence transparency, and trustless verification.

HydRA prioritizes non-interactive remote attestation for efficiency and only falls back to interactive remote attestation when necessary. In addition, HydRA supports the dynamic batch addition and removal of target devices, making it suitable for flexible and scalable trusted computing scenarios.

## Features

- Hybrid remote attestation mechanism
- Support for both interactive and non-interactive remote attestation
- Publicly verifiable attestation results
- Transparent attestation evidence
- Trustless verification
- Dynamic batch addition and removal of target devices
- Pure Rust implementation

## Project Structure

The HydRA project is implemented entirely in Rust and mainly consists of two modules:

- `dqea`: implements the distributed digital signature mechanism.
- `hydra_system`: implements the remote attestation system based on HydRA.

## Getting Started

Clone the repository:

```bash
git clone https://github.com/r1st4r/HydRA.git
