![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Language](https://img.shields.io/badge/language-C%2B%2B-blue)
![Status](https://img.shields.io/badge/status-ongoing-success)
![Focus](https://img.shields.io/badge/focus-security_research-purple)

# ClientManipulationFramework

Research-oriented framework for experimenting with and analyzing low-level client-side manipulation techniques on Windows systems.

The project focuses on low-level process interaction, telemetry collection, runtime behavior analysis, and operating-system-level observability of manipulation techniques such as DLL injection and memory manipulation.

![Telemetry Screenshot](docs/images/screen_telemetry.png)

## Example Telemetry Output

- [Basic Injection Log](Telemetry/basic_injection_run.json)

## Features

- Process enumeration and interaction
- Remote memory allocation and writing
- DLL injection and process manipulation experimentation
- ETW-based telemetry collection
- Runtime event monitoring
- JSONL telemetry logging
- Modular low-level Windows tooling
- Behavioral analysis experimentation

## Planned Work

- Additional injection techniques
- Expanded telemetry coverage
- Behavioral comparison framework
- Evasion strategy experimentation
- Runtime visualization tooling

## Repository Structure

| Project | Description |
|---|---|
| `ProcessToolkit` | Low-level Windows process interaction primitives |
| `Telemetry` | ETW-based telemetry collector and runtime monitoring |
| `TestDll` | Test DLL used for injection experiments |
| `TestTarget` | Target application used during controlled experiments |

## Research Context

This repository is part of an ongoing Master's thesis focused on analyzing operating-system-level behavioral patterns produced by client-side manipulation techniques on Windows systems.

The goal is to study how techniques such as memory manipulation, code injection, and execution control manifest during execution and which system-level effects remain observable across different implementations and evasion strategies.

## Technologies

- C++
- Win32 API
- ETW (Event Tracing for Windows)
- Windows Internals

## Build

Requirements:
- Visual Studio 2022
- Windows SDK
- CMake (optional)

Open the solution: **ClientManipulationFramework.sln**  
Build using: **x64 Release**

## Disclaimer

This project is intended for research and educational purposes only.