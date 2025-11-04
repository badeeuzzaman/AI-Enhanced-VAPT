# 🔒 AI-Enhanced VAPT Tool

**Automated Vulnerability Assessment & Penetration Testing with AI-Powered Analysis**

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![AI Powered](https://img.shields.io/badge/AI-DeepSeek--Chat-orange)](https://www.deepseek.com/)

A comprehensive, AI-enhanced vulnerability assessment and penetration testing tool that automates security scanning, leverages DeepSeek AI for intelligent analysis, and generates professional security reports.

## 🚀 Features

### 🤖 AI-Powered Analysis
- **Intelligent Vulnerability Validation**: AI-driven false positive detection
- **Context-Aware Analysis**: Service-specific technical analysis
- **Smart Recommendations**: AI-generated remediation strategies
- **Penetration Test Planning**: AI-assisted exploitation techniques

### 🔍 Comprehensive Scanning
- **Port Discovery**: Advanced Nmap port scanning
- **Service Detection**: Automatic service identification and categorization
- **Vulnerability Assessment**: Multi-service vulnerability scanning
- **CVE Integration**: Automatic CVE reference matching

### 📊 Professional Reporting
- **HTML Reports**: Beautiful, professional-grade vulnerability reports
- **Executive Summaries**: AI-generated executive and technical summaries
- **Risk Assessment**: Automated risk scoring and prioritization
- **Actionable Recommendations**: Specific, technical remediation guidance

### 🛡️ Security Features
- **Black-Box Methodology**: Non-intrusive security testing
- **Controlled Environment**: Safe, controlled penetration testing
- **Ethical Framework**: Built-in safety controls and scope validation
- **Compliance Ready**: Meets professional security assessment standards

## 📋 Requirements

### System Requirements
- **Operating System**: Linux (Kali Linux recommended), macOS, Windows (WSL)
- **Python**: Version 3.8 or higher
- **Nmap**: Version 7.80 or higher
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 1GB free space

### API Requirements
- **DeepSeek API Key**: [Get your free API key](https://platform.deepseek.com/)

## ⚡ Quick Start

### Installation and execution

1. **Clone the repository**
```bash
git clone https://github.com/badeeuzzaman/AI-Enhanced-VAPT.git
cd AI-Enhanced-VAPT
python3 setup.py
python3 create_missing_files.py
```
2. **Run the tool**
```bash
python3 main.py
```
3. **Follow the interactive prompts**
- **Enter client information**
- **Provide target IP address**
- **Input DeepSeek API key**
- **Confirm assessment parameters**

## 🔧 Modules Overview
### 1. Information Gathering (modules/information_gathering.py)
- **Client and target information collection**
- **API key validation and testing**
- **Input validation and sanitization**

### 2. Vulnerability Scanner (modules/scanner.py)
- **Port scanning with Nmap integration**
- **Service-specific vulnerability detection**
- **Multi-protocol service assessment**

### 3. AI Analysis (modules/ai_analyzer.py)
- **DeepSeek AI integration for vulnerability analysis**
- **False positive detection and validation**
- **Risk assessment and CVE matching**

### 4. Penetration Testing (modules/pentest.py)
- **AI-generated exploitation techniques**
- **Proof-of-concept development**
- **Safe testing methodologies**

### 5. Report Generation (modules/reporter.py)
- **Professional HTML report generation**
- **Executive and technical summaries**
- **Actionable recommendation formatting**
