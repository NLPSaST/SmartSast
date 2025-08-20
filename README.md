# SmartSast: AI-Powered SAST for Local, Private Code Scanning
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/drive/1FLn_i1Ln23pR7Sr25mafutaicASZa6LE?usp=sharing)
SmartSast is an innovative Static Application Security Testing (SAST) tool that uses **Large Language Models (LLMs)** to identify security vulnerabilities directly in your source code. Designed for privacy and ease of use, SmartSast provides **accurate, AI-driven analysis without sending your code to external servers.**

## What does the project do?
SmartSast is a **Static Application Security Testing (SAST) tool** built with Python and powered by **Large Language Models (LLMs)**. It analyzes your source code to detect potential security vulnerabilities, identifying risks based on **CWE (Common Weakness Enumeration) patterns.**. Using AI to provide **smarter and more accurate** results than traditional static scanners.

## Why is the project useful?
Unlike many SAST tools that run in the cloud or rely on static rules, SmartSast uses LLMs locally in Google Colab, giving developers and students a private, flexible, and AI-powered way to scan their code. It’s ideal for learning, testing, or working in secure environments where sending code to external servers is not an option. There's no need for complex setup or API keys — just open the Colab notebook and run it.

Traditional SAST tools often require complex setups, rely on fixed rule sets, or process your code on external servers. SmartSast offers a refreshing alternative:

+ **Privacy-First Scanning:** Run LLM-powered analysis directly in Google Colab, keeping your sensitive code secure and private.

+ **No Complex Setup:** Forget about installations, API keys, or lengthy configurations. Just open the Colab notebook and start scanning.

+ **AI-Powered Accuracy:** Leverage the intelligence of LLMs to detect vulnerabilities with greater precision than static, rule-based scanners.

+ **Ideal for Learning & Development:** Perfect for students, developers, and security enthusiasts looking to learn about SAST or integrate robust security checks into their local workflows.

## Features
+ **LLM-Powered Analysis:** Utilizes Large Language Models for intelligent vulnerability detection.

+ **CWE-Based Identification:** Maps identified vulnerabilities to Common Weakness Enumeration (CWE) patterns.

+ **Local Execution in Google Colab:** Ensures code privacy by running entirely within your Colab environment.

+ **Multi-Language Support:** (List the supported languages here, e.g., Python, Java, JavaScript, C++).

+ **JSON Output:** Provides structured vulnerability analysis in a standard format.

+ **Sample Code Included:** Get started quickly with example files in the \sample/` folder.

+ **No Installation or API Keys Required:** Streamlined setup for immediate use.

+ **RAG Dataset Integration (Recommended):** Enhances accuracy with a Retrieval Augmented Generation dataset (note on GPU/TPU usage).


## Quick Start: Using SmartSast in Google Colab
Getting started with SmartSast is straightforward. No installation or API keys are required! Simply open the Colab notebook and follow these steps:

**Ready to start? Click the badge below!**
[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/drive/1FLn_i1Ln23pR7Sr25mafutaicASZa6LE?usp=sharing)

1.  **Open the Notebook:** Click the "Open in Colab" badge above or at the top of this page.
2.  Save a Copy: In Colab, go to File > Save a copy in Drive to create your editable version.
3.  Prepare Your Data (Optional, but Recommended for Accuracy):
* Upload your RAR zip file (presumably containing the RAG dataset) to your Google Drive.(**latest version: CWE-top25-20250705T164339Z-1-001.zip**)
* Unzip this file to a specific folder in your Google Drive. This will be your `RAG_FOLDER` path.
4.  Configure Paths: At the beginning of the Colab notebook, define two paths:
* RAG_FOLDER: The path to the folder where you unzipped your RAG dataset.
* OUTPUT_FOLDER: The folder where the vulnerability analysis (.json) file will be saved.
5.  Run the Code: Execute the cells in the Colab notebook and follow any on-screen instructions. You can use the provided code samples in the sample/ folder to test it out.
6.  Review Results: Examine the detailed vulnerability analysis generated in your specified OUTPUT_FOLDER.

> **Pro Tip:** For optimal code accuracy and performance, it's highly recommended to use the RAG dataset and leverage Google Colab's GPU/TPU resources.

**Report**
```json
{
    "file_info": {
        "date": "20250820025121",
        "file_name": "test",
        "file_extension": ".java",
        "path_file": "/home/examples",
        "analysis duration": 765.55,
        "risk_level [in progress]": "Critical",
        "cwss_average [in progress]": 89.0
    },
    "cleaned_vulnerabilities": [
        {
            "Vulnerability_name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "CWE": "CWE-89",
            "CWSS": 89.0,
            "Description": "The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component. Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.",
            "Vulnerable_code": "String query = \"insert into users (status) values ('updated') where name='\" + data + \"'\";",
            "lines_range": "[88, 65]",
            "Solution": "Use parameterized queries or prepared statements to prevent SQL injection. For example:\nString query = \"insert into users (status) values ('updated') where name=?\";\nPreparedStatement ps = dbConnection.prepareStatement(query);\nps.setString(1, data);",
            "text1": "        String data = goodSource_SQL(); // Use good source to demonstrate good practice\n        try (Connection dbConnection = IO.getDBConnection();\n             Statement sqlStatement = dbConnection.createStatement()) {\n            String query = \"insert into users (status) values ('updated') where name='\" + data + \"'\";\n            sqlStatement.execute(query); // Safe usage as data is hardcoded\n        } catch (SQLException exceptSql) {\n            IO.logger.log(Level.WARNING, \"Database error\", exceptSql);",
            "text2": "        String data = badSource_SQL();\n        try (Connection dbConnection = IO.getDBConnection();\n             Statement sqlStatement = dbConnection.createStatement()) {\n            String query = \"insert into users (status) values ('updated') where name='\" + data + \"'\";\n            sqlStatement.execute(query); // POTENTIAL FLAW: SQL Injection\n        } catch (SQLException exceptSql) {\n            IO.logger.log(Level.WARNING, \"Database error\", exceptSql);"
        }
    ],
    "stats": {
        "total_vulnerabilities": 1,
        "unique_cwe_ids": 1,
        "exact_duplicates": 0,
        "name_duplicates": 0,
        "clean_vulnerabilities_count": 1
    },
    "exact_duplicates": {},
    "name_duplicates": {}
}
```
**Next Step**
* Add a way to identify code progress
* LLM performance measurement
  * Improve performace
  * Improve RAG database
    * Add CWEs
    * Detail CWE code examples and mitigations
* CWSS/Risk measurement

# Where can users get help?

❓ You can open an issue on GitHub

📖 Documentation and a wiki are planned

💬 Discord (link coming soon)

📧 Email (coming soon)




